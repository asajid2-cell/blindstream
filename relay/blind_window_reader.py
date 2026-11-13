"""S3: a relay reads a whole window at once and answers with the data shares it rebuilt.

The per-block read path has one failure that no amount of tuning removes. At any
concurrency, 3-5% of blocks arrive later than a player's buffer (or never), and one late
block is a hole in an ordered stream. A window carrying `n` shares of which any `k` rebuild
the data turns that tail into arithmetic: the answer arrives when the `k`-th share lands,
not when the last one does.

This module is the reader half of that. It issues shares of a window over the relay's held
FCP connection(s), keeps the first `k` that answer, stops asking, decodes, and returns the `k`
padded sealed data shares in order. Properties it is built to hold:

* **It never reads a prefix of the window and gives up.** `k` shares is the promise; fewer
  than `k` by the deadline is `WindowUnavailable`, which the relay reports as
  `window-incomplete` and the client treats as "ask another relay", not as "this track is
  broken".
* **A failed share is final for that window in this attempt, and `TRANSFER_FAILED` (code
  18) is retried once.** Code 18 is transient (a route rebuilt, a socket that sat idle);
  13 / 28 / 30 mean the substrate does not have it, and asking again would only spend the
  deadline. `blind_substrate.ReadPool` maps 18 to a 404 with no retry -- that is correct
  for one object and wrong for a window, where another share can substitute for this one.
* **The tail is cancelled, not abandoned.** Once `k` shares are in hand the workers stop
  issuing *new* shares and the answer is returned at the k-th arrival instead of waiting for
  the tail. The requests already in flight are then ended at the node: each fetch announces
  itself by a handle this module mints (`request_id=`), and `reap` sends `RemoveRequest` for
  every one still registered. The node answers `GetFailed` code 25 on that connection, the
  worker's fetch returns instead of blocking out its bound, and the lease goes **back to the
  pool clean** - so `lease-poisoned` stays at zero however large the fan-out is, and
  `cancelled == issued - k - failed` per window.
  This depends on the substrate accepting the handle (`crudenet.hyphanet.get(identifier=…)`
  plus `cancel(identifier)`, and `blind_substrate.ReadPool.cancel`). A substrate that cannot
  cancel is still served correctly: the reader falls back to the old behaviour, an FCP
  connection with an unanswered request on it is discarded as poisoned when it returns, and
  that is why `window_readers < readers` remains a guard (`check_window_pool`) rather than the
  thing that makes the fan-out work.
* **No fetch outlives its window.** A share's own bound is the window's remaining deadline,
  never the module's ceiling. A lease is held for as long as its fetch blocks, so a share
  allowed to run past the deadline keeps a connection out of the pool and the *next* window
  blocks in checkout -- measured on a real track on 2026-11-12 as a wedge on window 2 after
  windows 0 and 1 had each waited out the full per-share bound on their stragglers.

No ref is logged, counted per-ref, or returned to the client. The wire answer is the
shares' bytes and a count.
"""
from __future__ import annotations

import itertools
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import blind_fec

# `ClientGet` codes, as the FCP wire spells them (`GetFailed.Code`).
CODE_TRANSFER_FAILED = 18
CODE_DATA_NOT_FOUND = 13
CODE_ALL_DATA_NOT_FOUND = 28
CODE_RECENTLY_FAILED = 30
# The node's answer to our own `RemoveRequest`. Measured on build 1507, 2026-11-12: a
# cancelled `ClientGet` terminates with `GetFailed` code 25 (`CodeDescription=Cancelled`) at
# the moment of removal, and nothing else ever arrives on that connection. It is **not**
# `PersistentRequestRemoved`, which the FCP documentation names; a reader waiting for that
# message would wait until its deadline and conclude the cancel had failed.
CODE_CANCELLED = 25
# Codes that mean "the substrate does not have this share right now, as far as this node
# knows" -- final for the window in this attempt, because another share can substitute.
FINAL_MISS_CODES = frozenset({CODE_DATA_NOT_FOUND, CODE_ALL_DATA_NOT_FOUND,
                              CODE_RECENTLY_FAILED})

# The default per-window deadline. The spec's section 4.2 request carries its own; this is what a
# caller uses when it does not. It is deliberately shorter than a player's whole-buffer
# patience: a window that has not answered by here is one the client should hedge.
DEFAULT_DEADLINE_S = 30.0
# A share that has not answered by the window deadline is cancelled. The per-share bound is
# separate so a single stuck share cannot consume the whole window's time before the
# `k`-th arrival is even possible to observe.
DEFAULT_SHARE_BOUND_S = 120.0


class WindowError(Exception):
    """A window request the reader refuses, or a window it could not complete."""


class WindowUnavailable(WindowError):
    """Fewer than `k` shares arrived by the deadline. Retryable on another relay."""


class WindowMalformed(WindowError):
    """The request itself is not a window: wrong shape, k/n disagree with the share list."""


class WindowUndecodable(WindowError):
    """k shares arrived, and they would not decode.

    This is the relay's own failure, not the client's and not the track's: the shares came
    back and the code could not reconstruct from them. It has to reach the wire as a
    refusal, because the alternative - letting `FecError` escape the handler - closes the
    socket, and a closed socket is an unclassified transport error on the client. Measured
    2026-11-13: with `zfec` missing from a relay's `PYTHONPATH`, 10 of 17 windows died this
    way and every one of them looked like a dead connection rather than a broken relay.
    """


@dataclass
class WindowOutcome:
    """What one window read produced: the k shares, and the arithmetic behind them."""

    shares: list[bytes]                 # k padded sealed data shares, in order
    used: list[int]                     # the indices (0..n-1) that answered and were used
    issued: int                         # ClientGets actually sent (a retry sends again)
    arrived: int                        # shares that came back with bytes (>= k)
    cancelled: int                      # shares a RemoveRequest ended: the node answered 25
    failed: int                         # shares that answered with a final miss code
    retried: int                        # how many were re-issued after code 18
    skipped: int                        # shares never issued: k was already in hand
    seconds: float                      # wall time from first issue to the k-th arrival
    decode_seconds: float = 0.0
    first_share_seconds: float | None = None

    @property
    def balanced(self) -> bool:
        """Every request this window sent ended as exactly one of arrived/cancelled/failed.

        A retry sends again for the same share, so it is subtracted: `issued - retried` is the
        number of distinct shares dispatched. A share that never went out is `skipped`, not
        an issue at all. This is the identity the live proof checks per window; the literal
        form `cancelled == issued - k - failed` is this one plus `arrived == k`.
        """
        return self.issued - self.retried == self.arrived + self.cancelled + self.failed

    @property
    def shares_used(self) -> int:
        return len(self.used)


@dataclass
class WindowRequest:
    """One `POST /w` body, already parsed and validated."""

    k: int
    n: int
    shares: list[str]
    deadline_ms: int = int(DEFAULT_DEADLINE_S * 1000)

    @classmethod
    def from_body(cls, body: Any) -> "WindowRequest":
        if not isinstance(body, dict):
            raise WindowMalformed("a window request is a JSON object")
        k, n = body.get("k"), body.get("n")
        shares = body.get("shares")
        deadline = body.get("deadline_ms", int(DEFAULT_DEADLINE_S * 1000))
        if not isinstance(k, int) or not isinstance(n, int):
            raise WindowMalformed("k and n must be integers")
        if not isinstance(shares, list) or not all(isinstance(s, str) for s in shares):
            raise WindowMalformed("shares must be a list of refs")
        request = cls(k=k, n=n, shares=list(shares), deadline_ms=int(deadline))
        request.validate()
        return request

    def validate(self) -> None:
        """The geometry has to be self-consistent before a single request goes out.

        A caller that says `k=16, n=32` and hands 20 refs would otherwise have the relay
        ask for 20 and wait for 16 that can never arrive. The window is the client's claim,
        and the relay's only job is to try to satisfy it, so a claim that cannot be
        satisfied is a 400 rather than a wait.
        """
        if self.k < 1:
            raise WindowMalformed("a window needs at least one data share")
        if self.n <= self.k:
            raise WindowMalformed("a window needs at least one recovery share")
        if self.n > 255:
            raise WindowMalformed("a window cannot have more than 255 shares")
        if len(self.shares) != self.n:
            raise WindowMalformed("a %d-of-%d window needs %d refs, got %d"
                                  % (self.k, self.n, self.n, len(self.shares)))
        if len(set(self.shares)) != len(self.shares):
            # A duplicate ref is a claim that one share counts twice. It cannot: the
            # window's guarantee is k *distinct* answers.
            raise WindowMalformed("a window's refs must be distinct")
        if self.deadline_ms <= 0:
            raise WindowMalformed("a window needs a positive deadline")


def validate_window_refs(request: WindowRequest, *, usable: Callable[[str], bool]) -> None:
    """Refuse a window whose refs are not retrievable handles, before any request is sent."""
    for index, ref in enumerate(request.shares):
        if not usable(ref):
            raise WindowMalformed("share %d is not a retrieveable handle" % index)


class WindowReader:
    """Issue a window's shares at once on held connections, keep the first k, cancel rest.

    `pool` is the relay's held-connection pool: `checkout()` / `checkin()` / `discard()` of
    a mesh with `get(ref, ...)`. It is the same pool shape `blind_substrate.ReadPool` uses,
    so the deployment needs no new substrate code and a test can inject a fake mesh.

    `mesh_get` is how one share is fetched. The default calls `mesh.get` with the fields the
    spec names (`ReturnType=direct`, `Persistence=connection`, `MaxRetries=1`,
    `RealTimeFlag=false`, `MaxSize=32768`); a test injects a function so the reader's own
    policy -- keep the first k, cancel the rest, retry 18 once -- is exercised without a
    node.
    """

    def __init__(self, pool: Any, *, share_bound: float = DEFAULT_SHARE_BOUND_S,
                 concurrency: int = 64, retry_transfer_failed: bool = True,
                 counters: Any = None, checkout_timeout: float = 5.0,
                 warm_required: bool = False, now=time.monotonic) -> None:
        self.pool = pool
        self.share_bound = float(share_bound)
        self.concurrency = max(1, int(concurrency))
        self.retry_transfer_failed = bool(retry_transfer_failed)
        self.counters = counters
        self.checkout_timeout = float(checkout_timeout)
        # Whether the relay must finish a warm pass before it serves a window. False for a
        # reader with nothing to warm (a test fixture, a fake mesh); the deployed reader
        # sets it when the relay has a warm pass to run.
        self.warm_required = bool(warm_required)
        self._now = now
        # The cancel seam, set per read. `None` means the substrate cannot recall a request
        # and the reader falls back to discarding a poisoned lease, which is the old
        # behaviour and still correct - just costlier.
        self._cancel_fn: Callable[[str], bool] | None = None

    def _bump(self, key: str, by: int = 1) -> None:
        if self.counters is not None:
            self.counters.bump(key, by)

    # -- workers -------------------------------------------------------------

    def _one_share(self, lease: Any, request: WindowRequest, index: int,
                   fetch: Callable[[Any, str, float], bytes], state: "_WindowState",
                   stop: threading.Event, deadline: float) -> bool:
        """Fetch one share, retrying code 18 exactly once, and record the outcome.

        Returns whether the **connection** is still clean. That matters more than the share:
        a definitive miss (13/28/30) is an answer, so the lease goes back; a timeout or a
        socket error leaves a request outstanding on it, and the node's eventual answer to
        *that* request would be read as the next request's reply -- a share that decodes and
        whose digest is silently wrong. Measured on a real track 2026-11-12: exactly this,
        one window in seventeen, at eight-way concurrency.
        """
        ref = request.shares[index]
        attempts = 2 if self.retry_transfer_failed else 1
        for attempt in range(attempts):
            remaining = deadline - self._now()
            if stop.is_set() or remaining <= 0:
                with state.lock:
                    if attempt:
                        # This share *was* dispatched once and is now abandoned instead of
                        # re-issued. It is a cancelled request, not an unissued one: counting
                        # it as `skipped` would leave an issue with no ending and break the
                        # arithmetic the live proof checks.
                        state.cancelled += 1
                        self._bump("share-cancelled")
                    else:
                        # Never sent, so nothing was asked of the node: the window is answered
                        # by the k shares already in hand and this share is simply not spent.
                        state.skipped += 1
                return True
            # The share's bound is what is left of the window, capped by the module's own
            # ceiling. A fetch allowed to outlive the deadline holds its lease past the
            # point anyone is waiting for it, and the next window then blocks in checkout
            # on a connection that is still walking the network for an answer nobody wants.
            bound = min(float(self.share_bound), remaining)
            # The handle this fetch announces itself by, so a *later* arrival of k can cancel
            # it from another thread. Registered before the fetch starts, because the fetch
            # blocks and nothing else can name this request once it is running.
            handle = _share_handle(index, attempt)
            with state.lock:
                state.inflight[index] = handle
                state.issued += 1
            try:
                blob = fetch(lease, ref, bound, request_id=handle)
            except Exception as exc:  # noqa: BLE001 - classified here, never swallowed
                code = _code_of(exc)
                with state.lock:
                    state.inflight.pop(index, None)
                if code == CODE_TRANSFER_FAILED and attempt + 1 < attempts:
                    with state.lock:
                        state.retried += 1
                    self._bump("share-retried")
                    continue
                if code == CODE_CANCELLED:
                    # This share was cancelled because k arrived elsewhere. Not a failure of
                    # the substrate and not a straggler: the answer is already in hand.
                    with state.lock:
                        state.cancelled += 1
                    self._bump("share-cancelled")
                    return True
                # This share is not arriving and another can take its place. Not retried --
                # the window's deadline is the budget, not this share's patience.
                with state.lock:
                    state.failed += 1
                if code is not None:
                    # A `GetFailed` carrying a code is the node's *answer*: it is finished
                    # with this request, so nothing is outstanding on the connection.
                    self._bump("share-miss" if code in FINAL_MISS_CODES else "share-failed")
                    return True
                # No code: a timeout or a dead socket. The node may still be working on this
                # request, and its reply must not be handed to whoever uses the connection
                # next -- that is how a share arrives with another share's bytes.
                self._bump("share-failed")
                return False
            with state.lock:
                state.inflight.pop(index, None)
            if len(blob) != blind_fec.SHARE_BYTES:
                # A short read is not a share. Counting it as an arrival would let a
                # truncated object displace a real one and make the decode wrong rather
                # than absent.
                with state.lock:
                    state.failed += 1
                self._bump("share-wrong-size")
                return False
            if state.offer(index, bytes(blob), now=self._now()):
                stop.set()
            return True
        return True

    def _checkout(self, count: int, *, wait: float) -> list[Any]:
        """Take `count` leases, or none: a pool that cannot serve the window fails whole.

        A window's worker keeps its connection until its (deadline-bounded) fetch returns,
        so a previous window can still hold a lease when this one starts. That is a wait,
        not a refusal: the checkout is bounded by what is left of *this* window's deadline,
        so a backlog either clears in time or the window is `WindowUnavailable` and the
        client hedges to another relay. Bound the pool above the worker count so this path
        is rare rather than the norm.
        """
        leases: list[Any] = []
        for _ in range(count):
            try:
                try:
                    leases.append(self.pool.checkout(timeout=max(0.01, wait)))
                except TypeError:
                    # A pool whose `checkout` takes no bound (a fake in a test) is asked
                    # the only way it can answer.
                    leases.append(self.pool.checkout())
            except Exception as exc:  # noqa: BLE001 - a saturated pool is a refusal
                for lease in leases:
                    self.pool.discard(lease)
                self._bump("window-no-lease")
                raise WindowUnavailable("no connection for the window: %s"
                                        % type(exc).__name__) from None
        return leases

    def _checkin(self, lease: Any) -> None:
        try:
            self.pool.checkin(lease)
        except Exception:  # noqa: BLE001 - a lease that will not return is discarded
            self.pool.discard(lease)

    def read(self, request: WindowRequest, *,
             mesh_get: Callable[[Any, str, float], bytes] | None = None,
             cancel: Callable[[str], bool] | None = None) -> WindowOutcome:
        """Read one window. Returns `WindowOutcome`, or raises `WindowUnavailable`."""
        fetch = mesh_get or default_mesh_get
        # `cancel` ends an in-flight share by its handle. Optional because a test fixture
        # may not model removal, and because on a substrate that cannot cancel the reader
        # must still work - it just falls back to discarding the lease.
        self._cancel_fn = cancel
        started = self._now()
        deadline = started + request.deadline_ms / 1000.0

        state = _WindowState(request)
        stop = threading.Event()
        threads: list[threading.Thread] = []
        # One connection per share would be one handshake per share. The pool is bounded, so
        # a window takes a lease per worker and each worker walks a slice of the share list.
        workers = min(self.concurrency, len(request.shares))
        leases = self._checkout(workers, wait=max(0.01, deadline - self._now()))

        def work(lease: Any, indices: list[int]) -> None:
            # The worker owns its lease until it is done with it, and is the only one that
            # returns or retires it. A connection with an unanswered request on it is
            # discarded rather than checked in: its eventual answer would otherwise be read
            # as the next request's reply, which is a share that decodes and is wrong.
            clean = True
            try:
                for index in indices:
                    if stop.is_set():
                        with state.lock:
                            state.skipped += 1
                        continue
                    if not self._one_share(lease, request, index, fetch, state, stop,
                                           deadline):
                        clean = False
                        break
            finally:
                if clean:
                    self._checkin(lease)
                else:
                    self.pool.discard(lease)
                    self._bump("lease-poisoned")

        for worker, lease in enumerate(leases):
            slice_ = list(range(worker, len(request.shares), workers))
            thread = threading.Thread(target=work, args=(lease, slice_), daemon=True)
            thread.start()
            threads.append(thread)

        def reap(deadline: float) -> None:
            """End every request still in flight, so its lease can come back clean.

            Called on the k-th arrival and again at the deadline. Without it a straggler keeps
            walking the network after the window has already been answered, its connection is
            unusable for the whole time it runs, and on return it is discarded as poisoned -
            which is the pool cost the old build paid on every window. `cancel` sends the
            node's own RemoveRequest; the node answers `GetFailed`/25 on that connection, the
            worker's fetch returns with `Cancelled` instead of blocking out its bound, and the
            lease is handed back rather than thrown away.
            """
            if self._cancel_fn is None:
                return
            # Polled, not one-shot, and the reason is a measured race: a fast share can set
            # `stop` microseconds before a slow worker registers its handle, so a single pass
            # finds an empty set and cancels nothing. The loop is bounded by the window's own
            # deadline and stops as soon as nothing is in flight - it is a sweep for
            # registrations that landed while the sweep was running, not a wait.
            #
            # Each handle is cancelled **once** (F2). The sweep runs every 2 ms, and a worker
            # only clears its `inflight` entry when its own fetch returns - which is after the
            # cancellation it is waiting on. Without this set the same handle was re-cancelled
            # dozens of times per window, and a RemoveRequest for an identifier the node has
            # already finished with is answered with a protocol error: measured 2026-11-12 as
            # 8 poisoned leases *with* the cancel on.
            sent: set[str] = set()
            while True:
                with state.lock:
                    inflight = list(state.inflight.values())
                    handles = [handle for handle in inflight if handle not in sent]
                if not inflight:
                    # Nothing is outstanding: every worker has recorded its outcome, which is
                    # what the `issued + skipped == n` arithmetic is read against. This is a
                    # *drain* as well as a sweep - breaking on "no new handles" alone would
                    # return while late workers were still starting.
                    break
                for handle in handles:
                    sent.add(handle)
                    try:
                        if self._cancel_fn(handle):
                            self._bump("share-cancelled-sent")
                        else:
                            self._bump("cancel-unavailable")
                    except Exception:  # noqa: BLE001 - a cancel that fails costs a lease
                        self._bump("cancel-error")
                if self._now() >= deadline:
                    break
                time.sleep(0.002)

        # Answer at the k-th arrival, not at the last one: `stop` is set by the k-th offer,
        # so this wakes the moment k is in hand (or at the deadline, whichever is first).
        # **Exactly one reaper.** The watcher is the only thread that sends RemoveRequest:
        # a second reaper racing it would re-cancel handles the first had already ended, and
        # a RemoveRequest for an identifier the node no longer has is answered with a
        # ProtocolError that the fetch loop raises as a plain failure - which was measured
        # as 8 poisoned leases *with* the cancel on (2026-11-12) before this was fixed.
        def watch() -> None:
            stop.wait(max(0.0, deadline - self._now()))
            reap(deadline)

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        # Wait for the answer (or the deadline), then for the reaper to finish ending the
        # tail. The join is bounded by the same deadline, so a node that will not answer a
        # removal cannot hold the handler past the window it belongs to.
        stop.wait(max(0.0, deadline - self._now()))
        watcher.join(timeout=max(0.0, deadline - self._now()) + 1.0)

        with state.lock:
            arrived = dict(state.arrived)
            issued = state.issued
            cancelled = state.cancelled
            failed = state.failed
            retried = state.retried
            skipped = state.skipped
            first = state.first_arrival

        if len(arrived) < request.k:
            self._bump("window-incomplete")
            raise WindowUnavailable("%d of %d shares arrived by the deadline"
                                    % (len(arrived), request.k))
        used = sorted(arrived)[:request.k]
        decode_started = self._now()
        try:
            decoded = blind_fec.decode_window(
                {index: arrived[index] for index in used},
                blind_fec.Window(request.k, request.n))
        except blind_fec.FecError as exc:
            # A decode that fails is this relay's problem, and it must be *said*, not
            # signalled by a dropped socket. The message carries no ref (FecError's own
            # text is about k/n and share sizes), and it is not written anywhere - the
            # relay's no-log rule stands, so it is carried to the refusal and no further.
            self._bump("window-undecodable")
            raise WindowUndecodable(str(exc)) from exc
        decode_seconds = self._now() - decode_started
        self._bump("window-ok")
        self._bump("shares-ok", len(arrived))
        return WindowOutcome(
            shares=[bytes(share) for share in decoded], used=used,
            issued=issued, arrived=len(arrived), cancelled=cancelled, failed=failed,
            retried=retried, skipped=skipped, seconds=self._now() - started,
            decode_seconds=decode_seconds,
            first_share_seconds=first)


_handle_seq = itertools.count(1)


def _share_handle(index: int, attempt: int) -> str:
    """A per-share FCP identifier that is unique **process-wide**, not just per window.

    Fred keys a request's bookkeeping by this string and attributes a `RemoveRequest` to it,
    not to the socket. So two live requests with one identifier are one request to cancel and
    two answers to mis-attribute - and a handle derived from an object's memory address is
    not unique over time: CPython reuses a freed object's address, and the previous version
    (`id(request) & 0xFFFF`) therefore minted the *same* handle for a different window's share
    once the first request object was collected. Measured 2026-11-12: 7 of 17 windows decoded
    to the wrong bytes with every counter reporting `lease-poisoned: 0`, and one window lost 8
    of its own cancellations to another window's reaper.

    The counter is the uniqueness; the pid and index exist only so an operator reading a raw
    FCP trace can tell what a request was, and neither is needed for correctness.
    """
    return "win-%d-%d-%d-%d" % (os.getpid(), next(_handle_seq), index, attempt)


class _WindowState:
    """What the workers share: arrivals, and the decision to stop asking."""

    def __init__(self, request: WindowRequest) -> None:
        self.lock = threading.Lock()
        self.arrived: dict[int, bytes] = {}
        # Share index -> the handle its fetch announces itself by. Populated by the worker
        # before its fetch blocks and cleared when it returns, so the reaper can name exactly
        # the requests still flying and nothing else.
        self.inflight: dict[int, str] = {}
        self.issued = 0
        self.cancelled = 0
        self.failed = 0
        self.retried = 0
        self.skipped = 0
        self.first_arrival: float | None = None
        self.request = request

    def offer(self, index: int, blob: bytes, *, now: float) -> bool:
        """Record a share. Returns True when the window now has k (stop asking)."""
        with self.lock:
            if index in self.arrived:
                return False
            self.arrived[index] = blob
            if self.first_arrival is None:
                self.first_arrival = now
            return len(self.arrived) >= self.request.k


def default_mesh_get(mesh: Any, ref: str, bound: float,
                      request_id: str | None = None) -> bytes:
    """One share, with the fields the spec names for a window read (spec section 4.1).

    The handle is parsed by the substrate's own parser when the runtime is present, so a ref
    is never re-implemented here; a mesh that wants the plain handle (a fake in a test) gets
    it, because a test replaces the substrate, not the policy around it.

    `bound` is the time this share may take: what is left of the window, never the module's
    ceiling. Passing the ceiling here is what let a straggler outlive its window and hold a
    lease into the next one.
    """
    parsed: Any = ref
    try:
        from crudenet.refs import Ref
        parsed = Ref.from_uri(ref)
    except Exception:  # noqa: BLE001 - no runtime, or a handle the parser refuses
        pass
    kwargs: dict[str, Any] = {}
    if request_id is not None:
        # A substrate that accepts an identifier lets the window reader cancel this fetch
        # from another thread. One that does not ignores the field and the reader falls back
        # to discarding the lease. Passing it is what makes the cancel possible; requiring it
        # would make a fixture-only substrate unusable.
        kwargs["identifier"] = request_id
    return mesh.get(parsed, timeout=bound, max_size=blind_fec.SHARE_BYTES,
                    real_time=False, **kwargs)


def _is_cancelled(exc: BaseException) -> bool:
    """Is this the substrate's "we ended it ourselves" failure?

    `HyphanetMesh.get` raises a typed `Cancelled` for Fred's code 25, and that exception
    carries no numeric `code` - it is the *name* that says what it is. Matching it by type is
    the correct test; the name fallback exists because this module must keep working against
    a substrate that reports the same fact through a different class (a fixture). Measured
    2026-11-12: without this, nineteen RemoveRequests were sent, the node answered 25 on each,
    and the reader counted all nineteen as timeouts - which is exactly the poisoning the
    cancel exists to remove.
    """
    for candidate in (exc, getattr(exc, "__cause__", None)):
        if candidate is None:
            continue
        for klass in type(candidate).__mro__:
            if klass.__name__ == "Cancelled":
                return True
    return False


def _code_of(exc: BaseException) -> int | None:
    """The FCP code a substrate failure carried, if it carried one.

    `HyphanetMesh.get` wraps an FCP failure in `HyphanetError(...) from original`; the code
    lives on the cause or in the message. Reading it is what lets the reader tell a
    transient route rebuild (18) from a definitive miss (13/28/30), and the typed
    `Cancelled` (no numeric code at all) from both.
    """
    if _is_cancelled(exc):
        return CODE_CANCELLED
    for candidate in (exc, getattr(exc, "__cause__", None)):
        if candidate is None:
            continue
        value = getattr(candidate, "code", None)
        if isinstance(value, int):
            return value
    text = str(exc)
    for code in (CODE_TRANSFER_FAILED, CODE_DATA_NOT_FOUND, CODE_ALL_DATA_NOT_FOUND,
                 CODE_RECENTLY_FAILED, CODE_CANCELLED):
        if "code=%d" % code in text or "code %d" % code in text:
            return code
    return None
