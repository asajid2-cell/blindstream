"""S3: a window read keeps the first k, stops asking for the rest, and never answers short.

What is asserted here is the policy, not the network: a fake mesh stands in for the
substrate, so each test can state exactly which shares fail and how, and the reader's answer
is checked against the strand's own arithmetic. The claims that matter:

* **k of n is the promise.** Any k arriving shares decode to the window's data, so a test
  that fails n-k shares at random must still get the exact data back.
* **18 is retried once, 13/28/30 are not.** A transient route rebuild is worth a second
  ask; a definitive miss is not, because another share can take its place and the deadline is
  the budget.
* **A short window is a refusal, never a partial answer.** Fewer than k shares is
  `WindowUnavailable`, which the relay reports as `window-incomplete`.
* **A request in flight is cancelled, not abandoned.** After the k-th arrival the reader
  returns without waiting for the tail and sends `RemoveRequest` for every share still flying;
  the node answers `GetFailed`/25, the fetch returns, and the lease goes back to the pool
  clean. Tests pin that (a fake mesh that refuses a second issue on a busy connection, a
  cancelled share that must not be counted as a failure, and the arithmetic
  `cancelled == issued - k - failed`). A substrate with no cancel seam is still served - it
  falls back to discarding the lease, which is why the pool sizing guard remains a guard.

The metering and the wire shape are checked on the relay side (`handle_window`), including
the rule that no ref appears in any counter label.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import blind_fec  # noqa: E402
from blind_window_reader import (  # noqa: E402
    WindowMalformed,
    WindowReader,
    WindowRequest,
    WindowUnavailable,
    validate_window_refs,
)

SHARE = blind_fec.SHARE_BYTES


def ref(index: int) -> str:
    """A shape-valid CHK handle. The reader never parses it; the tests never use it twice."""
    body = ("%043d" % index).replace("0", "A")
    return "chk:CHK@%s,%s,AAMA--8" % (body, body)


def refs(count: int) -> list[str]:
    return [ref(i) for i in range(count)]


def window_data(count: int = 4) -> list[bytes]:
    """Deterministic padded data shares for a window with `count` data shares."""
    return [bytes([index]) * SHARE for index in range(count)]


class FakeMesh:
    """One held connection: it answers by ref from a plan, and records what it was asked.

    All meshes in a pool share one `answers` dict, which is how a test says what the
    *substrate* holds rather than what one socket does. A stored exception is raised.
    """

    def __init__(self, answers: dict[str, object], *, delay: float = 0.0) -> None:
        self.answers = answers
        self.delay = delay
        self.asked: list[str] = []
        self.lock = threading.Lock()
        # Cancellation, modelled the way the node actually behaves: a request can be ended by
        # identifier, and the *fetch* is what observes the ending. `cancelled` is the record a
        # test reads; `_gates` is how a share is held in flight until the test says otherwise.
        self.pending: dict[str, threading.Event] = {}
        self.cancelled: list[str] = []
        self._gate_for: dict[str, threading.Event] = {}

    def hold(self, name: str) -> None:
        """Make the fetch of `name` block until it is cancelled (or the gate is opened)."""
        self._gate_for[name] = threading.Event()

    def release(self, name: str) -> None:
        gate = self._gate_for.get(name)
        if gate is not None:
            gate.set()

    def cancel(self, identifier: str) -> bool:
        if identifier not in self.pending:
            return False
        self.cancelled.append(identifier)
        self.pending[identifier].set()
        return True

    def get(self, uri, *, identifier=None, **_):
        name = ref_of(uri)
        with self.lock:
            # The wire rule, modelled rather than assumed: one FCP connection carries one
            # request at a time. A reader that issued a new get while an earlier one was
            # still outstanding would have that earlier one's answer read as this one's -
            # so a fixture that would let it happen must refuse instead.
            assert not self.pending, (
                "a request was issued on a connection that still had %d outstanding; its "
                "answer would be read as this request's reply" % len(self.pending))
            self.asked.append(name)
            remaining = self._fail_times.get(name, 0) if hasattr(self, "_fail_times") else 0  # noqa: SLF001
            if remaining:
                self._fail_times[name] = remaining - 1
                raise _miss(18)
        gate = self._gate_for.get(name)
        if gate is not None and identifier is not None:
            event = threading.Event()
            self.pending[identifier] = event
            try:
                if not event.wait(10.0):
                    raise TimeoutError("gate never opened")
            finally:
                self.pending.pop(identifier, None)
            # Cancelled: the node answers code 25, exactly as build 1507 does. Not 13, and not
            # an absence - a read nobody wanted any more.
            raise _miss(25)
        if self.delay:
            time.sleep(self.delay)
        answer = self.answers.get(name)
        if isinstance(answer, BaseException):
            raise answer
        if answer is None:
            raise _miss(13)
        return answer


class _Handle:
    """What the substrate's ref parser returns: the handle, on `.value`."""

    def __init__(self, value: str) -> None:
        self.value = value


def ref_of(uri) -> str:
    return getattr(uri, "value", None) or str(uri)


class Pool:
    """A held-connection pool of `size` meshes over one shared answer set."""

    def __init__(self, answers: dict[str, object], size: int = 8, *,
                 fail_times: dict[str, int] | None = None, delay: float = 0.0) -> None:
        self._answers = answers
        self._fail_times = dict(fail_times or {})
        self._lock = threading.Lock()
        # Set before any mesh is built: `_build` hands each mesh a reference to it.
        self._holds: dict[str, threading.Event] = {}
        self.discarded: list[object] = []
        self._idle = [self._build(delay) for _ in range(size)]
        self.size = size
        # Every mesh built, idle or checked out. A cancel has to reach a *checked-out* one,
        # because that is where a straggler lives.
        self._built = list(self._idle)

    def _build(self, delay: float):
        mesh = FakeMesh(self._answers, delay=delay)
        mesh._fail_times = self._fail_times  # noqa: SLF001 - shared failure plan
        # Same reason as `_fail_times`: a test holds a *share* slow, not one socket, and the
        # worker that picks that share is whichever connection the pool handed out.
        mesh._gate_for = self._holds  # noqa: SLF001 - shared hold plan
        return mesh

    def hold(self, name: str) -> None:
        """Hold the fetch of `name` in flight until it is cancelled."""
        self._holds[name] = threading.Event()

    def cancelled_names(self) -> list[str]:
        with self._lock:
            return [name for mesh in self._built for name in mesh.cancelled]

    def checkout(self, **_):
        with self._lock:
            if not self._idle:
                # Grow rather than block: the reader's own concurrency is what decides how
                # many leases a window takes, and a test should not have to pre-count it.
                mesh = self._build(0.0)
                self._built.append(mesh)
                return mesh
            return self._idle.pop()

    def checkin(self, mesh):
        with self._lock:
            self._idle.append(mesh)

    def discard(self, mesh):
        with self._lock:
            self.discarded.append(mesh)

    def cancel(self, identifier: str) -> bool:
        """Deliver a cancel to every mesh built; only the one running it answers True."""
        with self._lock:
            meshes = list(self._built)
        for mesh in meshes:
            if mesh.cancel(identifier):
                return True
        return False

    @property
    def asked(self) -> list[str]:
        with self._lock:
            return [name for mesh in self._idle for name in mesh.asked]


def _fetch(mesh, ref: str, bound: float, *, request_id: str | None = None) -> bytes:
    """The reader's per-share call, with a ref the fake mesh understands.

    `bound` is the reader's own share deadline (what is left of the window); a fake does not
    need to honour it, and a test that does can assert on it. `request_id` is what the reader
    announces the fetch by, which is what lets a later arrival cancel it.
    """
    return mesh.get(_Handle(ref), identifier=request_id)


def _miss(code: int):
    error = RuntimeError("substrate miss: code=%d" % code)
    error.code = code  # type: ignore[attr-defined]
    return error


def publish(count: int = 4, n: int = 12) -> tuple[blind_fec.Window, list[bytes], dict[str, object]]:
    """Encode a window and return (geometry, shares, answers keyed by ref)."""
    geometry = blind_fec.Window(count, n)
    data = window_data(count)
    shares = blind_fec.encode_window(data, geometry)
    handles = refs(n)
    return geometry, data, dict(zip(handles, shares))


# --- the request shape ---------------------------------------------------------------------

def test_a_window_request_needs_consistent_geometry():
    ok = WindowRequest.from_body({"k": 4, "n": 12, "shares": refs(12), "deadline_ms": 5000})
    assert ok.k == 4 and ok.n == 12 and len(ok.shares) == 12


@pytest.mark.parametrize("body", [
    {"k": 4, "n": 12, "shares": refs(11)},                 # one ref short
    {"k": 4, "n": 4, "shares": refs(4)},                   # no recovery shares
    {"k": 0, "n": 12, "shares": refs(12)},                 # no data shares
    {"k": 4, "n": 12, "shares": refs(12)[:-1] + [refs(12)[0]]},  # a duplicate
    {"k": "4", "n": 12, "shares": refs(12)},               # a string k
    {"k": 4, "n": 12, "shares": refs(12), "deadline_ms": 0},
    {"k": 4, "n": 12},                                     # no shares at all
    [],
])
def test_a_malformed_window_request_is_refused(body):
    with pytest.raises(WindowMalformed):
        WindowRequest.from_body(body)


def test_a_window_with_a_dead_ref_is_refused_before_any_request():
    request = WindowRequest.from_body({"k": 4, "n": 12, "shares": refs(12)})
    validate_window_refs(request, usable=lambda handle: handle.startswith("chk:CHK@"))
    with pytest.raises(WindowMalformed):
        validate_window_refs(
            WindowRequest.from_body({"k": 1, "n": 2, "shares": ["not-a-ref", ref(1)]}),
            usable=lambda handle: handle.startswith("chk:CHK@"))


# --- the read itself ------------------------------------------------------------------------

def test_any_k_of_the_window_answers_with_the_exact_data():
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    # Only the recovery shares answer. A systematic window still rebuilds from them.
    live = {handle: blob for handle, blob in answers.items() if handle in handles[4:]}
    reader = WindowReader(Pool(live), concurrency=8)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 5000}), mesh_get=_fetch)
    assert outcome.shares == data
    # Which four arrival wins is a race among the eight recovery shares that answer, so the
    # assertion is about the set they came from, not their order.
    assert outcome.shares_used == 4
    assert all(4 <= index < 12 for index in outcome.used), outcome.used


def test_a_window_answers_as_soon_as_k_shares_arrive():
    """The point of the strand: the k-th arrival, not the slowest of n."""
    geometry, data, answers = publish(16, 32)
    handles = list(answers)
    # Half the shares are never going to answer. Any 16 of the 32 still rebuild the data.
    live = {handle: answers[handle] for handle in handles[:20]}
    reader = WindowReader(Pool(live), concurrency=1)
    started = time.monotonic()
    outcome = reader.read(WindowRequest.from_body(
        {"k": 16, "n": 32, "shares": handles, "deadline_ms": 5000}), mesh_get=_fetch)
    assert outcome.shares == data
    assert time.monotonic() - started < 5


def test_a_window_that_cannot_reach_k_is_a_refusal_not_a_partial_answer():
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    live = {handle: answers[handle] for handle in handles[:3]}
    reader = WindowReader(Pool(live), concurrency=4)
    with pytest.raises(WindowUnavailable):
        reader.read(WindowRequest.from_body(
            {"k": 4, "n": 12, "shares": handles, "deadline_ms": 300}), mesh_get=_fetch)


def test_code_18_is_retried_once_and_then_counts_as_a_failure():
    """A transient route rebuild gets one more ask; two failures is a missing share.

    The retry goes out on the same connection (18 is an answer, so the lease stays clean),
    and after the second failure the window simply uses another share.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    flaky = handles[0]
    answers[flaky] = _miss(18)
    pool = Pool(answers, size=1, fail_times={flaky: 99})
    reader = WindowReader(pool, concurrency=1, retry_transfer_failed=True)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 2000}), mesh_get=_fetch)
    assert outcome.retried >= 1
    assert outcome.shares == data
    assert pool.asked.count(flaky) == 2, "code 18 must be asked exactly twice, not more"


def test_a_transient_18_that_clears_is_used():
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    flaky = handles[0]
    pool = Pool(answers, size=1, fail_times={flaky: 1})
    reader = WindowReader(pool, concurrency=1)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 2000}), mesh_get=_fetch)
    assert outcome.shares == data
    assert pool.asked.count(flaky) == 2


@pytest.mark.parametrize("code", [13, 28, 30])
def test_a_final_miss_is_not_retried(code):
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    gone = handles[0]
    answers[gone] = _miss(code)
    pool = Pool(answers, size=1)
    reader = WindowReader(pool, concurrency=1)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 2000}), mesh_get=_fetch)
    assert outcome.shares == data
    assert pool.asked.count(gone) == 1


def test_a_short_share_is_not_counted_as_an_arrival():
    """A truncated object must make the window short, never make the decode wrong."""
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    live = dict(answers)
    # Eleven of twelve answer short; one good share is not a window.
    for handle in handles[1:]:
        live[handle] = answers[handle][:100]
    reader = WindowReader(Pool(live), concurrency=4)
    with pytest.raises(WindowUnavailable):
        reader.read(WindowRequest.from_body(
            {"k": 4, "n": 12, "shares": handles, "deadline_ms": 300}), mesh_get=_fetch)


def test_every_lease_is_returned_to_the_pool():
    """A window that leaks a lease is a pool that empties after k windows."""
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=4)
    reader = WindowReader(pool, concurrency=4)
    for _ in range(3):
        reader.read(WindowRequest.from_body(
            {"k": 4, "n": 12, "shares": handles, "deadline_ms": 2000}), mesh_get=_fetch)
    assert len(pool._idle) >= 4, "every lease must be checked back in"
    assert not pool.discarded, "a successful window must not discard a lease"


def test_a_share_may_not_outlive_the_window_it_belongs_to():
    """The bound handed to a fetch is what is left of the window, not the module ceiling.

    A share that ran past the deadline would keep its lease checked out (a fetch holds the
    connection for as long as it blocks), and the *next* window would then block in
    checkout. Measured on a real track 2026-11-12: windows 0 and 1 each waited out the 120 s
    ceiling on their stragglers and window 2 wedged for >60 s before the relay gave up.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    seen: list[float] = []

    def slow(mesh, handle: str, bound: float, *, request_id: str | None = None) -> bytes:
        seen.append(bound)
        return answers[handle]

    reader = WindowReader(Pool(answers), concurrency=2)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 500}), mesh_get=slow)
    assert outcome.shares == data
    assert seen, "every fetch must be bounded"
    assert max(seen) <= 0.5 + 0.05, "no share may be given more time than the window has"


def test_a_saturated_pool_is_window_unavailable_not_a_wait():
    """A pool with no free connection cannot serve the window; that is a refusal, not a hang."""
    geometry, data, answers = publish(4, 12)
    handles = list(answers)

    class Empty:
        def checkout(self, **kwargs):
            raise TimeoutError("no reader")

        def checkin(self, lease):
            pass

        def discard(self, lease):
            pass

    reader = WindowReader(Empty(), concurrency=4, checkout_timeout=0.05)
    started = time.monotonic()
    with pytest.raises(WindowUnavailable):
        reader.read(WindowRequest.from_body(
            {"k": 4, "n": 12, "shares": handles, "deadline_ms": 5000}), mesh_get=_fetch)
    assert time.monotonic() - started < 2.0


def test_a_lease_with_an_unanswered_request_is_discarded_not_returned():
    """A timeout leaves a request outstanding, so that connection must not be reused.

    This is the silent-corruption case: the node's eventual answer to the abandoned request
    is read as the next request's reply. The share decodes and its digest is wrong. Measured
    on a real track 2026-11-12 -- one window in seventeen at eight-way concurrency, which is
    what `lease-poisoned` counts.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    answers[handles[0]] = TimeoutError("no answer in time")
    pool = Pool(answers, size=4)
    reader = WindowReader(pool, concurrency=2)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 2000}), mesh_get=_fetch)
    assert outcome.shares == data
    assert pool.discarded, "a connection with an unanswered request is discarded"
    # A definitive miss, by contrast, leaves the connection clean and returns it.
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    answers[handles[0]] = _miss(13)
    clean_pool = Pool(answers, size=4)
    reader = WindowReader(clean_pool, concurrency=2)
    reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 2000}), mesh_get=_fetch)
    assert not clean_pool.discarded, "a definitive miss must not cost a connection"


def test_a_window_answers_at_k_without_waiting_for_the_tail():
    """The k-th arrival ends the read; the stragglers are abandoned, not awaited.

    The reason a window is faster than n reads is exactly this: the answer is the k-th share,
    not the last one. If the reader waited for every fetch, the tail would be back, so this
    pins the property the window route exists for.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    slow = handles[-1]
    original = answers[slow]

    def tail(mesh, handle: str, bound: float, *, request_id: str | None = None) -> bytes:
        if handle == slow:
            time.sleep(1.5)
        return answers[handle] if handle != slow else original

    pool = Pool(answers, size=4)
    reader = WindowReader(pool, concurrency=12)
    started = time.monotonic()
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}), mesh_get=tail)
    elapsed = time.monotonic() - started
    assert outcome.shares == data
    assert elapsed < 1.2, ("a window must answer at the k-th share, not the last: "
                           "took %.2fs with a 1.5s tail" % elapsed)


def test_the_stragglers_are_cancelled_once_k_have_arrived():
    """The cancel, not just the stop: every share still flying gets a RemoveRequest.

    Leaf 53's correction on the first night: `stop` only prevented *new* issues, so a
    straggler ran to its bound and its connection was thrown away. Measured on build 1507 the
    node does honour a removal - it answers `GetFailed`/25 and nothing follows - so the reader
    can end them, and the leases come back.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    # A small delay on *every* fetch, so all twelve workers are in flight before k can
    # arrive. Without it the four fast shares finish in the time it takes to start a thread,
    # `stop` is set, and the other eight never issue a request at all - a fixture that cannot
    # exercise the cancel because there is nothing to cancel.
    pool = Pool(answers, size=12, delay=0.05)
    # Most of the tail is genuinely slow: those fetches block until cancelled.
    for name in handles[4:]:
        pool.hold(name)
    reader = WindowReader(pool, concurrency=12)
    started = time.monotonic()
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    elapsed = time.monotonic() - started
    assert outcome.shares == data
    # If the slow shares had been awaited, the window would have run to the gate's timeout.
    assert elapsed < 3.0, "a straggler must be cancelled, not awaited: took %.2fs" % elapsed
    cancelled = pool.cancelled_names()
    assert cancelled, "the shares still flying at k must have been cancelled"
    assert outcome.cancelled >= 1, "a cancelled share is counted apart from a failed one"
    # And the pool keeps its connections: a cancelled share answers, so its lease is clean.
    assert not pool.discarded, "a cancelled share must not poison its lease"


def test_a_cancelled_share_is_not_counted_as_a_failure():
    """Code 25 means "we stopped asking", not "the substrate does not have it"."""
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    slow = handles[8:10]
    pool = Pool(answers, size=12)
    for name in slow:
        pool.hold(name)
    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    assert outcome.shares == data
    assert outcome.failed == 0, ("a cancelled share is not a substrate failure: %d were "
                                 "counted as failed" % outcome.failed)


def test_a_cancel_is_recognised_by_its_type_not_only_by_a_numeric_code():
    """Fred's code 25 arrives as a typed `Cancelled` with **no** code attribute.

    The reader's code table matches numbers and message text, and neither is what
    `crudenet.mesh.Cancelled` carries. Measured 2026-11-12: nineteen RemoveRequests went out,
    the node answered 25 on each, and every one was counted as a timeout - so the leases were
    discarded exactly as they were before the cancel existed. The regression is pinned here
    against the real exception class.
    """
    from blind_window_reader import _code_of, CODE_CANCELLED

    class Cancelled(Exception):  # the shape `crudenet.mesh.Cancelled` has
        pass

    assert not hasattr(Cancelled("x"), "code")
    assert _code_of(Cancelled("cancelled: short")) == CODE_CANCELLED
    # And the wrapped form: a substrate that re-raises with `from original`.
    try:
        try:
            raise Cancelled("cancelled: short")
        except Cancelled as original:
            raise RuntimeError("wrapped") from original
    except RuntimeError as wrapped:
        assert _code_of(wrapped) == CODE_CANCELLED


def test_a_substrate_that_cannot_cancel_still_serves():
    """No cancel seam is a cost, not a break: the reader falls back to discarding the lease."""
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=12)
    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch)  # no `cancel`
    assert outcome.shares == data


def test_k_arriving_while_others_are_in_flight_still_decodes_exactly():
    """The cancellation path must not corrupt the shares it keeps.

    The hazard it guards against is a late reply read as the next request's: if the cancel
    machinery slid one answer onto another, the decode would fail or produce wrong bytes. So
    the data is checked, not just the counts.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=12)
    for name in handles[6:]:
        pool.hold(name)
    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    assert outcome.shares == data
    assert len(outcome.used) == 4


def test_the_window_arithmetic_balances():
    """`cancelled == issued - k - failed` when nothing was skipped, and every request ends.

    This is the live proof's identity, pinned where it can be stated exactly: a straggler is
    cancelled rather than failed, a share that never went out is `skipped` rather than
    cancelled, and `issued - retried` counts distinct requests.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=12, delay=0.05)
    for name in handles[4:]:
        pool.hold(name)
    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    assert outcome.shares == data
    assert outcome.balanced, ("issued=%d retried=%d arrived=%d cancelled=%d failed=%d"
                              % (outcome.issued, outcome.retried, outcome.arrived,
                                 outcome.cancelled, outcome.failed))
    assert outcome.failed == 0
    assert outcome.cancelled == outcome.issued - geometry.k - outcome.failed
    assert outcome.arrived == geometry.k
    # Every share of the window is accounted for: despatched once, or never asked for.
    assert outcome.issued - outcome.retried + outcome.skipped == geometry.n
    assert outcome.skipped == 0, "every share was in flight before k could arrive"


def test_a_late_reply_cannot_reach_the_next_request_on_the_same_connection():
    """The corruption the cancel exists to prevent, checked as corruption rather than counts.

    A cancelled fetch's answer must not be delivered to the *next* request on that socket.
    `FakeMesh.get` refuses an issue while one is outstanding, so a reader that abandoned a
    request without ending it would fail here; and the following window is read on the same
    pool, so any leakage would show up as the wrong share bytes.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=12, delay=0.05)
    for name in handles[4:]:
        pool.hold(name)
    reader = WindowReader(pool, concurrency=12)
    first = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    assert first.shares == data
    # Let every cancelled worker return its lease before the next window asks for one.
    time.sleep(0.3)
    # A second window on the same pool, with no holds: every share answers, and the bytes
    # must be this window's - a late reply from the first would decode to the wrong data.
    second = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    assert second.shares == data
    assert not pool.discarded, "a cancelled request must release its lease clean"


def test_a_share_still_flying_at_the_k_th_arrival_keeps_its_lease_out():
    """Without a cancel seam the lease is held for as long as the straggler runs.

    This is the fallback, not the normal path: the substrate here takes no `request_id` and
    the read passes no `cancel`, so the eight shares still walking when k arrives cannot be
    recalled. They do finish (this fixture is only slow, not stuck), so their leases come
    back and nothing is poisoned - but the connection is unavailable while they run, which is
    why the pool sizing guard remains a guard.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    straggler = handles[-1]

    def tail(mesh, handle: str, bound: float, *, request_id: str | None = None) -> bytes:
        if handle == straggler:
            time.sleep(0.4)
        return answers[handle]

    pool = Pool(answers, size=12)
    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(WindowRequest.from_body(
        {"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}), mesh_get=tail)
    assert outcome.shares == data
    assert not pool.discarded, "a slow share that does answer must not poison its lease"
    # Give the straggler time to return, and then every lease must be back: the connection was
    # delayed, not lost. That is the distinction the pool sizing has to be built on.
    time.sleep(0.6)
    assert len(pool._idle) == 12, (  # noqa: SLF001 - the pool's own accounting
        "a straggler's lease returns once its fetch completes; it is delayed, not leaked")


def test_every_share_handle_is_unique_across_windows():
    """The handle is what the node attributes a cancel to, so it must not repeat in a process.

    The first version derived it from the request object's address (`id(request) & 0xFFFF`).
    CPython reuses a freed object's address, so a later window's share got an earlier window's
    handle - and one window's reaper then cancelled another window's live request. Measured
    2026-11-12: 7 of 17 windows decoded to the wrong bytes on a warm node while every counter
    still reported `lease-poisoned: 0`.
    """
    from blind_window_reader import _share_handle

    handles = [_share_handle(index, attempt) for index in range(32) for attempt in (0, 1)]
    assert len(set(handles)) == len(handles), "a handle repeated inside one process"
    # And two windows asking for the same (index, attempt) still get different handles.
    assert _share_handle(0, 0) != _share_handle(0, 0)


def test_a_share_abandoned_after_a_transient_failure_is_a_cancel_not_a_skip():
    """An issued request that is not re-issued ended as a cancel; `skipped` is for the unsent.

    Counting it as skipped leaves a dispatch with no ending, and the per-window arithmetic
    (`issued == arrived + cancelled + failed`) silently stops holding.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    # The first four shares each fail once with 18 and then the window is answered by the
    # recovery half; the retried share must be re-issued, not quietly dropped.
    pool = Pool(answers, size=12, fail_times={handle: 1 for handle in handles[:4]})
    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=pool.cancel)
    assert outcome.shares == data
    assert outcome.balanced
    assert outcome.retried >= 1


def test_a_window_that_cannot_decode_is_a_refusal_not_a_dropped_connection(monkeypatch):
    """k shares arrived and the code cannot reconstruct: that is `WindowUndecodable`.

    Measured 2026-11-13: a relay started without `zfec` on its `PYTHONPATH` answered 7 of 17
    windows and closed the socket on the other 10. The client sees a closed socket as a
    transport fault - the same thing it sees when a relay is simply down - so a broken relay
    and an absent one were indistinguishable, and no counter recorded the decode failure.

    The reader must name it. `WindowUndecodable` is what the relay maps onto `503
    window-undecodable` (the same instruction as `window-incomplete`: ask another relay).
    """
    from blind_window_reader import WindowUndecodable

    def refuse(*_args, **_kwargs):
        raise blind_fec.FecError("zfec is required to encode or decode shares")

    monkeypatch.setattr(blind_fec, "decode_window", refuse)
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=12)
    reader = WindowReader(pool, concurrency=12)
    with pytest.raises(WindowUndecodable) as refused:
        reader.read(
            WindowRequest.from_body({"k": 4, "n": 12, "shares": handles,
                                     "deadline_ms": 6000}),
            mesh_get=_fetch, cancel=pool.cancel)
    # The message is the library's own, about k/n and share sizes - never a ref.
    assert "zfec" in str(refused.value)


def test_each_handle_is_cancelled_at_most_once():
    """T6 (F2): the reap sweep runs every 2 ms and must not re-send a RemoveRequest.

    A worker only clears its `inflight` entry when its own fetch returns - which is *after*
    the cancellation it is waiting on - so the sweep sees the same handle on every pass
    until then. A second RemoveRequest for an identifier the node has finished with is
    answered with a protocol error, which is how a window ends up with poisoned leases
    (measured 2026-11-12: 8, with the cancel on).

    The seam is counted here rather than the fake mesh's list, because the mesh refuses a
    stale identifier silently - exactly the behaviour that hid the duplicate.
    """
    geometry, data, answers = publish(4, 12)
    handles = list(answers)
    pool = Pool(answers, size=12, delay=0.05)
    for name in handles[4:]:
        pool.hold(name)
    sent: list[str] = []

    def cancel(handle: str) -> bool:
        sent.append(handle)
        return pool.cancel(handle)

    reader = WindowReader(pool, concurrency=12)
    outcome = reader.read(
        WindowRequest.from_body({"k": 4, "n": 12, "shares": handles, "deadline_ms": 6000}),
        mesh_get=_fetch, cancel=cancel)

    assert outcome.shares == data
    assert sent, "the shares still flying at k must be cancelled"
    duplicates = {handle: sent.count(handle) for handle in set(sent) if sent.count(handle) > 1}
    assert not duplicates, "a handle was cancelled more than once: %r" % duplicates
    assert not pool.discarded, "0 poisoned leases: a cancelled share returns its connection"
