"""The blind relay's substrate read: pooled, held, read-only, content-addressed.

ADR 0011 Decision 4.5 and Decision 7: a relay holds pooled substrate (FCP) connections and
reuses them across blocks. A fresh FCP handshake is ~1.5 s and the node *serialises* them, so
per-request connections buy nothing and cost the door; one `FCPClient` is one socket carrying
one in-flight request at a time, so readers are pooled and *reused*, never shared.

**One ref in, ciphertext out, and nothing else.** This class's only public method takes a ref
and a byte ceiling. It is never given a credential, an owner, a device or a client address,
so there is no path by which a substrate read could be attributed. The ref it reads is the
same string the caller supplied; the relay does not decorate it, and a read is not repeated
under a different identity.

A relay is read-only by construction here: there is no insert, no listing and no search,
because there is no method for any of them. Refusing those surfaces is a property of the
*interface*, not of a check that could be edited away.

**One exception, and it is narrow: `read_edition`.** A mutable head (the catalogue's index
pointer) lives in an editioned namespace, not in a CHK, so a relay that could only read CHKs
could not carry it. It is a separate method rather than a widening of `read` for exactly the
reason above: `read` takes a `Ref`, and a USK is not one. `read_edition` is bound to a
*specific edition* - never the latest, never a namespace search - because resolving "latest"
is a search the node may spend 70 s on (measured on lab FCP 9591, 2026-11-12), and a client
that is told the edition it asks for is the only way that read stays a read.
"""
from __future__ import annotations

import threading
from typing import Any

MAX_WIRE = 16 * 1024 * 1024
# A read that misses spends seconds searching before it answers. Bounded so one handler
# thread cannot pin the pool behind a ref that will never resolve.
DEFAULT_READ_TIMEOUT = 60.0

# The write half's start-time self-check (the blind-fetch design). One fixed 32 KiB block -- the
# production stream-block insert unit -- and the handle the substrate's *own* derivation must
# return for it: a plain single-block CHK, key `sha256(blob)`, suffix `AAMA--8` (control byte
# 0, not a metadata document). The value is the same `chk_ref` golden the seam's fixed-vector
# test pins (`tests/test_blind_insert_seam.py`) and the owner derives locally. A staged
# runtime whose client defaults a content type frames the insert as a metadata document and
# moves the handle to `AAMC--8` -- measured on the lab write host (2026-10-18), where a stale
# runtime put one plaintext under two handles. So the relay asks the substrate the derive-only
# question at start and refuses if the answer is not this.
INSERT_SELF_CHECK_BLOB = bytes(range(256)) * 128            # 32768 bytes: one CHK block
INSERT_SELF_CHECK_REF = (
    "chk:CHK@bosJsNPo8TzdiLi~AMKuuQWnOfbdrHiyGLtYEvwrB-0,"
    "4RNgJR0Rc2UM3NIPER2PHKLkEvVy6LNqTcBnEhwXmbg,AAMA--8")
SELF_CHECK_TIMEOUT = 30.0


def _substrate_failures() -> tuple[type[BaseException], ...]:
    """The substrate's own transport-failure types, imported lazily.

    Lazy so the relay's own tests can exercise `WritePool.self_check` against a fake mesh
    with no staged crudenet runtime on the path (the same shape as
    `blind_insert_seam._substrate_failures`).
    """
    from crudenet.hyphanet import HyphanetError

    return (HyphanetError, TimeoutError, OSError)


class SubstrateError(Exception):
    """The substrate could not answer: a transport/connection failure (503, retryable)."""


class SubstrateTimeout(SubstrateError):
    """The substrate did not answer inside the serving bound (503, but NOT retried).

    A miss that is still walking Hyphanet when the bound elapses is not a dead socket, so
    the one-retry-for-a-closed-connection rule must not apply: retrying it would double the
    very latency the bound exists to cap, and the caller has already waited it out. It is
    still a 503 rather than a 404 because the node never said the object is absent - only
    that it did not answer in time.
    """


class SubstrateMiss(Exception):
    """The substrate answered, and does not hold the object (404, definitive for now)."""


class SubstrateTooLarge(Exception):
    """The object exceeds the wire ceiling (413)."""


# The substrate's own answers for "the namespace holds no such edition", as FCP `GetFailed`
# codes. Not one code but a family, measured on lab FCP 9591 (2026-11-12) over five probes of
# an edition that does not exist:
#
#   13  Data not found            - the clean answer
#   30  Terminated by a node      - a peer dropped the request rather than saying "no"
#   11  Too many path folds       - the search was cut short rather than exhausted
#   15  Too many path folds/timeout
#   18  Found it, lost it while receiving
#
# Treating only 13 as absent made a missing edition answer `503 substrate-unavailable` in
# 3.0 s, which every relay answers identically: a client probing forward would spend its pass
# window asking relay after relay to be told the same thing. That is the wrong instruction
# for "this edition is not readable by anyone", so the whole family is reported as a miss.
# The one thing this must not swallow is a *timeout*: a search that ran out the serving bound
# is retryable and is reported as `SubstrateTimeout`, before this check.
_EDITION_ABSENT_CODES = ("11", "13", "15", "18", "30")


def _is_edition_absent(message: str) -> bool:
    """Does a substrate failure name one of the "no such edition" codes?"""
    marker = "code="
    start = message.find(marker)
    while start != -1:
        rest = message[start + len(marker):].split(None, 1)[0].rstrip(",;.")
        if rest in _EDITION_ABSENT_CODES:
            return True
        start = message.find(marker, start + len(marker))
    return False


class _ReaderPool:
    """A small pool of persistent substrate readers to one node.

    Same shape as the fetch gateway's `ReaderPool`, reimplemented rather than imported so
    the relay has no dependency on the frozen `fetch-request/1` module. A failed reader is
    discarded and the read retried **once** on a fresh connection: a socket the node closed
    while it sat idle is the case that would otherwise turn a held object into a miss.
    """

    def __init__(self, fcp_port: int, *, host: str = "127.0.0.1", size: int = 8,
                 label: str = "blind-relay", insert_queue: str = "bulk") -> None:
        self.host = host
        self.fcp_port = int(fcp_port)
        self.size = max(1, int(size))
        self.label = label
        # Which queue a mesh built here inserts in. It governs inserts only -- reads take
        # their scheduling class per request -- so the read pool's default ("bulk") is inert
        # for it, and only the write half (`WritePool`) selects something else.
        self.insert_queue = insert_queue
        self._free = threading.Condition(threading.Lock())
        self._idle: list[Any] = []
        # Every reader this pool has built and not closed. A cancel has to reach a reader
        # that is *checked out* - a straggling fetch holds its lease by definition - so
        # looking only at the idle pile would never find the one to cancel.
        self._built: list[Any] = []
        self._open = 0

    def _build(self) -> Any:
        # Imported lazily: the relay's own tests inject a fake substrate and must not
        # require a staged crudenet runtime on the path. `crudenet.hyphanet` connects
        # lazily, so building a mesh here does not open a socket yet.
        from crudenet.hyphanet import HyphanetMesh

        reader = HyphanetMesh(self.fcp_port, host=self.host, label=self.label,
                              insert_queue=self.insert_queue)
        with self._free:
            self._built.append(reader)
        return reader

    def checkout(self, *, timeout: float | None = None, fresh: bool = False) -> Any:
        end = None if timeout is None else time_monotonic() + timeout
        while True:
            retire = None
            with self._free:
                if not fresh and self._idle:
                    return self._idle.pop()
                if self._open < self.size:
                    self._open += 1
                elif fresh and self._idle:
                    retire = self._idle.pop()
                else:
                    remaining = None if end is None else end - time_monotonic()
                    if remaining is not None and remaining <= 0:
                        raise TimeoutError("no reader available")
                    self._free.wait(remaining)
                    continue
            if retire is not None:
                self._close(retire)
            try:
                return self._build()
            except Exception:
                with self._free:
                    self._open -= 1
                    self._free.notify()
                raise

    def checkin(self, reader: Any) -> None:
        with self._free:
            self._idle.append(reader)
            self._free.notify()

    def cancel(self, handle: str) -> bool:
        """End an in-flight fetch by the handle it announced itself by.

        The handle is minted by the caller and threaded into the mesh, so the node already
        knows which request it is; this only has to deliver the order on the connection that
        is running it. That connection is **checked out**, not idle - the whole point of a
        straggler is that its lease is still held - so this asks every reader the pool has
        built, and the mesh answers True only from the one that has that handle outstanding.
        """
        with self._free:
            candidates = list(self._built)
        for reader in candidates:
            cancel = getattr(reader, "cancel", None)
            if cancel is None:
                continue
            try:
                if cancel(handle):
                    return True
            except Exception:  # noqa: BLE001 - a failed cancel costs a lease, never a window
                continue
        return False

    def discard(self, reader: Any) -> None:
        self._close(reader)
        with self._free:
            self._open -= 1
            try:
                self._built.remove(reader)
            except ValueError:
                pass
            self._free.notify()

    def close(self) -> None:
        with self._free:
            idle, self._idle = self._idle, []
            self._open -= len(idle)
            self._free.notify_all()
        for reader in idle:
            self._close(reader)

    @staticmethod
    def _close(reader: Any) -> None:
        try:
            reader.close()
        except Exception:  # noqa: BLE001 - a reader already gone is still released
            pass


def time_monotonic() -> float:
    import time

    return time.monotonic()


class ReadPool:
    """The relay's held-connection substrate reader.

    `read(ref, max_size)` returns the ciphertext for one content-addressed ref, or raises a
    substrate error. Nothing else in the relay calls into a substrate: `read` is the whole
    surface, and it is the only place a ref leaves the process.
    """

    # How long the substrate is given to say "no such edition" before the answer is "could not
    # ask". Measured on lab FCP 9591 (2026-11-12): an absent edition took 9.95 s, 1.91 s, 5.05 s,
    # 6.94 s, 5.77 s and 8.02 s across six probes - it is a search that fails, not an index
    # lookup. The block route's bound (3 s in the deployed relay) is shorter than that, so a
    # head read under it can only ever answer "unavailable" and never "absent", which is the
    # one distinction a forward probe needs. A *hit* is unaffected: 0.15 s cold.
    DEFAULT_HEAD_TIMEOUT = 15.0

    def __init__(self, *, fcp_port: int = 0, host: str = "127.0.0.1", size: int = 8,
                 timeout: float = DEFAULT_READ_TIMEOUT, label: str = "blind-relay",
                 head_timeout: float | None = None) -> None:
        self.timeout = float(timeout)
        # The head's bound is its own and is never shortened below the block's: the point of it
        # is to outlast a search whose answer is "nothing", and a bound that inherited a 3 s
        # block deadline would make every absent edition indistinguishable from an outage.
        self.head_timeout = max(float(head_timeout or self.DEFAULT_HEAD_TIMEOUT), self.timeout)
        self._pool = _ReaderPool(fcp_port, host=host, size=size, label=label)

    def read(self, ref: str, *, max_size: int = MAX_WIRE) -> bytes:
        from crudenet.mesh import ObjectNotFound, TransferFailed
        from crudenet.refs import Ref

        # `Cancelled` is newer than the rest of the mesh package, and a fixture that stubs
        # `crudenet.mesh` without it must still import this module - so the lookup is here,
        # where the name is only needed by the except below, and absent means "this substrate
        # has no such answer", which is true of such a fixture.
        try:
            from crudenet.mesh import Cancelled
        except ImportError:  # pragma: no cover - only a stub mesh lacks it
            Cancelled = ()  # type: ignore[assignment]

        def one(reader: Any) -> bytes:
            # real_time=True is the serving scheduling class (ADR 0005): it changes *when*
            # bytes move, never whether they may. MaxSize is enforced by the node before
            # the transfer, so an over-large object costs no bandwidth to refuse.
            return reader.get(Ref.from_uri(ref), timeout=self.timeout, max_size=max_size,
                              real_time=True)

        def attempt(reader: Any) -> bytes:
            try:
                blob = one(reader)
            except Cancelled:
                # Not the client's cancel - this is the plain block route, which does not
                # cancel anything - but a node that reports code 25 must still not be read as
                # "absent". The connection is clean (the node stopped on its own terms), so it
                # goes back and the read is a miss for this attempt.
                self._pool.checkin(reader)
                raise SubstrateMiss("Cancelled") from None
            except (ObjectNotFound, TransferFailed) as exc:
                # A substrate *answer*: the connection is still good, so it goes back.
                self._pool.checkin(reader)
                raise SubstrateMiss(str(exc.__class__.__name__)) from None
            except Exception as exc:  # noqa: BLE001 - a transport failure is retried once
                self._pool.discard(reader)
                # `HyphanetMesh.get` wraps every transport failure in `HyphanetError(…)
                # from original`, so the timeout is visible only on the cause chain. A read
                # that ran out the serving bound is *not* a dead socket: retrying it would
                # double the very latency the bound exists to cap.
                if isinstance(exc, TimeoutError) or isinstance(exc.__cause__, TimeoutError):
                    raise SubstrateTimeout("serve-timeout") from None
                raise SubstrateError(exc.__class__.__name__) from None
            # A *success* must hand the reader back too. A lease that is never returned is a
            # slot gone for the life of the process, and the pool holds only `size` of them:
            # after that many successful fetches the pool is empty and every later read
            # answers `503 substrate-unavailable` at the checkout timeout, not because the
            # substrate is unreachable but because the relay has no reader left to ask. That
            # is how the live relay-a stopped serving (2026-10-18): ~`size` refs served, then
            # every read refused at 60 s while the same ref read from a fresh pool in 0.3 s.
            self._pool.checkin(reader)
            return blob

        try:
            reader = self._pool.checkout(timeout=self.timeout)
        except TimeoutError:
            # Every reader is busy. The pool is the door's *throughput* bound, not a queue:
            # a bounded wait that expires sheds (503, retryable) rather than parking the
            # handler thread on the pool forever. An unbounded checkout here is what wedged
            # the relay (114 handler threads) when one reader was never checked back in.
            raise SubstrateError("read pool exhausted") from None
        try:
            return attempt(reader)
        except SubstrateTimeout:
            # Never retried: the bound has already been waited out once, and a second
            # attempt would make the answer later than the bound it was set to enforce.
            raise
        except SubstrateError:
            # A fresh connection, not just any reader: the socket that failed may have been
            # closed while idle, and another idle reader could be that same dead socket.
            reader = self._pool.checkout(fresh=True, timeout=30.0)
            try:
                return attempt(reader)
            except SubstrateError:
                raise

    def read_edition(self, uri: str, *, max_size: int = MAX_WIRE,
                     timeout: float | None = None) -> bytes:
        """Read **one named edition** of a mutable namespace. `uri` must be a `USK@…/<edition>`.

        This is the catalogue head's read and nothing else: the owner writes the index pointer
        into an editioned namespace, and a device with no pointer fetches the edition it last
        saw. It is deliberately *not* a general namespace read:

        * **A negative edition is refused.** `USK@…/-1` is the substrate's "find the newest"
          form, and on lab FCP 9591 that search measured 70.5 s cold / 25.1 s warm against
          0.16 s for a named edition (2026-11-12). A relay that served "latest" would put a
          minute-scale search on the client's first-open path while looking like a single
          read, and it would also make the relay's answer depend on a search whose cost the
          relay cannot bound. The client keeps its last known edition and asks for the next
          *specific* one; discovering which edition is current is the client's decision.
        * **It cannot be reached through `read`.** `read` takes a `Ref`, and `Ref` refuses a
          USK prefix on purpose (`crudenet.refs`), so nothing that looks like content
          addressing can carry a mutable locator by accident. Two verbs, two types.
        * **It answers what the substrate returned**, never the edition that was asked for. A
          node that redirected to another edition is a fact the caller must see, and
          `resolve_usk` reports it from the address the request finished at.

        Raises `SubstrateMiss` when the namespace has no such edition, `SubstrateTimeout` when
        the serving bound expired, and `SubstrateError` for a transport failure.
        """
        from crudenet.mesh import ObjectNotFound
        from crudenet.refs import partition_usk

        try:
            _, edition = partition_usk(uri)
        except ValueError as exc:
            raise SubstrateError("not a namespace edition: %s" % exc) from None
        if edition < 0:
            raise SubstrateError("latest-edition reads are not a relay surface")

        bound = self.head_timeout if timeout is None else float(timeout)

        def attempt(reader: Any) -> bytes:
            try:
                _, blob, _ = reader.resolve_usk(uri, timeout=bound)
            except ObjectNotFound as exc:
                # The node answered: this edition does not exist. The connection is clean.
                self._pool.checkin(reader)
                raise SubstrateMiss(str(exc.__class__.__name__)) from None
            except Exception as exc:  # noqa: BLE001 - classified below, not swallowed
                # A timeout is retryable and is *not* an absence; it is checked first and
                # keeps its own type so the caller does not read it as "no such edition".
                if isinstance(exc, TimeoutError) or isinstance(exc.__cause__, TimeoutError):
                    self._pool.discard(reader)
                    raise SubstrateTimeout("serve-timeout") from None
                # The substrate's "no such edition" family is an *answer*, not a transport
                # failure: the connection is still good, so it goes back to the pool and the
                # caller is told the edition is absent. Everything else is a transport
                # failure and is retried once on a fresh reader.
                if _is_edition_absent(str(exc)):
                    self._pool.checkin(reader)
                    raise SubstrateMiss("edition-absent") from None
                self._pool.discard(reader)
                raise SubstrateError(exc.__class__.__name__) from None
            if len(blob) > max_size:
                self._pool.checkin(reader)
                raise SubstrateTooLarge("%d bytes" % len(blob))
            self._pool.checkin(reader)
            return blob

        try:
            reader = self._pool.checkout(timeout=bound)
        except TimeoutError:
            raise SubstrateError("read pool exhausted") from None
        try:
            return attempt(reader)
        except SubstrateTimeout:
            raise
        except SubstrateError:
            reader = self._pool.checkout(fresh=True, timeout=30.0)
            try:
                return attempt(reader)
            except SubstrateError:
                raise

    def close(self) -> None:
        self._pool.close()

    def cancel(self, handle: str) -> bool:
        """End an in-flight share read by the handle its fetch announced itself by.

        The window reader calls this for every share still flying once it has k, so the
        node stops work nobody will use and - the part that matters here - the connection
        becomes reusable instead of being thrown away. Returns whether the handle was known;
        False on a substrate that cannot cancel, which the window reader treats as "fall back
        to discarding the lease".
        """
        return self._pool.cancel(handle)

    def connected_peers(self) -> int:
        """How many opennet peers the node can reach **right now** (R1's census).

        Read on an idle leased connection, never a shared one: `ListPeers` is a request like
        any other, and issuing it while a fetch is outstanding on the same socket is exactly
        the desynchronisation this pool exists to avoid. The lease goes back afterwards, so a
        relay that polls its own readiness does not bleed connections.

        This is the *only* readiness fact the relay asks the substrate for, and it is
        deliberately not `peer_count`: a fresh node's peer list fills with `NEVER CONNECTED`
        entries while nothing is reachable (measured 2026-11-12: 25 listed, 0-5 connected).
        """
        try:
            reader = self._pool.checkout(timeout=10.0)
        except TimeoutError:
            raise SubstrateError("read pool exhausted") from None
        try:
            count = int(reader.connected_peer_count())
        except Exception as exc:  # noqa: BLE001 - a census that fails is not a census of zero
            self._pool.discard(reader)
            raise SubstrateError("peer census failed: %s" % type(exc).__name__) from None
        self._pool.checkin(reader)
        return count


class WritePool:
    """The relay's held-connection substrate *insert*, used only by `POST /i`.

    The fetch surface has no write at all (`ReadPool.read` is its whole interface); this is
    the separate, opt-in half the owner publish path uses (the blind-fetch design). One archive
    in, one derived handle per object out - the owner cross-checks each handle against its
    locally derived `chk_ref(blob)`, so a lying relay is caught, and the *relay* is what
    holds the ~1.5 s FCP handshakes and the node's serialisation.

    The seam is one function, `seam(pool, items) -> {oid: ref}`: `pool` is a held-connection
    pool (`checkout`/`checkin`/`discard`), `items` is the object list `[(oid, ciphertext), …]`
    sorted by oid, and the answer maps each oid to the full `chk:CHK@…` handle. This module
    reimplements no `GetCHKOnly` derivation; the deployment supplies the adapter that reaches
    the substrate's own derivation (see `docs/blind-relay-interface.md`, "The insert seam").
    When no seam is configured the relay answers `write-unavailable` (501) rather than
    pretending to have inserted anything - an insert whose durability is not real is worse
    than a refusal.
    """

    def __init__(self, *, fcp_port: int = 0, host: str = "127.0.0.1", size: int = 4,
                 label: str = "blind-relay-insert", seam: Any = None) -> None:
        # The write half runs the adaptive queue: a small object goes real-time and a large
        # one bulk. This is the queue the production insert worker uses (`relay_spool_worker`)
        # and the only one measured to accept a block before a listener is waiting on it --
        # the bulk request starter is backed off on this substrate (`fill_lane_transport`), so
        # a bulk-only write half would wait on a starter that never runs.
        self._pool = _ReaderPool(fcp_port, host=host, size=size, label=label,
                                 insert_queue="adaptive")
        self._seam = seam

    @property
    def available(self) -> bool:
        return self._seam is not None

    def self_check(self) -> bool:
        """Derive the pinned handle from the substrate at start, storing nothing.

        `POST /i` stores through the substrate's own `put`; this asks the *same* runtime the
        *derive-only* question (`GetCHKOnly`, which stores nothing) for one fixed 32 KiB
        block, so a staged runtime that would frame an insert differently -- a `content_type`
        default, a wrapper -- is caught before the relay ever accepts a write. Returns True
        when the node derives `INSERT_SELF_CHECK_REF` for `INSERT_SELF_CHECK_BLOB`, False when
        it derives a different handle; a substrate that cannot answer raises `SubstrateError`.
        """
        mesh = self._pool.checkout(timeout=SELF_CHECK_TIMEOUT)
        try:
            ref = mesh.ref_for(INSERT_SELF_CHECK_BLOB, object_id="self-check",
                               timeout=SELF_CHECK_TIMEOUT)
        except _substrate_failures() as exc:
            self._pool.discard(mesh)
            raise SubstrateError(f"self-check derive failed: {type(exc).__name__}") from None
        except Exception:
            self._pool.discard(mesh)
            raise
        self._pool.checkin(mesh)
        # `Ref.value` is the full `chk:CHK@…`; `to_uri()` would strip the `chk:` and never
        # match. An empty or wrapped answer simply does not equal the pinned handle.
        return ref.value == INSERT_SELF_CHECK_REF

    def insert(self, blobs: dict[str, bytes]) -> dict[str, str]:
        """Derive a content-addressed handle for each object's ciphertext.

        `blobs` is `{object_id: ciphertext}` as the owner's spool archive carries it; the
        returned `{object_id: ref}` is what the owner confirms against its own derivation.
        """
        if self._seam is None:
            raise SubstrateError("write seam is not configured")
        items = sorted(blobs.items())
        return self._seam(self._pool, items)

    def close(self) -> None:
        self._pool.close()
