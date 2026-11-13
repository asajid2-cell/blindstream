"""The blind relay of ADR 0011: `GET /b/{ref}` and nothing else.

One route serves one thing. A caller presents a door credential (a conduit pass, ADR 0011
Decision 2) and a ref, and receives the ciphertext of that one content-addressed object, or
a refusal. There is no request body, no owner, no corpus, no grant, no routing proof, no
device id and no job id on the wire, and the reply is never personalised.

    GET /b/{ref}        Authorization: Bearer <door credential>
      200  application/octet-stream   the ciphertext of that one object
      404  not retrievable within the bounded hold (definitive for now; retry elsewhere)
      413  the object exceeds the wire ceiling
      429  the credential's own window is spent (Retry-After)
      503  the relay is shedding load / the substrate could not answer (Retry-After)

The rules this module is built to satisfy (ADR 0011 Decision 4), each guarded by a test:

1. **No logs.** No address, no path/ref, no timing, no size is written anywhere - not to a
   file, a journal or a metrics label. The only observability is a set of aggregate
   counters (accepted, refused, bytes, cache hits/misses, errors), which name no ref and no
   credential. `tests/test_blind_relay_nologs.py` proves *from the code's own abstract
   syntax tree* that this module contains no logging or file-writing construct at all, so
   adding a log line and re-running is a red proof, not a review promise.
2. **Cache keyed by the ref alone** (`blind_cache.RefCache`). A hit is a stated side
   channel (a side channel): it says someone fetched this ref recently, never who.
3. **A cache hit is a side channel, and the wire says nothing about it.** An earlier design used to
   state the hit in an `X-Blind-Cache` response header; that header is gone (F1, 2026-11-13)
   because a cross-user cache probe could read it. The relay still counts `hit`/`miss`
   internally as aggregate, ref-free data, and the two answers are byte-identical.
4. **No direct fallback.** The relay is reachable only as a v3 onion service. There is no
   clearnet path and no fallback: `--onion-host` makes the relay bind loopback-only and
   refuse any request whose `Host` is not that onion, so a clearnet client that reaches the
   daemon by accident is turned away rather than served.
5. **Reader pool, not a single reader.** Substrate reads go through `blind_substrate.ReadPool`
   (pooled, held connections; the node serialises fresh handshakes).

**Search, listing, updatable-key (SSK/USK) reads and insert are refused, not implemented.**
`do_GET` answers only `/b/{ref}`; every other path is 404 and every method but GET is 405,
including on `/b/`. There is no code path to a substrate operation other than the one
content-addressed read in `ReadPool.read`.

`POST /i` (the insert half, the blind-fetch design, owner-side lane) shares the credential and
the no-log rules and lands on this module as its own build step; it is not in this file yet.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Sequence

import blind_fec
from blind_cache import RefCache
from blind_door import OP_DISCOVERY, OP_FETCH, OP_INSERT, OP_PLAYBACK, DoorGate
from blind_window_reader import (
    WindowMalformed,
    WindowReader,
    WindowRequest,
    WindowUnavailable,
    WindowUndecodable,
    default_mesh_get,
    validate_window_refs,
)
from blind_substrate import (
    ReadPool,
    SubstrateError,
    SubstrateMiss,
    SubstrateTimeout,
    SubstrateTooLarge,
    WritePool,
)

# The ref is a content-addressed handlethe reader already verifies. The bound and the shape
# are the same the fetch fabric uses (`owner_spool_transport.valid_ref`, `fetch_gateway`):
# a `chk:CHK@` prefix, printable ASCII, no whitespace. A ref with a query, a fragment or a
# path separator is not a ref and is refused before it can reach the substrate.
REF_PATH = re.compile(r"^/b/(chk:CHK@[A-Za-z0-9,~_\-.]{1,500})$")
# The head route: one named *edition* of a mutable namespace, `GET /h/{usk}`.
#
# The catalogue's index pointer is one small object in an editioned namespace, and a device
# with no pointer yet has to be able to read it without the owner being up. That makes it a
# relay read - but not a content read: a USK names a revision, not a blob, so it cannot
# travel as a `Ref` (`crudenet.refs` refuses the prefix precisely so the two are never
# confused).
#
# The edition is required and must be a plain non-negative integer. `-1` is the substrate's
# "search for the newest" form and is refused before it reaches a node: measured 70.5 s cold
# against 0.16 s for a named edition on lab FCP 9591 (2026-11-12), which is a search wearing
# a read's clothes. The client carries the edition it last saw and asks for the next one.
HEAD_PATH = re.compile(
    r"^/h/(USK@[A-Za-z0-9,~_\-.]{1,400}/[A-Za-z0-9._\-]{1,64}/(?:0|[1-9][0-9]{0,17}))$")
# A content handle as the owner knows it: the full `chk:CHK@…` string (the same shape
# `owner_spool_transport.valid_ref` and the fetch fabric carry). The insert seam must
# answer one per object; a bare-base64 handle the owner cannot cross-check is refused.
HANDLE_RE = re.compile(r"^chk:CHK@[A-Za-z0-9,~_\-.]{1,500}$")
MAX_WIRE = 16 * 1024 * 1024

# The insert half (`POST /i`): one tarred spool archive per request, the exact shape
# `owner_spool_transport.spool_archive` writes and that Leaf 17's owner client sends.
INSERT_PATH = "/i"
# The window route: one POST, one body, one answer made of data shares. It is a
# *read*, so it shares the fetch pass and the fetch half's availability; a write-only
# relay has no window surface at all.
WINDOW_PATH = "/w"
MAX_WINDOW_BODY = 64 * 1024
OID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_OBJECTS = 16
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
INSERT_METADATA_FIELDS = {"object_id", "blob_sha256"}
INSERT_OPTIONAL_FIELDS = {"class", "deadline_rank"}


class Counters:
    """Aggregate, ref-free observability. Counts only, never a ref, credential or size.

    There is deliberately no per-ref and no per-credential series: a sideways aggregate is
    the only thing this daemon is allowed to know about its own traffic, because the traffic
    is exactly the metadata ADR 0011 Decision 4.1 forbids it to keep.
    """

    def __init__(self) -> None:
        self._values: dict[str, int] = {}
        self._lock = threading.Lock()

    def bump(self, key: str, by: int = 1) -> None:
        with self._lock:
            self._values[key] = self._values.get(key, 0) + by

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._values)


def bearer(header_value: str | None) -> str:
    """Extract the credential from an `Authorization: Bearer <pass>` header."""
    if not header_value or not header_value.startswith("Bearer "):
        return ""
    return header_value[len("Bearer "):].strip()


def read_spool_archive(raw: bytes) -> dict[str, bytes]:
    """Parse the owner's tarred spool archive into `{object_id: ciphertext}`.

    The relay validates the archive the same way the owner wrote it (`spool_archive`), so a
    malformed handoff is refused before anything reaches a substrate: exactly the `inbox/`
    members, each `NNNN.json` with a matching `NNNN.bin`, a metadata record whose fields are
    only the known ones, and a `blob_sha256` that matches the ciphertext bytes. A mismatch
    is the relay's own check that the bytes it is about to insert are the bytes named.

    Raises `ValueError` on anything else. Nothing here records a name, a size or a time.
    """
    blobs: dict[str, bytes] = {}
    metadata: dict[str, dict[str, Any]] = {}
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("not a tar archive") from exc
    with archive:
        for member in archive:
            parts = member.name.split("/")
            if len(parts) != 2 or parts[0] != "inbox" or member.isdir() or not member.isfile():
                raise ValueError("unexpected archive member")
            name = parts[1]
            stem = name.rsplit(".", 1)[0]
            if not OID_RE.match(stem):
                raise ValueError("invalid object identity")
            if name.endswith(".json"):
                if member.size > 4096 or stem in metadata:
                    raise ValueError("invalid spool metadata")
                record = json.loads(archive.extractfile(member).read(4097))
                if not isinstance(record, dict):
                    raise ValueError("invalid spool metadata")
                if (set(record) - INSERT_OPTIONAL_FIELDS) != INSERT_METADATA_FIELDS:
                    raise ValueError("invalid spool metadata")
                if record["object_id"] != stem:
                    raise ValueError("metadata names another object")
                metadata[stem] = record
            elif name.endswith(".bin"):
                if member.size > MAX_WIRE:
                    raise ValueError("ciphertext exceeds the wire ceiling")
                blobs[stem] = archive.extractfile(member).read(member.size + 1)
            else:
                raise ValueError("unexpected archive member")
    if not 0 < len(blobs) <= MAX_OBJECTS or len(blobs) != len(metadata) or set(blobs) != set(metadata):
        raise ValueError("incomplete spool archive")
    for oid, blob in blobs.items():
        if hashlib.sha256(blob).hexdigest() != metadata[oid]["blob_sha256"]:
            raise ValueError("ciphertext does not match its digest")
    return blobs


# A ref the substrate can hold must be a well-formed CHK key: `chk:CHK@<routing>,<encryption>,
# <suffix>` - two 32-byte Freenet-base64 keys and a 5-byte crypto-params suffix. A ref that
# matches `REF_PATH`'s charset but is not this shape (e.g. a field of the wrong decoded length,
# such as a 16-character all-`A` string) can never be stored by any node, so it is refused
# `404 not-a-ref` up front - definitive, never a `503` a client would retry (F7). This is a
# **shape** gate, not derivation: the relay still reimplements no CHK (the suffix's algorithm is
# the node's call, not the relay's), and the check is length, not content - a 43-character
# all-`A` field decodes to 32 bytes and *passes*, because whether it names a storable block is
# the node's answer, not the relay's.
_CHK_FIELD = re.compile(r"^[A-Za-z0-9~_-]+$")


def _chk_field_bytes(field: str) -> int | None:
    """Decoded byte length of one Freenet-base64 CHK field, or `None` if it is not one."""
    if not _CHK_FIELD.match(field) or len(field) % 4 == 1:
        return None
    pad = (-len(field)) % 4
    try:
        return len(base64.b64decode(field.replace("~", "+").replace("-", "/") + "=" * pad))
    except ValueError:
        return None


def chk_usable(ref: str) -> bool:
    """Can `ref` be a storable CHK key? Three fields, two 32-byte keys, a 5-byte suffix."""
    if not ref.startswith("chk:CHK@"):
        return False
    parts = ref[len("chk:CHK@"):].split(",")
    if len(parts) != 3:
        return False
    return [_chk_field_bytes(part) for part in parts] == [32, 32, 5]


def _refusal(code: int, reason: str, *, retry_after: int | None = None) -> tuple[int, bytes, dict[str, str]]:
    """A refusal body, and the headers that go with it. Contains no reflected input.

    The reason is a code the client switches on; it is never built from the request, so a
    refusal cannot echo a ref, a credential or a path back to the caller or into a log.
    """
    headers = {"Content-Type": "application/json"}
    if retry_after is not None:
        headers["Retry-After"] = str(int(retry_after))
    return code, json.dumps({"refusal": reason}).encode("utf-8"), headers


def window_fan_out(readers: int, requested: int) -> int:
    """The per-window share fan-out to run with: the request, or half the pool for zero.

    A fixed default cannot satisfy `check_window_pool` for every pool size, and a default
    that is too large turns the first straggling share into a wedged window. Half the pool
    is the ratio measured green, leaves at least one lease free for the next window, and
    needs no operator arithmetic.
    """
    if requested > 0:
        return requested
    return max(1, int(readers) // 2)


def check_window_pool(readers: int, window_readers: int) -> str | None:
    """Why the window route cannot run on this pool, or None when it can.

    The window reader takes one lease per share in flight, and a lease is held until its
    fetch returns - a straggling share can hold one past its window's deadline. So a window
    that may take *every* lease can, once one share straggles, leave the next window unable
    to check out the k it needs: it waits out its whole deadline and the client hedges for
    a reason that has nothing to do with the substrate.

    Measured 2026-11-12 on the test track: 12 readers with 4 shares in flight and 24 with 6
    were green (17/17 windows); 16 readers with 16 shares in flight wedged, three windows
    timing out at 45 s while every share was resident. The invariant is therefore strict:
    the pool must be larger than one window's fan-out, so a straggler always leaves room.

    This is a configuration error, not a runtime fault, and it is named at start rather
    than three windows later - a wedge reads as a substrate failure to anyone who hits it.
    """
    if readers < 1 or window_readers < 1:
        return ("--readers and --window-readers must both be positive (got %d and %d)"
                % (readers, window_readers))
    if window_readers >= readers:
        return ("--window-readers (%d) must be less than --readers (%d): a window may have "
                "one share in flight per lease, so a fan-out that can take every lease "
                "starves the next window as soon as one share straggles - it then waits out "
                "its deadline and the client hedges for no substrate reason. Raise --readers "
                "above the per-window fan-out (12/4 and 24/6 are known good)"
                % (window_readers, readers))
    return None


class SettleGate:
    """A relay only serves once its node can reach peers, and has for a while (R1).

    The predicate is the substrate's own `CONNECTED` peer count, not uptime, not a warm
    sample and not the length of the peer list. Measured on a fresh node 2026-11-12
    (`docs/measurements.md` section 7): `NodeHello` answers at 5 s with zero connected
    peers; the *list* reaches 25 entries while `CONNECTED` oscillates 0-5 for four minutes;
    8 connected at 243 s. A window pass begun on that node before the count held lost 12 of
    17 windows; the same pass after it answered 17/17.

    Two knobs, both measured rather than guessed:
      * `floor` - the count that must be held. 8 is the smallest number the settle run
        actually observed reaching, and a relay that released at 1 or 3 would release into
        the oscillation above.
      * `stability_s` - how long it must hold without dipping. The measured curve fell back
        to 0 twice after reaching 3 and 4 (at 102 s and 172 s), so a one-sample reading is
        not a settle: it is one point on a curve that goes back down.

    Until both hold the relay answers `503 relay-warming` with Retry-After, which is
    "ask another relay", the same instruction `window-incomplete` carries. The check is
    cheap and infrequent: one `ListPeers` per `poll_s`, on a leased pooled connection.

    A settle is a licence that can be lost, not one granted for the process's life (D6). The
    census keeps being polled after `_settled`, and a count that sits below the floor for
    `demote_after_s` takes the relay back to `503 relay-warming`; it is re-admitted only by
    holding the floor for a fresh `stability_s`. Measured 2026-11-13: a settled lab node lost
    its peer count when the uplink blipped and kept answering windows, which is the same
    failure the warm path exists to refuse - the client pays for a node that cannot route.
    """

    #: The floor, **measured** rather than guessed. `floor_sweep.py` ran one full window pass
    #: of the test publication in each connected-count band on a fresh node (2026-11-12,
    #: artefact `docs/fastsub-r1-floor-sweep.json`), gate off, 30 s held in each band:
    #:
    #:   band (0,1)  -> 15/17 windows, 262.8 s wall
    #:   band (4,5)  -> 17/17, 1.1 s
    #:   band (6,7)  -> 17/17, 13.7 s
    #:   band (8,11) -> 17/17, 1.8 s
    #:   band (12,+) -> 17/17, 1.2 s
    #:
    #: The pass is complete from 5 connected up, so the smallest defensible floor is 5. The
    #: earlier value, 8, was where the settle run happened to cross on one box - not a
    #: measurement, and a cold node spent an extra ~200 s refused for it. 5 is a floor, not a
    #: claim about capacity: a settled node sampled 13-16 connected, and the gate does not
    #: refuse a node merely for being quiet.
    DEFAULT_FLOOR = 5
    #: Long enough that the oscillation measured on the cold node (down to 0 after 3 and 4)
    #: cannot satisfy it with a lucky sample, short enough that a settled node is not held
    #: back: a settled node never dips below the floor, so this costs it one window.
    DEFAULT_STABILITY_S = 30.0
    #: How long the census may stay below the floor before a *settled* relay stops serving
    #: (D6). Two polls at the shipped `poll_s` of 5 s, so one missed census is not a
    #: demotion; long enough that a client mid-play is not knocked off by a momentary dip,
    #: short enough that a genuinely peerless node stops being handed deadlines.
    DEFAULT_DEMOTE_AFTER_S = 10.0

    def __init__(self, substrate: Any, *, floor: int = DEFAULT_FLOOR,
                 stability_s: float = DEFAULT_STABILITY_S, poll_s: float = 5.0,
                 demote_after_s: float = DEFAULT_DEMOTE_AFTER_S, now=time.monotonic) -> None:
        self.substrate = substrate
        self.floor = max(0, int(floor))
        self.stability_s = max(0.0, float(stability_s))
        self.poll_s = max(0.05, float(poll_s))
        self.demote_after_s = max(0.0, float(demote_after_s))
        self._now = now
        self._lock = threading.Lock()
        # When the floor was first observed *continuously*, or None while it is not held.
        self._holding_since: float | None = None
        # When the census first dropped below the floor after a settle, while still inside
        # the demotion grace. None means the count is at or above the floor.
        self._below_since: float | None = None
        self._last_poll = float("-inf")
        self._settled = False
        # The record the operator reads: how many censuses, when the floor was first met,
        # when it became a settle. Counts and times only - no ref, no peer, no address.
        self.census = 0
        self.first_hold_at: float | None = None
        self.settled_at: float | None = None
        # D6: how many times a settle was lost, and when the last one was.
        self.demotions = 0
        self.demoted_at: float | None = None

    def _census_now(self) -> int:
        census = getattr(self.substrate, "connected_peers", None)
        if census is None:
            # A substrate with no peer surface (a fixture, or the block route's plain file
            # backend) has nothing to settle on. Treating that as "not settled" would make a
            # test-only relay permanently warming; treating it as "settled" is the honest
            # reading of "there is no network path to be ready for".
            return self.floor
        return int(census())

    def ready(self) -> bool:
        """Is this relay allowed to serve? Polls at most once per `poll_s`."""
        with self._lock:
            now = self._now()
            if now - self._last_poll < self.poll_s:
                # Between polls: the last answer stands, so a burst of client requests costs
                # one census between them rather than one each. A settled relay stays
                # settled between polls; an unsettled one stays refused.
                return self._settled
            self._last_poll = now
            try:
                count = self._census_now()
            except Exception:  # noqa: BLE001 - a census that fails is not a settled node
                # Fail closed: a census that cannot answer is read as a node with no peers,
                # so it feeds the same demotion timer a zero count does.
                count = -1
            self.census += 1
            if count < self.floor:
                self._holding_since = None
                if not self._settled:
                    return False
                if self._below_since is None:
                    self._below_since = now
                if now - self._below_since < self.demote_after_s:
                    # Inside the grace: a dip is not yet a loss, and demoting on one quiet
                    # census would take a healthy relay out of the fleet for 30 s.
                    return True
                # D6: the peer count has been below the floor for the whole grace window.
                # The node cannot route, so stop accepting windows and say so the same way
                # a warming relay does: ask another relay, come back.
                self._settled = False
                self._below_since = None
                self.demoted_at = now
                self.demotions += 1
                return False
            self._below_since = None
            if self._settled:
                return True
            if self._holding_since is None:
                self._holding_since = now
                self.first_hold_at = now
            if now - self._holding_since >= self.stability_s:
                self._settled = True
                self.settled_at = now
                return True
            return False


def window_units(k: int) -> int:
    """Pass units one window costs: `ceil(k/16)`.

    One unit used to buy one second of audio. A 16-block window is about 13 s of a
    320 kbps stream, so charging one unit per 16 data shares keeps the meter's shape --
    an abuse brake on how much a credential may pull -- while removing it as the
    capacity bound.
    """
    return max(1, (int(k) + 15) // 16)


# How long a head answer may be reused, in seconds.
#
# A named-edition read is *not* a pin: measured on lab FCP 9591, asking for edition 0 while
# edition 2 was current returned edition 2's bytes (reported edition 2, 0.02 s). So the URI the
# cache is keyed by names a slot whose meaning moves whenever the owner publishes, and a hit
# under the block route's 600 s TTL would serve a pointer from a revision that has already been
# superseded. The window is short because the reuse is worth almost nothing: a head hit on the
# node is 0.02 s, and what the cache saves is one local read.
HEAD_CACHE_TTL_S = 5.0

# D6b: the census cannot see a node the network has left, so the reads have to say it.
#
# Measured 2026-11-13 on a Cybera Fred: cutting peer UDP both ways (verified matching 63
# packets in 15 s) moved `volatile.status == CONNECTED` only from 29 to 16-25 over minutes -
# Freenet holds the status long after the last packet, and `ListPeers` in build 1507 carries
# no last-received-packet field to bound it with. `volatile.percentTimeRoutableConnection` and
# `averagePingTime` describe those unreachable peers as healthy, because they are frozen. So
# the *only* observable of "the network left us" is that reads stop working.
#
# A relay therefore demotes on evidence: three consecutive window reads that could not reach k
# shares, spanning at least ROUTE_FAIL_MIN_SPAN_S, take it out for ROUTE_DEMOTE_S. Refusals
# caused by the client (401/429/400/cold) never count, and one successful window clears the
# streak.
ROUTE_FAIL_STREAK = 3
ROUTE_FAIL_MIN_SPAN_S = 20.0
ROUTE_DEMOTE_S = 60.0


class ShareDropped(RuntimeError):
    """A share the relay deliberately lost, classified by the reader as a definitive miss.

    The reader reads FCP codes rather than exception types, on purpose: 13 is the node saying
    "I have finished with this request and the answer is no", which is the one failure that
    leaves the connection clean and lets another share take this one's place.
    """

    code = 13


class Faults:
    """Deliberate faults on a *test* relay, for the client lane's device arms (A4/A6/A9).

    Every switch is inert unless its environment variable is set, and a unit test proves the
    default is inert. They exist so a hedge, an integrity check and a loss margin can be
    measured against the *real* relay rather than a fake transport; a serving relay is started
    with none of these set, so nothing here can fire by accident.

      BLINDSTREAM_FAULT_DROP_PCT   drop exactly this percent of every window's shares (A9a)
      BLINDSTREAM_FAULT_DELAY_S    hold the answer this many seconds (A4b)
      BLINDSTREAM_FAULT_BLACKHOLE  accept the request and never answer (A4c, HTTP stall)
      BLINDSTREAM_FAULT_CORRUPT    flip one byte in the first share of a good answer (A6)
      BLINDSTREAM_FAULT_TRUNCATE   answer half the body a good answer would have (A6)

    **A4a is not here.** A handshake blackhole has to happen below HTTP: the relay's tor
    forwards the onion port to `127.0.0.1:<relay port>`, so `iptables -I INPUT -p tcp --dport
    <relay port> -j DROP` on loopback makes the connection hang before a request is written -
    a TCP-level stall, which is what the client's handshake budget is for.

    The dropped shares are chosen evenly across the window and their count is exactly
    `floor(n * pct / 100)`, so "25 %" is 3 of 12, 5 of 20 and 8 of 32 - the arithmetic the
    verdict quotes, not a random draw the run cannot reproduce.
    """

    #: How long a blackholed request is held before the thread gives up. The client's own
    #: bound is shorter; this only keeps the switch from pinning a thread forever.
    BLACKHOLE_SECONDS = 120.0

    def __init__(self, *, drop_pct: int = 0, delay_s: float = 0.0, blackhole: bool = False,
                 corrupt: bool = False, truncate: bool = False) -> None:
        self.drop_pct = max(0, min(100, int(drop_pct)))
        self.delay_s = max(0.0, float(delay_s))
        self.blackhole = bool(blackhole)
        self.corrupt = bool(corrupt)
        self.truncate = bool(truncate)

    @classmethod
    def from_env(cls, environ=None) -> "Faults":
        env = os.environ if environ is None else environ
        def flag(name: str) -> bool:
            return str(env.get(name, "")).strip().lower() not in ("", "0", "false", "no", "off")
        def number(name: str) -> float:
            raw = str(env.get(name, "")).strip()
            try:
                return float(raw) if raw else 0.0
            except ValueError:
                return 0.0
        return cls(drop_pct=int(number("BLINDSTREAM_FAULT_DROP_PCT")),
                   delay_s=number("BLINDSTREAM_FAULT_DELAY_S"),
                   blackhole=flag("BLINDSTREAM_FAULT_BLACKHOLE"),
                   corrupt=flag("BLINDSTREAM_FAULT_CORRUPT"),
                   truncate=flag("BLINDSTREAM_FAULT_TRUNCATE"))

    def active(self) -> bool:
        return bool(self.drop_pct or self.delay_s or self.blackhole or self.corrupt
                    or self.truncate)

    def drop_indexes(self, n: int) -> set[int]:
        """Exactly `floor(n * pct / 100)` indexes, spread evenly across the window."""
        count = (int(n) * self.drop_pct) // 100
        if count <= 0 or n <= 0:
            return set()
        # Index i is dropped when the running quota crosses an integer between i and i+1.
        return {i for i in range(n)
                if (i * count) // n != ((i + 1) * count) // n}

    def damaged(self, body: bytes) -> bytes:
        """Apply an integrity fault to a good answer, if one is switched on."""
        if not body:
            return body
        if self.corrupt:
            first = bytearray(body[:blind_fec.SHARE_BYTES])
            first[0] ^= 0xFF
            return bytes(first) + body[blind_fec.SHARE_BYTES:]
        if self.truncate:
            return body[: len(body) // 2]
        return body


class Relay:
    """The relay's decision core, testable without a socket.

    `handle_fetch(ref, credential)` is the whole content surface: it returns
    `(status, body, headers)`. The HTTP layer only maps it onto the wire, so a test can
    assert the policy directly and the daemon and the test share one code path.
    """

    def __init__(self, *, gate: DoorGate, cache: RefCache, substrate: Any,
                 insert: Any = None, hold_seconds: float = 60.0, read_enabled: bool = True,
                 counters: Counters | None = None, now=time.time,
                 window_reader: WindowReader | None = None,
                 head_cache: RefCache | None = None,
                 faults: "Faults | None" = None,
                 require_role_passes: bool = False) -> None:
        self.gate = gate
        self.cache = cache
        # The head gets its own cache, because its key does not mean what a block ref means.
        # See HEAD_CACHE_TTL_S: a named edition resolves to the newest, so the same URI can name
        # different bytes minutes apart, and only a short window keeps a hit from being a lie.
        self.head_cache = head_cache if head_cache is not None else RefCache(
            max_entries=64, ttl_seconds=HEAD_CACHE_TTL_S, max_bytes=1024 * 1024)
        self.substrate = substrate
        # The write host runs the read half **off** (`--insert-only`): it is not a read relay
        # and must not become one. With reads disabled there is no code path to a substrate read,
        # so a `GET /b/{ref}` on that host is refused before anything is looked up - the read
        # surface is absent, not merely dark. `substrate` is `None` in that stance.
        self.read_enabled = read_enabled
        # The write half is opt-in: a relay with no insert seam refuses `/i` rather than
        # pretending. The fetch surface is byte-identical whether or not one is configured.
        self.insert = insert
        self.hold_seconds = float(hold_seconds)
        self.counters = counters or Counters()
        self._now = now
        # The window reader is the fetch half's other shape: a whole window at once,
        # first k wins. It is absent on a write-only relay, for the same reason the
        # substrate is.
        self.window_reader = window_reader
        # Whether this relay may serve a window yet. Measured 2026-11-12 on the test track:
        # a fresh Fred's first window pass lost 4 of 17 to share timeouts and its second
        # answered 17/17, with windows falling 37 -> 12 s as the node filled its store.
        # A relay that answers a window while still cold therefore hands the client a
        # warm-up cost it never agreed to pay, so warmth is part of readiness rather than
        # a tuning note. A relay with no warm pass to run (a test fixture, or the block
        # route alone) is ready from start: nothing to pay.
        self.warm = False
        # R1: settle-gated admission. `settle` is a `SettleGate` when this relay has a peer
        # surface to judge, and `None` on a relay that has nothing to wait for (a fixture, a
        # write-only host, or an operator who has explicitly disabled the gate). It is checked
        # on the window route, which is the route a cold node measurably loses windows on.
        self.settle = None
        # Test-relay faults (A4/A6/A9). A production relay has all of these off; the object
        # is always present so the window path has no None branch to get wrong.
        self.faults = faults or Faults()
        # Plan2 §5: one pass per role. With this on, `/h/` requires a `discovery` pass and
        # `/w` a `playback` pass, and a `fetch` pass opens neither - so a relay cluster
        # cannot link a listener's discovery to its playback by the bearer it sees. It is off
        # by default because the deployed client presents `fetch` everywhere; the sweep to
        # turn it on is the fleet's, `--require-role-passes`.
        self.require_role_passes = bool(require_role_passes)
        # D6b: the read-evidence side of readiness. Counts consecutive window reads that could
        # not reach k, and the time the streak began; `_route_down_until` is set while the
        # relay is demoted for it.
        self._route_fails = 0
        self._route_fail_since: float | None = None
        self._route_down_until: float | None = None
        self.route_demotions = 0

    # -- the one content route ------------------------------------------------

    def handle_fetch(self, ref: str, credential: str) -> tuple[int, bytes, dict[str, str]]:
        if not self.read_enabled:
            # A write-only relay: the read half is not deployed here, so there is nothing to
            # serve and no substrate to ask. Refused before the credential, because this route
            # does not exist on this host at all.
            self.counters.bump("no-read-surface")
            return _refusal(404, "no-read-surface")
        token, verdict = self.gate.admits(credential, op=OP_FETCH, now=self._now())
        if token is None:
            self.counters.bump("refused")
            return _refusal(401, verdict)
        if not self.gate.spend_window(token, now=self._now()):
            # The credential's own window is spent. This is the only brake the relay has
            # (C4): a per-credential budget, never a content decision.
            self.counters.bump("metered")
            return _refusal(429, "window-spent", retry_after=5)

        cached = self.cache.get(ref, now=self._now())
        if cached is not None:
            # A cache hit is a side channel, and until F1 the response stated it in a header.
            # That header is gone: anyone holding a ref could probe it and learn that someone
            # else had asked for the same object. The answer is now byte-identical to a miss.
            self.counters.bump("hit")
            self.counters.bump("bytes", len(cached))
            return 200, cached, {"Content-Type": "application/octet-stream"}

        self.counters.bump("miss")
        try:
            blob = self.substrate.read(ref, max_size=MAX_WIRE)
        except SubstrateMiss:
            self.counters.bump("not-available")
            return _refusal(404, "not-available")
        except SubstrateTooLarge:
            self.counters.bump("too-large")
            return _refusal(413, "too-large")
        except SubstrateTimeout:
            # Same 503 the client sees, but a different operational fact: the read ran out
            # the serving bound, which is NOT the substrate being down. The counters may say
            # so without naming a ref (they carry no ref, credential or size).
            self.counters.bump("serve-timeout")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        except SubstrateError:
            self.counters.bump("substrate-error")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        self.cache.put(ref, blob, now=self._now())
        self.counters.bump("bytes", len(blob))
        return 200, blob, {"Content-Type": "application/octet-stream"}

    # -- the head route -------------------------------------------------------

    def handle_head(self, uri: str, credential: str) -> tuple[int, bytes, dict[str, str]]:
        """`GET /h/{usk}`: one named edition of the catalogue head's namespace.

        Metered exactly like a block: same fetch pass, same window, one unit. The head is one
        small object fetched at first open, so it must cost what a block costs - a separate
        budget would be a second door with its own rules, and the point of one credential is
        that every read is the same read.

        Nothing about the request is recorded: no namespace, no edition, no credential. The
        counters carry only outcomes, and the answer says nothing about the relay's cache
        state (F1): a hit and a miss are the same 200 with the same headers.
        """
        if not self.read_enabled:
            self.counters.bump("no-read-surface")
            return _refusal(404, "no-read-surface")
        op = OP_DISCOVERY if self.require_role_passes else OP_FETCH
        token, verdict = self.gate.admits(credential, op=op, now=self._now())
        if token is None:
            self.counters.bump("refused")
            return _refusal(401, verdict)
        if not self.gate.spend_window(token, now=self._now()):
            self.counters.bump("metered")
            return _refusal(429, "window-spent", retry_after=5)

        cached = self.head_cache.get(uri, now=self._now())
        if cached is not None:
            self.counters.bump("hit")
            self.counters.bump("head-bytes", len(cached))
            return 200, cached, {"Content-Type": "application/octet-stream"}
        self.counters.bump("miss")
        try:
            blob = self.substrate.read_edition(uri, max_size=MAX_WIRE)
        except SubstrateMiss:
            # Definitive *for this edition*: the namespace may exist at another one, and the
            # client's own probing decides that. `head-absent` rather than `not-available`
            # so the counter cannot be read as "the catalogue is gone".
            self.counters.bump("head-absent")
            return _refusal(404, "head-absent")
        except SubstrateTooLarge:
            self.counters.bump("too-large")
            return _refusal(413, "too-large")
        except SubstrateTimeout:
            self.counters.bump("serve-timeout")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        except SubstrateError:
            self.counters.bump("substrate-error")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        self.head_cache.put(uri, blob, now=self._now())
        self.counters.bump("head-bytes", len(blob))
        return 200, blob, {"Content-Type": "application/octet-stream"}

    # -- readiness by evidence (D6b) ------------------------------------------

    def _note_route_failure(self, now: float) -> None:
        """Count one window that could not reach k, and demote on a sustained streak (D6b).

        Only the substrate's own failures come here - a spent pass, a malformed body or a cold
        relay are the client's or the start's, not the network's. The span condition is what
        keeps a burst of retries inside one bad minute from being read as a dead node.
        """
        self._route_fails += 1
        if self._route_fails == 1:
            self._route_fail_since = now
        if (self._route_fails >= ROUTE_FAIL_STREAK
                and self._route_fail_since is not None
                and now - self._route_fail_since >= ROUTE_FAIL_MIN_SPAN_S):
            self._route_down_until = now + ROUTE_DEMOTE_S
            self._route_fails = 0
            self._route_fail_since = None
            self.route_demotions += 1

    # -- the pool's cancel seam -----------------------------------------------

    def _cancel_share(self, handle: str) -> bool:
        """End one in-flight share read, so its connection can go back to the pool clean.

        The window reader asks for this once it has k shares (the rest are answers nobody
        wants) and again at the deadline. It matters for the *pool*, not for the window: a
        request left running keeps its connection out of service until its own bound expires,
        and then the connection is unusable anyway because its reply may still be in flight.
        Cancelling is what turns "the pool must be bigger than the fan-out" from something
        that makes the route work into a plain safety guard.

        A substrate that cannot cancel is not a failure: this returns False, the reader falls
        back to discarding the poisoned lease, and the relay serves. It is just costlier.
        """
        cancel = getattr(self.substrate, "cancel", None)
        if cancel is None:
            return False
        try:
            return bool(cancel(handle))
        except Exception:  # noqa: BLE001 - a cancel that raises costs a lease, never a window
            return False

    # -- the window route ------------------------------------------------------

    def handle_window(self, credential: str, raw: bytes) -> tuple[int, bytes, dict[str, str]]:
        """`POST /w`: read one window's shares, decode, answer with the data shares.

        The pass is the *fetch* pass, not a second surface: a window is a read that asks
        for several objects at once, so it is metered by the same credential and charged
        `ceil(k/16)` units -- one unit now buys about 13 s of audio instead of one
        second's.

        Every refusal is a code the client switches on and none carries a ref: a
        malformed body is 400, a spent window 429, and a window that could not reach k
        shares by its deadline is 503 `window-incomplete` with a Retry-After, which is
        "ask another relay", never "this track is broken".
        """
        if not self.read_enabled or self.window_reader is None:
            self.counters.bump("no-window-surface")
            return _refusal(404, "no-read-surface")
        if self.faults.blackhole:
            # A4a: the request was accepted and no answer will come. The point of the arm is
            # the client's hedge, so the relay must look alive and silent, not refuse.
            self.counters.bump("fault-blackhole")
            time.sleep(self.faults.BLACKHOLE_SECONDS)
            return _refusal(503, "window-incomplete", retry_after=2)
        if self.faults.delay_s:
            # A4b: a slow primary. Sleeping here holds the answer at the same place a slow
            # substrate read would, so the client's trigger and its hedge see the real shape.
            self.counters.bump("fault-delay")
            time.sleep(self.faults.delay_s)
        if self.settle is not None and not self.settle.ready():
            # R1: the node cannot reach peers yet, or has not held them long enough. This is
            # the *first* readiness check, before warmth, because it is the earlier fact: a
            # node with no connected peer has nothing to warm against. Same instruction to the
            # client (`relay-warming`, ask another relay), different reason recorded.
            self.counters.bump("relay-unsettled")
            return _refusal(503, "relay-warming", retry_after=5)
        if self._route_down_until is not None and self._now() < self._route_down_until:
            # D6b: the reads have been failing, so this node is not serving the network right
            # now however its peer list reads. Same instruction: ask another relay.
            self.counters.bump("route-demoted")
            return _refusal(503, "relay-warming", retry_after=5)
        if self.window_reader.warm_required and not self.warm:
            # Starting, not broken: the client is told to ask another relay and come back,
            # which is the same instruction `window-incomplete` carries and the one the
            # client already implements. Serving now would spend the client's deadline on
            # the node's warm-up - measured as 4 lost windows on a cold Fred.
            self.counters.bump("window-cold")
            return _refusal(503, "relay-warming", retry_after=5)
        op = OP_PLAYBACK if self.require_role_passes else OP_FETCH
        token, verdict = self.gate.admits(credential, op=op, now=self._now())
        if token is None:
            self.counters.bump("refused")
            return _refusal(401, verdict)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.counters.bump("malformed-window")
            return _refusal(400, "malformed-window")
        try:
            request = WindowRequest.from_body(body)
            validate_window_refs(request, usable=chk_usable)
        except WindowMalformed:
            self.counters.bump("malformed-window")
            return _refusal(400, "malformed-window")
        # The window's whole cost is charged at once, before the read. All-or-nothing, so
        # a pass that cannot pay for the window is refused without being half-spent.
        if not self.gate.spend_window(token, units=window_units(request.k), now=self._now()):
            self.counters.bump("metered")
            return _refusal(429, "window-spent", retry_after=5)
        mesh_get = None
        if self.faults.drop_pct:
            # A9a: this share of every window is lost before it is read. The drop is applied
            # at the *fetch* seam, not by removing refs from the request: the reader places
            # each share by its position, so a shortened list would silently mis-number every
            # share after the first drop and the window would decode into wrong bytes. A
            # definitive miss is exactly how a refused or lost share reaches the reader, and
            # the k-of-n guarantee is then what the arm measures.
            dropped = self.faults.drop_indexes(len(request.shares))
            if dropped:
                self.counters.bump("fault-shares-dropped", len(dropped))
                lost = {request.shares[index] for index in dropped}
                base = default_mesh_get
                def mesh_get(mesh, ref, bound, **kwargs):
                    if ref in lost:
                        raise ShareDropped("fault: share dropped")
                    return base(mesh, ref, bound, **kwargs)
        try:
            outcome = self.window_reader.read(request, cancel=self._cancel_share,
                                              mesh_get=mesh_get)
        except WindowUnavailable:
            self.counters.bump("window-incomplete")
            self._note_route_failure(self._now())
            return _refusal(503, "window-incomplete", retry_after=2)
        except WindowUndecodable:
            # k arrived and the code could not reconstruct from them. Same instruction to the
            # client as `window-incomplete` - ask another relay - because a second relay with a
            # working erasure library serves it. Without this the exception escaped the handler
            # and the socket closed, which the client cannot tell from a network fault.
            # The counter is bumped by the reader, which shares this relay's `Counters`; bumping
            # it here as well counts one failed window twice.
            return _refusal(503, "window-undecodable", retry_after=2)
        except SubstrateError:
            self.counters.bump("substrate-error")
            self._note_route_failure(self._now())
            return _refusal(503, "substrate-unavailable", retry_after=2)
        # A window that decoded is proof the node can still route: the streak ends here.
        self._route_fails = 0
        self._route_fail_since = None
        body = b"".join(outcome.shares)
        if self.faults.corrupt or self.faults.truncate:
            # A6: the answer is a good window with one byte flipped, or half of one. The
            # client's digest check is the thing under test, so the relay must answer 200.
            self.counters.bump("fault-damaged")
            body = self.faults.damaged(body)
        self.counters.bump("window-bytes", len(outcome.shares) * blind_fec.SHARE_BYTES)
        return 200, body, {
            "Content-Type": "application/octet-stream",
            "X-Window-Shares-Used": str(outcome.shares_used),
            # ClientGets the relay actually dispatched - which is *not* n: once k have arrived
            # the workers stop asking, so a fast window sits between k and n. The arithmetic
            # the cancel is proved by is on the wire: `issued == arrived + cancelled + failed`,
            # `issued + skipped == n`, and a share never asked for is `skipped`, not issued and
            # then cancelled. `arrived` can exceed k by a share that lands just after the
            # window was answered. No ref, no size and nothing about a track is in any of
            # these.
            "X-Window-Shares-Issued": str(outcome.issued),
            "X-Window-Shares-Arrived": str(outcome.arrived),
            "X-Window-Shares-Cancelled": str(outcome.cancelled),
            "X-Window-Shares-Failed": str(outcome.failed),
            "X-Window-Shares-Skipped": str(outcome.skipped),
        }

    def handle_insert(self, credential: str, raw: bytes) -> tuple[int, bytes, dict[str, str]]:
        """`POST /i`: insert one owner spool archive, answer one derived handle per object.

        The pass gates the *conduit* exactly as the fetch pass does (`op == "insert"`), and
        the relay never reads the archive for authorization - only for the bytes. The owner
        does not trust the handle it gets back: it re-derives `chk_ref(blob)` locally and
        refuses a disagreement, so a lying relay is caught.
        """
        token, verdict = self.gate.admits(credential, op=OP_INSERT, now=self._now())
        if token is None:
            self.counters.bump("refused")
            return _refusal(401, verdict)
        if not self.gate.spend_window(token, now=self._now()):
            self.counters.bump("metered")
            return _refusal(429, "window-spent", retry_after=5)
        if self.insert is None:
            # This deployment has no substrate write seam. Refusing is the honest answer:
            # an insert whose durability is not real is worse than a "try another relay".
            self.counters.bump("write-unavailable")
            return _refusal(501, "write-unavailable")
        try:
            blobs = read_spool_archive(raw)
        except (ValueError, OSError, json.JSONDecodeError):
            self.counters.bump("malformed-insert")
            return _refusal(400, "malformed-insert")
        try:
            refs = self.insert.insert(blobs)
        except SubstrateError:
            self.counters.bump("substrate-error")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        # Only ids the caller named and the relay derived: an id the relay invented would
        # be an object the owner cannot cross-check, so it is dropped rather than answered.
        answer = {oid: refs[oid] for oid in sorted(blobs) if oid in refs}
        if set(answer) != set(blobs):
            self.counters.bump("insert-incomplete")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        # The pinned seam contract: every handle is the full `chk:CHK@…` the owner re-derives
        # against. A bare or malformed handle is a broken write half, refused rather than
        # answered - the owner would reject it anyway, and a clean refusal says "try another".
        if not all(isinstance(r, str) and HANDLE_RE.match(r) for r in answer.values()):
            self.counters.bump("insert-bad-handle")
            return _refusal(503, "substrate-unavailable", retry_after=2)
        self.counters.bump("inserted", len(answer))
        body = json.dumps({"refs": answer}).encode("utf-8")
        return 200, body, {"Content-Type": "application/json"}


class _Server(ThreadingHTTPServer):
    """The serving socket. Bounded backlog; no per-connection state is retained."""

    request_queue_size = 128
    daemon_threads = True

    def __init__(self, address, handler, *, relay: Relay, onion_host: str | None) -> None:
        self.relay = relay
        self.onion_host = onion_host
        super().__init__(address, handler)

    def handle_error(self, request, client_address) -> None:
        # `socketserver` prints a full traceback to stderr, which on a serving host is
        # journald. A traceback can carry a ref's frame locals, and this daemon must write
        # nothing about a request anywhere - so the traceback is swallowed entirely. The
        # aggregate error counter is bumped by the handler; nothing else is recorded.
        self.relay.counters.bump("handler-error")


def make_handler(relay: Relay, *, onion_host: str | None) -> type[BaseHTTPRequestHandler]:
    """Build the request handler bound to one relay.

    `onion_host` is the relay's own v3 onion address. When set, a request arriving with any
    other `Host` is refused (`421`): the daemon sits behind Tor's `HiddenServicePort`
    forwarding, and a request that did not come through the onion service must not be
    served. `None` is the loopback test/dev stance and is refused by `main()` for a real
    bind unless explicitly acknowledged.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Headers+body total deadline. A GET carries no body (enforced), so this bounds a
        # trickled header line and nothing more.
        timeout = 15.0

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            # BaseHTTPRequestHandler's default writes `address - - "request" status` to
            # stderr, which is journald on a serving host: address + ref + time, exactly
            # what ADR 0011 Decision 4.1 forbids. Silenced at the source.
            pass

        def log_error(self, format: str, *args: object) -> None:  # noqa: A002
            pass

        # -- wire plumbing ----------------------------------------------------

        def _send(self, status: int, body: bytes, headers: dict[str, str]) -> None:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            # Never cached by an intermediary: the relay's own ref-keyed cache is the only
            # cache in the design, and a proxy cache would be a second, unstated one.
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    # The caller went away (a client that gave up on the hold). That is not
                    # an error to record - recording it would be a per-request event.
                    pass

        def _refuse(self, status: int, reason: str, *, retry_after: int | None = None) -> None:
            code, body, headers = _refusal(status, reason, retry_after=retry_after)
            self._send(code, body, headers)

        def _drain_body(self, *, limit: int = 1 << 20) -> None:
            """Consume a request body so the connection stays usable, without reading it.

            A GET carries no body; if one is present the request is refused, but the bytes
            must still be read off the socket before the reply or the client hangs. `limit`
            bounds what is drained: a refused request must not make the relay spend its own
            bandwidth reading an unbounded upload.
            """
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                return
            remaining = min(max(0, length), max(0, limit))
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)

        def _onion_ok(self) -> bool:
            if onion_host is None:
                return True
            host = self.headers.get("Host", "")
            return host.split(":", 1)[0].lower() == onion_host.lower()

        # -- routes -----------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            if not self._onion_ok():
                # Not our onion service. Refuse; do not serve, do not fall back to clearnet.
                self._drain_body()
                self._refuse(421, "not-onion")
                return
            match = REF_PATH.match(self.path)
            if match is None:
                head = HEAD_PATH.match(self.path)
                if head is not None:
                    if self.headers.get("Content-Length", "0") not in ("", "0"):
                        self._drain_body()
                        self._refuse(400, "body-not-allowed")
                        return
                    status, body, headers = relay.handle_head(
                        head.group(1), bearer(self.headers.get("Authorization")))
                    self._send(status, body, headers)
                    return
                # Everything that is not `GET /b/{ref}` or `GET /h/{edition}`.
                self._drain_body()
                if self.path.startswith("/b/") and "?" in self.path:
                    # A ref path carrying a query is a request to attach something beside
                    # the ref. The ref is the only input the surface has, so this is a
                    # malformed ref (400), not a route.
                    self._refuse(400, "malformed-request")
                elif self.path.startswith("/h/"):
                    # A head path that did not parse is a malformed head (400): a negative
                    # edition and a USK with no edition both land here, and both are requests
                    # the relay will not turn into a search. Distinct from "no route".
                    self._refuse(400, "malformed-head")
                else:
                    # No route here: no search, no listing, no HEAD that enumerates, and no
                    # namespace read other than one named edition. There is no code path to
                    # answer it (404).
                    self._refuse(404, "not-a-ref")
                return
            if not chk_usable(match.group(1)):
                # Shape-valid but not a CHK key (F7): it can never be stored by any node, so
                # it is definitive (`404 not-a-ref`), never a retryable `503`. Refused here,
                # before the substrate, so the node is never asked to parse a dead ref.
                self._drain_body()
                self._refuse(404, "not-a-ref")
                return
            if self.headers.get("Content-Length", "0") not in ("", "0"):
                self._drain_body()
                self._refuse(400, "body-not-allowed")
                return
            status, body, headers = relay.handle_fetch(match.group(1),
                                                       bearer(self.headers.get("Authorization")))
            self._send(status, body, headers)

        def do_POST(self) -> None:  # noqa: N802
            # `POST /i` is the only POST: one tarred spool archive, one pass. Everything
            # else - and every other method - is refused below.
            if not self._onion_ok():
                self._drain_body()
                self._refuse(421, "not-onion")
                return
            if self.path == WINDOW_PATH:
                length = self.headers.get("Content-Length", "")
                if not length.isdecimal() or int(length) <= 0:
                    self._refuse(411, "length-required")
                    return
                size = int(length)
                if size > MAX_WINDOW_BODY:
                    if self._credential() == "":
                        self._drain_body()
                        self._refuse(401, "credential-missing")
                        return
                    self._drain_body(limit=65536)
                    self._refuse(413, "body-too-large")
                    return
                raw = self._read_exact(size)
                if len(raw) != size:
                    relay.counters.bump("body-truncated")
                    self._refuse(503, "body-truncated", retry_after=2)
                    return
                status, body, headers = relay.handle_window(self._credential(), raw)
                self._send(status, body, headers)
                return
            if self.path != INSERT_PATH:
                self._drain_body()
                self._refuse(404, "not-a-route")
                return
            length = self.headers.get("Content-Length", "")
            if not length.isdecimal():
                self._refuse(411, "length-required")
                return
            size = int(length)
            if size <= 0 or size > MAX_ARCHIVE_BYTES:
                # The credential is checked first so an unauthorised caller cannot make the
                # relay buffer a large body; a request that is not a pass at all gets 401.
                if self._credential() == "":
                    self._drain_body()
                    self._refuse(401, "credential-missing")
                    return
                self._drain_body(limit=65536)
                self._refuse(413, "archive-too-large")
                return
            raw = self._read_exact(size)
            if len(raw) != size:
                # A short body is the *transport* (a Tor circuit closing mid-body), not a
                # malformed archive: the owner's bytes were well-formed and arrived cut off.
                # Refused here, BEFORE the pass is admitted or its window spent, so an owner
                # that re-POSTs the same pass on a fresh stream is not double-counted against
                # the window budget (drill 3). Retryable - a definitive 400 would tell
                # the owner its archive was bad when it was the circuit that broke.
                relay.counters.bump("body-truncated")
                self._refuse(503, "body-truncated", retry_after=2)
                return
            status, body, headers = relay.handle_insert(self._credential(), raw)
            self._send(status, body, headers)

        def _credential(self) -> str:
            return bearer(self.headers.get("Authorization"))

        def _read_exact(self, size: int) -> bytes:
            chunks: list[bytes] = []
            remaining = size
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 1 << 16))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)

        def _reject_method(self) -> None:
            self._drain_body()
            self._refuse(405, "method-not-allowed")

        # No HEAD that enumerates (ADR 0011 Decision 1). Every method but GET (and POST on
        # `/i`) is 405, including on `/b/{ref}`: the surface is one GET, one POST, nothing
        # beside them.
        do_HEAD = _reject_method
        do_PUT = _reject_method
        do_DELETE = _reject_method
        do_PATCH = _reject_method
        do_OPTIONS = _reject_method
        do_TRACE = _reject_method

    return Handler


def warm_pass(relay: Relay, refs: Sequence[str], *, limit: int = 64,
              target_seconds: float = 0.0, max_seconds: float = 0.0,
              timeout: float = 30.0) -> dict:
    """Read a sample of the publication's shares, so the node's first real window is warm.

    Measured on a fresh node 2026-11-12 (docs/measurements.md): the first pass over the
    S2 track lost 4 of 17 windows to share timeouts and the second answered 17/17, with
    window times falling 37 -> 12 s as the node filled. A cold node is not broken, it is
    paying a one-time cost - so the relay should pay it deliberately, before it accepts a
    window, rather than pass it to whichever client happens to ask first.

    `refs` is the sample to read; which refs is the operator's business (they are refs, so
    they name no track). The result is counts and durations only: how many answered, how many
    did not, how long each read took, and the total - the warm pass must not become a place a
    ref is logged. `read_seconds` is one float per ref read, in the order they were asked, and
    it carries no ref: it exists because a total cannot tell a uniform cost from a few reads
    eating a deadline, and those two want different knobs.

    **Where to stop.** Two ceilings and one early exit, and all three are needed:

    - `limit` is a count ceiling, and a count alone is not a bound: 32 refs cost 150.9 s on
      the measured cold node, so a pathologically slow one could hold the relay down for
      minutes.
    - `max_seconds > 0` is therefore the wall-clock ceiling, checked between blocks. A
      warming relay is not yet serving, so this number *is* the boot outage: the operator
      chooses it, and a relaunched relay cannot extend it by being slow.
    - `target_seconds > 0` is the stop-early point. A fixed sample count drifts as the
      library grows and as nodes differ - the measured cold Fred answered 29 of 32 and was
      still at the edge of what it would give - so the pass also stops once a block costs no
      more than the target, which is where the cold penalty has flattened (37 -> 12 s, then
      0.16-8 s warm). It is absolute on purpose: a relative rule (a fraction of the fastest
      block seen) measures load as much as warmth, and a loaded node would then stop early
      believing itself warm.
    """
    started = time.monotonic()
    asked = arrived = missed = 0
    errors = 0
    read_seconds: list[float] = []
    ceiling = max(0, int(limit))
    sample = list(refs)[:ceiling]
    # One read at a time, so a block's wall time is that read's warm-up and not queueing.
    granularity = 8
    for offset in range(0, len(sample), granularity):
        if max_seconds > 0 and (time.monotonic() - started) >= max_seconds:
            break
        block_started = time.monotonic()
        for ref in sample[offset:offset + granularity]:
            asked += 1
            read_started = time.monotonic()
            try:
                relay.substrate.read(ref, max_size=MAX_WIRE)
                arrived += 1
            except (SubstrateMiss, SubstrateTimeout):
                # A miss is an answer about this ref, not about the node: the ref is not on
                # this node's neighbourhood, and asking it again spends warm-up on the same
                # absence.
                missed += 1
            except Exception:  # noqa: BLE001 - a warming failure is counted, never raised
                errors += 1
            # Duration only, never the ref: this is what separates "every read cost 4 s"
            # from "three reads cost 50 s and the rest were instant", and the two want
            # different knobs (a sample size versus a per-read deadline).
            read_seconds.append(round(time.monotonic() - read_started, 3))
        if target_seconds > 0 and (time.monotonic() - block_started) <= target_seconds:
            break
    seconds = time.monotonic() - started
    relay.counters.bump("warm-pass")
    # `asked` is what the pass *spent*, not the size of the sample: a stop-early pass reads a
    # prefix, and reporting the ceiling as asked would make the operator's line claim work
    # that did not happen.
    return {"asked": asked, "arrived": arrived,
            "missed": missed, "errors": errors, "seconds": round(seconds, 2),
            "read_seconds": read_seconds}


def serve(relay: Relay, *, host: str = "127.0.0.1", port: int = 0,
          onion_host: str | None = None) -> _Server:
    handler = make_handler(relay, onion_host=onion_host)
    return _Server((host, port), handler, relay=relay, onion_host=onion_host)


def _issuer_public(key_hex: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex.strip()))
    except (ValueError, TypeError) as exc:
        raise SystemExit("--issuer-key must be 64 hex characters (a raw Ed25519 key)") from exc


def _load_seam(dotted: str):
    """Resolve a `module:function` insert seam, so the deployment wires its own derivation."""
    import importlib

    module_name, _, func_name = dotted.partition(":")
    if not module_name or not func_name:
        raise SystemExit("--insert-seam must be 'module:function'")
    try:
        module = importlib.import_module(module_name)
        return getattr(module, func_name)
    except (ImportError, AttributeError) as exc:
        raise SystemExit(f"--insert-seam could not be loaded: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ADR 0011 blind relay (GET /b/{ref})")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address; loopback only when an onion host is set")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--onion-host", default=os.environ.get("BLINDSTREAM_RELAY_ONION_HOST") or None,
                        help="this relay's v3 onion address; requests not carrying it are refused "
                             "(or the BLINDSTREAM_RELAY_ONION_HOST env var; an explicit flag wins)")
    parser.add_argument("--issuer-key", default=os.environ.get("BLINDSTREAM_RELAY_ISSUER_KEY", ""),
                        help="issuer Ed25519 public key, raw hex (or the env var)")
    parser.add_argument("--relay-id", default="*", help="relay id this daemon answers to")
    parser.add_argument("--fcp-port", type=int, default=0)
    parser.add_argument("--reader-host", default="127.0.0.1")
    parser.add_argument("--readers", type=int, default=8)
    parser.add_argument("--serve-timeout", type=float, default=3.0,
                        help="longest a serving substrate read may block before the relay "
                             "answers: a definite miss must be prompt, never a hang. A miss "
                             "that is still walking the network at this bound answers 503 "
                             "(retryable), not 404 - the substrate has not said the object is "
                             "absent, only that it did not answer in time. The old 60 s value "
                             "overshot a client's 20 s block deadline, so absence and a hang "
                             "were indistinguishable and the client retried forever. The "
                             "default is 3 s because the client's own relay bound (~6 s) also "
                             "pays the onion circuit (~2-3 s), so a read bound above ~3 s "
                             "cannot answer inside the client's budget either")
    parser.add_argument("--head-timeout", type=float, default=15.0,
                        help="R: how long one named-edition head read may run. Deliberately "
                             "longer than --serve-timeout: an absent edition is a search "
                             "(measured 2-10 s), and under the block bound the route could "
                             "never tell 'absent' from 'unavailable'.")
    parser.add_argument("--hold-seconds", type=float, default=None,
                        help="deprecated alias for --serve-timeout (an explicit value wins)")
    parser.add_argument("--cache-entries", type=int, default=512)
    parser.add_argument("--cache-ttl", type=float, default=600.0)
    parser.add_argument("--insert-seam", default=None,
                        help="'module:function' deriving {object_id: ref} for POST /i; without "
                             "one the relay refuses inserts (501) rather than faking one")
    parser.add_argument("--settle-floor", type=int, default=SettleGate.DEFAULT_FLOOR,
                        help="R1: how many substrate peers must be CONNECTED before a window "
                             "is served (default %d, the count a fresh node was measured to "
                             "reach at 243 s; a settled node holds 13-16)" %
                             SettleGate.DEFAULT_FLOOR)
    parser.add_argument("--settle-stability", type=float,
                        default=SettleGate.DEFAULT_STABILITY_S,
                        help="R1: how long that floor must hold without dipping before the "
                             "relay serves (default %.0fs; the measured cold curve fell back "
                             "to 0 twice after reaching 3 and 4)" %
                             SettleGate.DEFAULT_STABILITY_S)
    parser.add_argument("--settle-poll", type=float, default=5.0,
                        help="R1/D6: seconds between peer censuses, while warming and after "
                             "a settle (default 5)")
    parser.add_argument("--settle-demote-after", type=float,
                        default=SettleGate.DEFAULT_DEMOTE_AFTER_S,
                        help="D6: how long a settled relay's census may sit below the floor "
                             "before it answers 503 relay-warming again (default %.0fs)" %
                             SettleGate.DEFAULT_DEMOTE_AFTER_S)
    parser.add_argument("--require-role-passes", action="store_true",
                        help="plan2 section 5: /h/ and the index pages need a `discovery` pass, "
                             "/w needs a `playback` pass, and a `fetch` pass opens neither "
                             "(default off: the deployed client still presents `fetch`)")
    parser.add_argument("--no-settle-gate", action="store_true",
                        help="do not gate admission on the peer census (a test host, or a "
                             "deployment whose substrate reports no peers)")
    parser.add_argument("--windows", action="store_true",
                        help="serve POST /w (the fast-retrieval window route); needs the "
                             "read half")
    parser.add_argument("--window-readers", type=int, default=0,
                        help="how many shares one window may have in flight; 0 (the default) "
                             "derives half the pool, which is the ratio measured green. Must "
                             "be strictly less than --readers or the relay refuses to start")
    parser.add_argument("--warm-refs", default=None,
                        help="a file of refs (one per line, no other field) the relay reads "
                             "once at start to warm its node before serving a window; with "
                             "--windows and no warm pass, every window is refused "
                             "503 relay-warming until one has completed")
    parser.add_argument("--warm-limit", type=int, default=64,
                        help="the most refs of --warm-refs one warm pass reads (default 64)")
    parser.add_argument("--warm-target", type=float, default=0.0,
                        help="stop the warm pass once a block of reads takes no longer than "
                             "this many seconds, which is the flattening point; 0 pays the "
                             "whole --warm-limit sample")
    parser.add_argument("--warm-max-seconds", type=float, default=0.0,
                        help="wall-clock ceiling on the warm pass, checked between blocks "
                             "(default 0 = no time ceiling). This is the boot outage: while "
                             "warming the relay is not serving, and --warm-limit alone lets a "
                             "slow node hold it down for minutes")
    parser.add_argument("--insert-only", action="store_true",
                        help="write-only relay: refuse GET /b/{ref} and build no read substrate "
                             "(the write host must not be a read host)")
    args = parser.parse_args(argv)

    if not args.issuer_key:
        raise SystemExit("--issuer-key (or BLINDSTREAM_RELAY_ISSUER_KEY) is required")
    if args.onion_host and args.host not in ("127.0.0.1", "::1", "localhost"):
        # An onion service forwards to loopback. A relay that also binds a routable address
        # has a clearnet path, which ADR 0011 Decision 4.4 forbids. Fail closed at start.
        raise SystemExit("an onion relay must bind loopback only (--host 127.0.0.1)")
    if args.insert_only and not args.insert_seam:
        # A write-only relay with no write seam would serve neither half: refuse at start
        # rather than run a daemon that answers nothing but refusals.
        raise SystemExit("--insert-only requires --insert-seam")
    # A fan-out the pool cannot survive is refused at start. The default derives half the
    # pool rather than a fixed count, so a relay configured with a small --readers does not
    # have to name the window fan-out too and cannot inherit an impossible one.
    args.window_readers = window_fan_out(args.readers, args.window_readers)
    if args.windows and not args.insert_only:
        problem = check_window_pool(args.readers, args.window_readers)
        if problem is not None:
            # A pool smaller than one window's fan-out is a wedged window, not a substrate
            # fault. Fail closed at start and name both numbers, so the failure is never
            # blamed on the node three windows into a play.
            raise SystemExit(problem)

    gate = DoorGate(_issuer_public(args.issuer_key), relay_id=args.relay_id)
    read_enabled = not args.insert_only
    # An explicit --hold-seconds wins (compatibility); otherwise --serve-timeout, whose
    # default bounds a miss to low single-digit seconds.
    serve_timeout = args.hold_seconds if args.hold_seconds is not None else args.serve_timeout
    substrate = None
    if read_enabled:
        substrate = ReadPool(fcp_port=args.fcp_port, host=args.reader_host, size=args.readers,
                             timeout=serve_timeout,
                             # The head's own bound, and it must not inherit the block's: a
                             # block miss is answered in low single-digit seconds while an
                             # absent *edition* is a search that measured 2-10 s, so a head
                             # read under the block bound would always report "unavailable"
                             # and never "absent". `--head-timeout` raises it explicitly.
                             head_timeout=args.head_timeout)
    insert = None
    if args.insert_seam:
        insert = WritePool(fcp_port=args.fcp_port, host=args.reader_host, size=4,
                           seam=_load_seam(args.insert_seam))
        # The write half is only as good as the runtime under it. The substrate's own
        # derivation, asked derive-only (nothing stored), must return the pinned handle for
        # one fixed block: a staged runtime that framed an insert differently would publish
        # one plaintext under two handles (measured 2026-10-18 - a stale `content_type`
        # default moved a block's handle `AAMA--8` -> `AAMC--8`). Fail closed at start rather
        # than serve writes under a handle the owner will reject.
        try:
            derived_ok = insert.self_check()
        except SubstrateError:
            raise SystemExit(
                "--insert-seam self-check could not derive from the substrate")
        if not derived_ok:
            raise SystemExit(
                "--insert-seam self-check failed: the staged runtime derives a different "
                "handle than the pinned one")
    faults = Faults.from_env()
    # A faulted relay is a deployment fact the operator must be able to read back, so the
    # switches ride on the same single startup line rather than a second one (the no-log
    # rule allows exactly one print).
    fault_note = ""
    if faults.active():
        fault_note = ", faults: " + " ".join(
            name for name, on in (("drop=%d%%" % faults.drop_pct, bool(faults.drop_pct)),
                                  ("delay=%.1fs" % faults.delay_s, bool(faults.delay_s)),
                                  ("blackhole", faults.blackhole),
                                  ("corrupt", faults.corrupt),
                                  ("truncate", faults.truncate)) if on)
    relay = Relay(gate=gate, cache=RefCache(max_entries=args.cache_entries,
                                            ttl_seconds=args.cache_ttl),
                  substrate=substrate, insert=insert, hold_seconds=serve_timeout,
                  read_enabled=read_enabled, faults=faults,
                  require_role_passes=args.require_role_passes)
    if read_enabled and args.windows:
        # One held pool: a window is a read, and a second pool to the same node would
        # only double the handshakes. `warm_required` with a warm-refs file makes warmth
        # part of readiness; a launch with no warm sample to read has nothing to pay and
        # is ready from start.
        relay.window_reader = WindowReader(substrate._pool, concurrency=args.window_readers,
                                           counters=relay.counters,
                                           warm_required=bool(args.warm_refs))
        if not args.no_settle_gate:
            # R1: admission by the peer census, before warmth. A fresh Fred answers FCP with
            # no connected peer at all, and a window pass begun there loses most of its
            # windows - so the relay must not serve until the count has held.
            relay.settle = SettleGate(substrate, floor=args.settle_floor,
                                      stability_s=args.settle_stability,
                                      poll_s=args.settle_poll,
                                      demote_after_s=args.settle_demote_after)
    warm_note = ""
    if read_enabled and args.windows and args.warm_refs:
        # Warm before accepting a window: the cost is paid here, once, instead of by the
        # first client that happens to ask. The sample is read outside this module (the
        # no-log rule allows no file read in here), and a sample that cannot be read is a
        # start-time error rather than a silently-cold relay.
        from blind_warm import run as run_warm, summary_line

        try:
            outcome = run_warm(relay, args.warm_refs, limit=args.warm_limit,
                               target_seconds=args.warm_target,
                               max_seconds=args.warm_max_seconds)
        except (OSError, ValueError) as exc:
            raise SystemExit("--warm-refs could not be used: %s" % exc) from exc
        relay.warm = True
        warm_note = ", " + summary_line(outcome)
    elif read_enabled and args.windows:
        # Nothing to warm from means nothing to pay: a launch with no warm sample is one
        # where the node is assumed warm by the operator (a test, or a dev host).
        relay.warm = True
    server = serve(relay, host=args.host, port=args.port, onion_host=args.onion_host)
    where = args.onion_host or f"{args.host}:{server.server_address[1]}"
    # Startup is the one line this daemon prints, and it is the operator's, not a request
    # log: it names the bind and nothing that arrived. It goes to stdout, deliberately not
    # stderr - the no-log rule treats *touching* stderr as a violation, because stderr is
    # where a traceback or a diagnostic would carry a ref. The request path prints nothing
    # at all; `tests/test_blind_relay_nologs.py` proves it against the AST and at runtime.
    print(f"blind relay listening on {where} (loopback {server.server_address[0]}:"
          f"{server.server_address[1]}{warm_note}{fault_note})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if substrate is not None:
            substrate.close()
        if insert is not None:
            insert.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
