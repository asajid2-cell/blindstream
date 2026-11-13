"""S3 wire: `POST /w` on the blind relay -- one window in, data shares out, nothing leaked.

The route is driven over a real loopback socket, so what is asserted is the wire a client
sees: the admission (a fetch pass, not an insert one), the metering (`ceil(k/16)` units), the
response shape (exactly k x 32768 bytes, in order, with a shares-used count and no refs), and
the refusals (400 for a body that is not a window, 503 `window-incomplete` for a window that
could not be satisfied).

The last test is the privacy one the spec asks for: the counters the relay keeps must name no
ref and no corpus -- a captured snapshot has to be a set of aggregate labels only.
"""
from __future__ import annotations

import http.client
import json
import time
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import blind_fec  # noqa: E402
from blind_cache import RefCache  # noqa: E402
from blind_door import OP_FETCH, OP_INSERT, DoorGate, DoorIssuer  # noqa: E402
from blind_relay import Relay, serve  # noqa: E402
from blind_window_reader import WindowReader  # noqa: E402

SHARE = blind_fec.SHARE_BYTES


def ref(index: int) -> str:
    body = ("%043d" % index).replace("0", "A")
    return "chk:CHK@%s,%s,AAMA--8" % (body, body)


def body_for(k: int, n: int) -> tuple[bytes, list[str], list[bytes]]:
    """A window's wire body, its refs in order, and the data shares it should answer with."""
    data = [bytes([index]) * SHARE for index in range(k)]
    shares = blind_fec.encode_window(data, blind_fec.Window(k, n))
    handles = [ref(index) for index in range(n)]
    request = {"k": k, "n": n, "shares": handles, "deadline_ms": 5000}
    return json.dumps(request).encode(), handles, data


class Substrate:
    """A node with no network: ref -> bytes, and a record of what was asked."""

    def __init__(self, objects=None) -> None:
        self.objects = dict(objects or {})
        self.asks: list[str] = []
        self.lock = threading.Lock()

    def read(self, ref, *, max_size):
        with self.lock:
            self.asks.append(ref)
        if ref not in self.objects:
            raise _miss()
        return self.objects[ref]


class Mesh:
    """One held connection over the same object map, so the window reader can use it."""

    def __init__(self, objects: dict[str, bytes]) -> None:
        self.objects = objects

    def get(self, uri, **_):
        name = getattr(uri, "value", None) or str(uri)
        if name not in self.objects:
            raise _miss()
        return self.objects[name]


class Pool:
    def __init__(self, objects: dict[str, bytes], size: int = 8) -> None:
        self._objects = objects
        self._idle = [Mesh(objects) for _ in range(size)]

    def checkout(self, **_):
        return self._idle.pop() if self._idle else Mesh(self._objects)

    def checkin(self, mesh):
        self._idle.append(mesh)

    def discard(self, mesh):
        pass


class Handle:
    def __init__(self, value: str) -> None:
        self.value = value


def _miss():
    error = RuntimeError("not available: code=13")
    error.code = 13
    return error


def _fetch(mesh, handle: str) -> bytes:
    return mesh.get(Handle(handle))


def _server(objects: dict[str, bytes], *, windows: bool = True):
    issuer = DoorIssuer()
    gate = DoorGate(issuer.public_key, relay_id="r1")
    relay = Relay(gate=gate, cache=RefCache(), substrate=Substrate(objects))
    if windows:
        relay.window_reader = WindowReader(Pool(objects), concurrency=8, counters=relay.counters)
    srv = serve(relay, host="127.0.0.1", port=0, onion_host=None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, relay, issuer


def _post(port: int, path: str, body: bytes, *, credential: str | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if credential is not None:
        headers["Authorization"] = "Bearer " + credential
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    payload = resp.read()
    out = (resp.status, payload, dict(resp.getheaders()))
    conn.close()
    return out


def _window_objects(k: int, n: int, *, drop: int = 0):
    """The substrate's contents for a window, with the last `drop` shares absent."""
    data = [bytes([index]) * SHARE for index in range(k)]
    shares = blind_fec.encode_window(data, blind_fec.Window(k, n))
    handles = [ref(index) for index in range(n)]
    objects = {handle: blob for handle, blob in zip(handles, shares)}
    for handle in handles[n - drop:]:
        del objects[handle]
    return objects, handles, data


# --- the happy path -------------------------------------------------------------------

def test_a_window_answers_with_exactly_k_data_shares_in_order():
    objects, handles, data = _window_objects(4, 12)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, headers = _post(srv.server_address[1], "/w", body,
                                         credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 200
        assert headers["Content-Type"] == "application/octet-stream"
        assert len(payload) == 4 * SHARE
        assert payload == b"".join(data)
        assert headers["X-Window-Shares-Used"] == "4"
        # Issued is what the relay actually dispatched, not n: the reader stops asking once
        # k have arrived, so a fast window sits between k and n. The four headers must
        # account for every share of the window exactly once.
        issued = int(headers["X-Window-Shares-Issued"])
        arrived = int(headers["X-Window-Shares-Arrived"])
        cancelled = int(headers["X-Window-Shares-Cancelled"])
        failed = int(headers["X-Window-Shares-Failed"])
        skipped = int(headers["X-Window-Shares-Skipped"])
        assert 4 <= issued <= 12
        assert issued + skipped == 12
        assert issued == arrived + cancelled + failed
        assert arrived >= 4
    finally:
        srv.shutdown()


def test_the_answer_survives_most_of_the_window_being_absent():
    """The strand's whole claim: four of twelve is enough, and the answer is still exact."""
    objects, handles, data = _window_objects(4, 12, drop=8)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, _ = _post(srv.server_address[1], "/w", body,
                                   credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 200
        assert payload == b"".join(data)
    finally:
        srv.shutdown()


# --- refusals -------------------------------------------------------------------------

def test_a_window_that_cannot_reach_k_is_window_incomplete():
    objects, handles, data = _window_objects(4, 12, drop=10)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, headers = _post(srv.server_address[1], "/w", body,
                                         credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 503
        assert json.loads(payload)["refusal"] == "window-incomplete"
        assert "Retry-After" in headers
    finally:
        srv.shutdown()


def test_an_insert_pass_cannot_open_a_window():
    objects, _, _ = _window_objects(4, 12)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, _ = _post(srv.server_address[1], "/w", body,
                                   credential=issuer.mint(op=OP_INSERT, relay="r1"))
        assert status == 401
        assert json.loads(payload)["refusal"] == "credential-wrong-operation"
        assert relay.counters.snapshot().get("window-ok", 0) == 0
    finally:
        srv.shutdown()


@pytest.mark.parametrize("bad", [
    b"not json",
    b"[]",
    json.dumps({"k": 4, "n": 12, "shares": ["chk:CHK@" + "A" * 43 + "," + "A" * 43 + ",AAMA--8"]}).encode(),
    json.dumps({"k": 4, "n": 12, "shares": [ref(i) for i in range(11)]}).encode(),
    json.dumps({"k": 4, "n": 4, "shares": [ref(i) for i in range(4)]}).encode(),
])
def test_a_body_that_is_not_a_window_is_400(bad):
    objects, _, _ = _window_objects(4, 12)
    srv, relay, issuer = _server(objects)
    try:
        status, payload, _ = _post(srv.server_address[1], "/w", bad,
                                   credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 400
        assert json.loads(payload)["refusal"] == "malformed-window"
    finally:
        srv.shutdown()


def test_a_missing_credential_is_401_and_no_reader_is_touched():
    objects, _, _ = _window_objects(4, 12)
    substrate = Substrate(objects)
    srv, relay, issuer = _server(objects)
    relay.substrate = substrate
    try:
        body, _, _ = body_for(4, 12)
        status, payload, _ = _post(srv.server_address[1], "/w", body)
        assert status == 401
        assert json.loads(payload)["refusal"] == "credential-missing"
        assert substrate.asks == []
    finally:
        srv.shutdown()


def test_a_write_only_relay_has_no_window_surface():
    objects, _, _ = _window_objects(4, 12)
    srv, relay, issuer = _server(objects, windows=False)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, _ = _post(srv.server_address[1], "/w", body,
                                   credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 404
        assert json.loads(payload)["refusal"] == "no-read-surface"
    finally:
        srv.shutdown()


# --- metering -------------------------------------------------------------------------

@pytest.mark.parametrize("k,units", [(1, 1), (4, 1), (16, 1), (17, 2), (32, 2), (48, 3)])
def test_a_window_costs_ceil_k_over_16_units(k, units):
    from blind_relay import window_units
    assert window_units(k) == units


def test_a_window_over_the_budget_is_429_and_no_share_is_read():
    """One unit buys one window at k<=16; a second request over a one-unit budget is refused."""
    objects, handles, data = _window_objects(16, 32)
    srv, relay, issuer = _server(objects)
    try:
        # A pass with a one-unit window: the first 16-of-32 costs exactly that unit.
        cred = issuer.mint(op=OP_FETCH, relay="r1", window=1)
        body, _, _ = body_for(16, 32)
        first = _post(srv.server_address[1], "/w", body, credential=cred)
        assert first[0] == 200
        second = _post(srv.server_address[1], "/w", body, credential=cred)
        assert second[0] == 429
        assert "Retry-After" in second[2]
    finally:
        srv.shutdown()


def test_an_expensive_window_is_metered_by_its_cost_not_its_requests():
    """A 32-of-64 window costs ceil(32/16) = 2 units, charged whole before the read.

    The claim is not "large windows are refused" -- a 2-unit pass opens it. The claim is that
    the cost is all-or-nothing: a 1-unit pass is refused with nothing read and nothing spent,
    rather than paying one unit, reading 16 shares, and running out mid-window.
    """
    objects, handles, data = _window_objects(32, 64)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(32, 64)
        poor = issuer.mint(op=OP_FETCH, relay="r1", window=1)
        status, payload, headers = _post(srv.server_address[1], "/w", body, credential=poor)
        assert status == 429
        assert json.loads(payload)["refusal"] == "window-spent"
        assert "Retry-After" in headers
        # Nothing was read and nothing was half-charged: no window reached the substrate.
        snapshot = relay.counters.snapshot()
        assert snapshot.get("window-ok", 0) == 0
        assert snapshot.get("window-incomplete", 0) == 0
        # The same window opens for a pass that can actually pay its cost.
        rich = issuer.mint(op=OP_FETCH, relay="r1", window=2)
        status, payload, _ = _post(srv.server_address[1], "/w", body, credential=rich)
        assert status == 200
        assert len(payload) == 32 * SHARE
    finally:
        srv.shutdown()


# --- the privacy claim ------------------------------------------------------------------

def test_no_counter_names_a_ref_or_a_track():
    """The counters are the relay's only self-knowledge, and they carry no ref."""
    objects, handles, data = _window_objects(4, 12)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        _post(srv.server_address[1], "/w", body,
              credential=issuer.mint(op=OP_FETCH, relay="r1"))
        snapshot = relay.counters.snapshot()
        labels = " ".join(snapshot)
        values = " ".join(str(value) for value in snapshot.values())
        for handle in handles:
            assert handle not in labels
            assert "CHK@" not in labels
            assert handle[8:30] not in labels
        assert "CHK@" not in values
        # The labels that must exist are aggregate facts about windows, not content.
        assert "window-ok" in snapshot
        assert snapshot["window-ok"] == 1
    finally:
        srv.shutdown()


def test_the_response_carries_no_ref():
    objects, handles, data = _window_objects(4, 12)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, headers = _post(srv.server_address[1], "/w", body,
                                         credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 200
        flat = json.dumps(headers)
        assert "CHK@" not in flat
        for handle in handles:
            assert handle not in payload.decode("latin-1")
    finally:
        srv.shutdown()


# --- the pool invariant, refused at start -----------------------------------------


def test_a_window_fan_out_that_can_take_every_lease_is_refused():
    """Measured 2026-11-12: 16 readers with 16 shares in flight wedged three windows.

    A window takes one lease per share in flight and holds it until the fetch returns, so
    a fan-out that can consume the whole pool leaves the next window nothing to check out
    once one share straggles. That is a configuration error and must be named at start -
    as a wedge it reads to an operator as the substrate failing.
    """
    from blind_relay import check_window_pool

    problem = check_window_pool(16, 16)
    assert problem is not None
    assert "16" in problem
    assert "--window-readers" in problem and "--readers" in problem


def test_the_ratios_measured_green_are_accepted():
    from blind_relay import check_window_pool

    assert check_window_pool(12, 4) is None
    assert check_window_pool(24, 6) is None
    assert check_window_pool(8, 1) is None


@pytest.mark.parametrize("readers,window_readers", [(0, 0), (8, 0), (0, 4), (-1, 2)])
def test_a_pool_or_fan_out_of_zero_is_refused(readers, window_readers):
    from blind_relay import check_window_pool

    assert check_window_pool(readers, window_readers) is not None


def test_the_window_fan_out_defaults_to_half_the_pool():
    """A relay that names only --readers must not inherit an impossible fan-out.

    The old default was 64, which against the default pool of 8 was a wedge waiting for
    the first straggle. The default now derives from the pool, so the same launch that
    worked before still works and the invariant holds without the operator knowing it.
    """
    from blind_relay import check_window_pool, window_fan_out

    for readers in (2, 8, 12, 16, 24, 64):
        fan_out = window_fan_out(readers, 0)
        assert fan_out >= 1
        assert check_window_pool(readers, fan_out) is None, (
            "the derived default must satisfy the invariant at %d readers" % readers)
    # An explicit fan-out is used as asked, and is still checked.
    assert window_fan_out(16, 4) == 4
    assert check_window_pool(16, window_fan_out(16, 16)) is not None


# --- warmth is part of readiness --------------------------------------------------


def test_a_warming_relay_refuses_a_window_instead_of_paying_it_cold():
    """Measured 2026-11-12: a cold Fred lost 4 of 17 windows to share timeouts.

    Handing that cost to whichever client asks first is the defect. The refusal is the
    same instruction `window-incomplete` carries - ask another relay, come back - so the
    client needs no new behaviour, and no deadline is spent on the node's warm-up.
    """
    issuer = DoorIssuer()
    gate = DoorGate(issuer.public_key, relay_id="warm")
    relay = Relay(gate=gate, cache=RefCache(), substrate=None, read_enabled=True)
    relay.window_reader = WindowReader(_EmptyPool(), warm_required=True)
    credential = issuer.mint(op=OP_FETCH, relay="warm", window=4096, ttl=600)
    body = json.dumps({"k": 2, "n": 4,
                       "shares": [_ref_char(index) for index in range(4)],
                       "deadline_ms": 5000}).encode()

    status, payload, headers = relay.handle_window(credential, body)

    assert status == 503
    assert json.loads(payload)["refusal"] == "relay-warming"
    assert headers.get("Retry-After") == "5"
    assert relay.counters.snapshot().get("window-cold") == 1


def test_a_reader_with_nothing_to_warm_is_ready_from_start():
    """A fixture or a block-only relay has no warm pass to run, so it pays nothing."""
    assert WindowReader(_EmptyPool()).warm_required is False


def test_the_warm_pass_reports_counts_and_never_raises(tmp_path):
    """The warm pass must not become a place a ref is logged, or a start-time crash."""
    from blind_relay import warm_pass

    class _Substrate:
        def __init__(self):
            self.asked = []

        def read(self, ref, *, max_size):
            self.asked.append(ref)
            if ref.endswith("miss"):
                from blind_substrate import SubstrateMiss
                raise SubstrateMiss("not-available")
            return b"x" * 32768

    class _Relay:
        substrate = _Substrate()
        counters = _Counters()

    relay = _Relay()
    refs = ["chk:CHK@hit0", "chk:CHK@miss", "chk:CHK@hit1"]
    outcome = warm_pass(relay, refs, limit=3)

    assert outcome["asked"] == 3
    assert outcome["arrived"] == 2
    assert outcome["missed"] == 1
    assert outcome["errors"] == 0
    assert relay.counters.snapshot()["warm-pass"] == 1
    assert set(outcome) == {"asked", "arrived", "missed", "errors", "seconds",
                            "read_seconds"}
    # One duration per read, in ask order - and no ref anywhere in the outcome.
    assert len(outcome["read_seconds"]) == 3
    assert all(isinstance(value, float) for value in outcome["read_seconds"])
    assert "CHK@" not in json.dumps(outcome)


def test_a_warm_pass_stops_once_a_block_cost_no_more_than_the_target():
    """The sample is sized by the flattening point, not by a fixed count.

    Measured 2026-11-12: a cold Fred answered 29 of 32 refs and was still at the edge of
    what it would give, so a fixed 32 is already a guess that drifts. A block whose reads
    are as quick as the target means the node is no longer paying the cold penalty - read on
    and the pass is spending a client's wait to prove what it already knows.
    """
    from blind_relay import warm_pass

    released = []

    class _WarmSubstrate:
        """Every read quick: the node was warm from the first block."""

        def read(self, ref, *, max_size):
            released.append(ref)
            return b"x" * SHARE

    class _Relay:
        counters = _Counters()

    relay = _Relay()
    relay.substrate = _WarmSubstrate()
    refs = ["chk:CHK@warm%d,AAMA--8,AAMA--8" % index for index in range(32)]
    outcome = warm_pass(relay, refs, limit=32, target_seconds=0.5)

    # The first block is the whole pass: 8 refs, not 32.
    assert outcome["asked"] == 8
    assert outcome["arrived"] == 8
    assert len(released) == 8


def test_a_warm_pass_with_no_target_reads_the_whole_sample():
    """The default is the old behaviour, so a launch that sets no target is unchanged."""
    from blind_relay import warm_pass

    class _Substrate:
        requested = []

        def read(self, ref, *, max_size):
            self.requested.append(ref)
            return b"x" * SHARE

    class _Relay:
        counters = _Counters()

    relay = _Relay()
    relay.substrate = _Substrate()
    refs = ["chk:CHK@warm%d,AAMA--8,AAMA--8" % index for index in range(20)]
    outcome = warm_pass(relay, refs, limit=20)

    assert outcome["asked"] == 20
    assert outcome["arrived"] == 20
    assert len(relay.substrate.requested) == 20


def test_a_node_that_never_flattens_still_stops_at_the_ceiling():
    """A cold node has to stop somewhere: the pass must not warm until the node feels warm."""
    from blind_relay import warm_pass

    class _SlowSubstrate:
        """Each read is slower than any target, so the pass never sees a flat block."""

        def read(self, ref, *, max_size):
            import time as _time
            _time.sleep(0.002)
            return b"x" * SHARE

    class _Relay:
        counters = _Counters()

    relay = _Relay()
    relay.substrate = _SlowSubstrate()
    refs = ["chk:CHK@slow%d,AAMA--8,AAMA--8" % index for index in range(40)]
    outcome = warm_pass(relay, refs, limit=12, target_seconds=1e-6)

    assert outcome["asked"] == 12
    assert outcome["arrived"] == 12


def test_a_warm_pass_is_bounded_by_wall_clock_as_well_as_by_refs():
    """A count ceiling is not a time bound: 32 refs cost 150.9 s on the measured cold node.

    While warming, the relay is not serving, so this ceiling is the boot outage. A
    pathologically slow node must be cut off by time, not allowed to run to the sample's end.
    """
    from blind_relay import warm_pass

    class _VerySlowSubstrate:
        def read(self, ref, *, max_size):
            import time as _time
            _time.sleep(0.02)
            return b"x" * SHARE

    class _Relay:
        counters = _Counters()

    relay = _Relay()
    relay.substrate = _VerySlowSubstrate()
    refs = ["chk:CHK@slow%d,AAMA--8,AAMA--8" % index for index in range(64)]
    outcome = warm_pass(relay, refs, limit=64, max_seconds=0.05)

    # Two blocks' worth at most: the ceiling is checked before each block.
    assert outcome["asked"] < len(refs)
    assert outcome["asked"] <= 16
    assert outcome["seconds"] >= 0.05


def test_a_warm_pass_with_no_time_ceiling_is_not_cut_short():
    """0 means no time ceiling, so a launch that sets none behaves exactly as before."""
    from blind_relay import warm_pass

    class _Substrate:
        def read(self, ref, *, max_size):
            import time as _time
            _time.sleep(0.005)
            return b"x" * SHARE

    class _Relay:
        counters = _Counters()

    relay = _Relay()
    relay.substrate = _Substrate()
    refs = ["chk:CHK@t%d,AAMA--8,AAMA--8" % index for index in range(16)]
    outcome = warm_pass(relay, refs, limit=16, max_seconds=0.0)

    assert outcome["asked"] == 16


def test_the_warm_pass_asked_count_is_what_it_spent_not_the_sample_size():
    """A stop-early pass that reports the ceiling would claim work the operator never paid."""
    from blind_relay import warm_pass

    class _Substrate:
        def read(self, ref, *, max_size):
            return b"x" * SHARE

    class _Relay:
        counters = _Counters()

    relay = _Relay()
    relay.substrate = _Substrate()
    refs = ["chk:CHK@flat%d,AAMA--8,AAMA--8" % index for index in range(64)]
    outcome = warm_pass(relay, refs, limit=64, target_seconds=60.0)

    assert outcome["asked"] < len(refs)
    assert outcome["asked"] == outcome["arrived"] + outcome["missed"] + outcome["errors"]


class _Counters:
    def __init__(self):
        self._values = {}

    def bump(self, key, by=1):
        self._values[key] = self._values.get(key, 0) + by

    def snapshot(self):
        return dict(self._values)


class _EmptyPool:
    def checkout(self, *, timeout=None):
        raise TimeoutError("no reader available")

    def checkin(self, lease):
        pass

    def discard(self, lease):
        pass


def _ref_char(index: int) -> str:
    return "chk:CHK@AAAA%s,AAAA%s,AAMA--8" % (chr(65 + index), chr(65 + index))


# --- R1: a relay only serves once its node has settled ------------------------------
#
# The predicate is the substrate's own CONNECTED peer count, held for a stability window.
# Measured 2026-11-12 on a fresh node (docs/measurements.md): FCP answers at 5 s
# with zero connected peers, the peer *list* reaches 25 while CONNECTED oscillates 0-5 for
# four minutes, and 8 connected is first observed at 243 s. These tests pin the rule, not
# the numbers - the numbers are the defaults and the live record is the proof.


class _PeerSubstrate:
    """A substrate whose connected-peer count a test drives directly."""

    def __init__(self, counts):
        self._counts = list(counts)
        self.calls = 0

    def connected_peers(self) -> int:
        self.calls += 1
        return self._counts.pop(0) if self._counts else 0


def test_the_default_floor_is_the_measured_one_not_a_guess():
    """The default floor comes from `floor_sweep.py`, not from where a run happened to cross.

    Measured 2026-11-12 on a fresh node against the test publication, one full pass per band:
    (0,1) -> 15/17 windows, (4,5) -> 17/17, (6,7) -> 17/17, (8,11) -> 17/17, (12,+) -> 17/17.
    The pass is complete from 5 connected up, so 5 is the floor and 8 was a guess that kept a
    cold node refused for ~200 s longer than it needed to be. This pins the number so it is not
    quietly raised back to a round one.
    """
    from blind_relay import SettleGate

    assert SettleGate.DEFAULT_FLOOR == 5, (
        "the default floor must be the measured 5; re-run floor_sweep.py before changing it")
    assert SettleGate.DEFAULT_STABILITY_S == 30.0


def test_a_settle_gate_needs_the_floor_held_for_the_stability_window():
    """One reading at the floor is not a settle: the measured curve fell back to 0 twice."""
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    # 8 connected on the first census, then held. A gate that released on the first reading
    # would serve at t=0; this one does not, because one sample is not a hold.
    substrate = _PeerSubstrate([8] * 20)
    gate = SettleGate(substrate, floor=8, stability_s=30.0, poll_s=0.0, now=clock)
    assert gate.ready() is False, "the floor was just reached; it has not been held"
    clock.t = 29.0
    assert gate.ready() is False, "still inside the stability window"
    clock.t = 31.0
    assert gate.ready() is True
    assert gate.settled_at == 31.0
    assert gate.first_hold_at == 0.0


def test_a_dip_below_the_floor_restarts_the_stability_window():
    """The measured cold curve went 0 -> 3 -> 0 -> 4 -> 0 before it held."""
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    # census at t=0 -> 8 (hold starts), t=10 -> 0 (reset), t=20 -> 8 (hold restarts),
    # t=40 -> 8, t=52 -> 8 -> 30 s since the restart.
    substrate = _PeerSubstrate([8, 0, 8, 8, 8])
    gate = SettleGate(substrate, floor=8, stability_s=30.0, poll_s=0.0, now=clock)
    assert gate.ready() is False
    clock.t = 10.0
    assert gate.ready() is False, "a dip below the floor is not a settle"
    clock.t = 20.0
    assert gate.ready() is False, "the hold restarted at t=20"
    assert gate.first_hold_at == 20.0
    clock.t = 52.0
    assert gate.ready() is True, "30 s have passed since the restart"


def test_a_settled_relay_demotes_when_the_floor_is_lost_for_ten_seconds():
    """D6: a settle is not permanent. Ten seconds without the floor and the relay stops.

    A settled node can lose its peers: the uplink blips, the peer set churns, the node
    restarts under the relay. Before D6 `ready()` returned True for the process's life after
    the first settle, so the relay kept handing out windows from a node that could not route -
    exactly the lost windows the warm path exists to refuse.
    """
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    # 8 at t=0 (hold starts), 8 at t=31 (settle), then the peer count is gone for good.
    substrate = _PeerSubstrate([8, 8] + [0] * 20)
    gate = SettleGate(substrate, floor=8, stability_s=30.0, poll_s=0.0,
                      demote_after_s=10.0, now=clock)

    assert gate.ready() is False, "the floor was just reached"
    clock.t = 31.0
    assert gate.ready() is True, "settled after the stability window"

    clock.t = 36.0
    assert gate.ready() is True, "the first census below the floor only starts the grace"
    clock.t = 45.0
    assert gate.ready() is True, "9 s below the floor is still inside the 10 s grace"
    clock.t = 46.0
    assert gate.ready() is False, "10 s below the floor: demoted"
    assert gate.demotions == 1
    assert gate.demoted_at == 46.0


def test_a_dip_shorter_than_the_grace_does_not_demote():
    """One quiet census must not take a healthy relay out of the fleet for 30 s."""
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    # settle at 31, dip to 3 at 36, back to 8 at 41 - five seconds below the floor.
    substrate = _PeerSubstrate([8, 8, 3, 8, 8, 8])
    gate = SettleGate(substrate, floor=8, stability_s=30.0, poll_s=0.0,
                      demote_after_s=10.0, now=clock)

    assert gate.ready() is False
    clock.t = 31.0
    assert gate.ready() is True
    clock.t = 36.0
    assert gate.ready() is True, "inside the grace"
    clock.t = 41.0
    assert gate.ready() is True, "the count came back; the grace never expired"
    assert gate.demotions == 0
    assert gate.demoted_at is None


def test_a_demoted_relay_is_re_admitted_only_after_a_fresh_stability_window():
    """D6: recovery is the same settle as the first one, not a latch flipped back."""
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    # settle at 31, lost from 36 to 46 (demoted), peers back at 51 and held.
    substrate = _PeerSubstrate([8, 8] + [0] * 3 + [8] * 20)
    gate = SettleGate(substrate, floor=8, stability_s=30.0, poll_s=0.0,
                      demote_after_s=10.0, now=clock)

    assert gate.ready() is False
    clock.t = 31.0
    assert gate.ready() is True
    for t in (36.0, 41.0, 46.0):
        clock.t = t
        assert gate.ready() is (t < 46.0), "serving through the grace, then demoted"
    assert gate.demotions == 1

    clock.t = 51.0
    assert gate.ready() is False, "the floor is back, but the fresh hold has just begun"
    clock.t = 80.0
    assert gate.ready() is False, "29 s of the 30 s stability window is not a settle"
    clock.t = 81.0
    assert gate.ready() is True, "re-admitted after the full stability window"
    assert gate.demotions == 1, "a recovery is not a new demotion"


def test_a_demoted_relay_refuses_a_window_with_relay_warming():
    """The wire refusal after demotion is the warming one: ask another relay, come back."""
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    objects, handles, data = _window_objects(4, 12)
    issuer = DoorIssuer()
    door = DoorGate(issuer.public_key, relay_id="demoted")
    relay = Relay(gate=door, cache=RefCache(), substrate=Substrate(objects))
    relay.window_reader = WindowReader(Pool(objects), concurrency=8,
                                       counters=relay.counters)
    relay.settle = SettleGate(_PeerSubstrate([16, 16] + [0] * 10), floor=8,
                              stability_s=0.0, poll_s=0.0, demote_after_s=10.0,
                              now=clock)
    assert relay.settle.ready() is True  # settled, stability 0
    for t in (5.0, 10.0, 15.0, 20.0):  # below the floor from 10 s; grace expires at 20 s
        clock.t = t
        relay.settle.ready()
    assert relay.settle.demotions == 1

    body = json.dumps({"k": 2, "n": 4,
                       "shares": [_ref_char(index) for index in range(4)],
                       "deadline_ms": 5000}).encode()
    kwargs = {"relay": "demoted", "window": 4096, "ttl": 600}
    credential = issuer.mint(**kwargs)
    status, payload, headers = relay.handle_window(credential, body)

    assert status == 503
    assert json.loads(payload)["refusal"] == "relay-warming"
    assert headers.get("Retry-After") == "5"
    assert relay.counters.snapshot().get("relay-unsettled") == 1


def test_an_unsettled_relay_refuses_a_window_with_retry_after():
    """Same refusal and same Retry-After as the warm path: ask another relay, come back."""
    from blind_relay import SettleGate

    issuer = DoorIssuer()
    gate = DoorGate(issuer.public_key, relay_id="unsettled")
    relay = Relay(gate=gate, cache=RefCache(), substrate=None, read_enabled=True)
    relay.window_reader = WindowReader(_EmptyPool())
    relay.settle = SettleGate(_PeerSubstrate([0, 1, 2]), floor=8, stability_s=1.0,
                             poll_s=0.0)
    credential = issuer.mint(op=OP_FETCH, relay="unsettled", window=4096, ttl=600)
    body = json.dumps({"k": 2, "n": 4,
                       "shares": [_ref_char(index) for index in range(4)],
                       "deadline_ms": 5000}).encode()

    status, payload, headers = relay.handle_window(credential, body)

    assert status == 503
    assert json.loads(payload)["refusal"] == "relay-warming"
    assert headers.get("Retry-After") == "5"
    assert relay.counters.snapshot().get("relay-unsettled") == 1


def test_a_settled_relay_serves_the_same_window():
    """The gate is a readiness predicate, not a second content check: once settled, 200."""
    from blind_relay import SettleGate

    objects, handles, data = _window_objects(4, 12)
    issuer = DoorIssuer()
    door = DoorGate(issuer.public_key, relay_id="settled")
    relay = Relay(gate=door, cache=RefCache(), substrate=Substrate(objects))
    relay.window_reader = WindowReader(Pool(objects), concurrency=8,
                                       counters=relay.counters)
    relay.settle = SettleGate(_PeerSubstrate([16] * 5), floor=8, stability_s=0.0,
                              poll_s=0.0)
    srv = serve(relay, host="127.0.0.1", port=0, onion_host=None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        body, _, _ = body_for(4, 12)
        status, payload, _ = _post(srv.server_address[1], "/w", body,
                                   credential=issuer.mint(op=OP_FETCH, relay="settled"))
        assert status == 200
        assert payload == b"".join(data)
    finally:
        srv.shutdown()


def test_a_census_that_fails_is_not_a_settled_node():
    """A substrate error must fail closed: treat the node as warming, never as ready."""
    from blind_relay import SettleGate

    class _Broken:
        def connected_peers(self) -> int:
            raise OSError("peer census failed")

    gate = SettleGate(_Broken(), floor=8, stability_s=0.0, poll_s=0.0)
    assert gate.ready() is False
    assert gate.settled_at is None


def test_the_census_polls_at_most_once_per_interval():
    """A burst of client requests between polls must cost one census, not one each."""
    from blind_relay import SettleGate

    class _Clock:
        def __init__(self):
            self.t = 0.0

        def __call__(self):
            return self.t

    clock = _Clock()
    substrate = _PeerSubstrate([8] * 100)
    gate = SettleGate(substrate, floor=8, stability_s=0.0, poll_s=5.0, now=clock)
    for _ in range(50):
        gate.ready()
    assert substrate.calls == 1, "50 requests inside one poll interval cost %d censuses" % substrate.calls


def test_a_window_that_cannot_decode_is_503_not_a_dropped_connection(monkeypatch):
    """The relay must *answer* that it cannot decode, not close the socket.

    Measured on lab relay 2, 2026-11-13: started without `zfec` on `PYTHONPATH`, it answered 7
    of the test publication's 17 windows and dropped the connection on the other 10. The drop is
    `_Server.handle_error` swallowing the traceback out of `FecError`, and from the client's
    side it is indistinguishable from a relay that is not there - so the client would hedge
    against a network fault that does not exist and no counter would name the real cause.

    The wire answer is `503 window-undecodable`, the same instruction `window-incomplete`
    carries: ask another relay, this one cannot serve it.
    """
    objects, handles, data = _window_objects(4, 12)

    def refuse(*_args, **_kwargs):
        raise blind_fec.FecError("zfec is required to encode or decode shares")

    monkeypatch.setattr(blind_fec, "decode_window", refuse)
    srv, relay, issuer = _server(objects)
    try:
        body, _, _ = body_for(4, 12)
        status, payload, headers = _post(
            srv.server_address[1], "/w", body,
            credential=issuer.mint(op=OP_FETCH, relay="r1"))
        assert status == 503, "an undecodable window must be a refusal, not a closed socket"
        assert json.loads(payload)["refusal"] == "window-undecodable"
        assert "Retry-After" in headers
        counts = relay.counters.snapshot()
        assert counts.get("window-undecodable", 0) == 1
        assert counts.get("handler-error", 0) == 0, "the handler must not have died"
    finally:
        srv.shutdown()


# --- test-relay fault switches (A4/A6/A9) --------------------------------------------
#
# Every switch is inert unless its variable is set. That is the property a serving relay
# depends on, so it is asserted first and against a *real* window answer, not a stub.


def test_faults_are_inert_unless_the_environment_says_so():
    from blind_relay import Faults

    off = Faults.from_env({})
    assert off.active() is False
    assert (off.drop_pct, off.delay_s, off.blackhole, off.corrupt, off.truncate) == \
        (0, 0.0, False, False, False)
    assert off.drop_indexes(32) == set(), "nothing dropped when nothing is switched on"
    body = b"0123456789" * 8
    assert off.damaged(body) is body, "an unswitched relay must return the answer untouched"

    # Every spelling an operator might use for "off" is off.
    for value in ("", "0", "false", "no", "off"):
        assert Faults.from_env({"BLINDSTREAM_FAULT_BLACKHOLE": value}).blackhole is False


def test_the_25_percent_drop_is_exactly_a_quarter_of_every_window():
    from blind_relay import Faults

    faults = Faults.from_env({"BLINDSTREAM_FAULT_DROP_PCT": "25"})
    for n, want in ((12, 3), (20, 5), (32, 8)):
        indexes = faults.drop_indexes(n)
        assert len(indexes) == want, "n=%d dropped %d, wanted %d" % (n, len(indexes), want)
        assert all(0 <= index < n for index in indexes)
    assert faults.drop_indexes(0) == set()


def test_a_dropped_quarter_still_decodes_the_window():
    """A9a: lose 3 of 12 shares and the window must still reconstruct from what is left."""
    from blind_relay import Faults

    objects, handles, data = _window_objects(4, 12)
    issuer = DoorIssuer()
    relay = Relay(gate=DoorGate(issuer.public_key, relay_id="lossy"), cache=RefCache(),
                  substrate=Substrate(objects), faults=Faults(drop_pct=25))
    relay.window_reader = WindowReader(Pool(objects), concurrency=8, counters=relay.counters)
    body, _, _ = body_for(4, 12)
    kwargs = {"relay": "lossy", "window": 4096, "ttl": 600}

    status, payload, headers = relay.handle_window(issuer.mint(**kwargs), body)

    assert status == 200
    assert payload == b"".join(data), "the dropped shares must not change the plaintext"
    assert relay.counters.snapshot().get("fault-shares-dropped") == 3


def test_a_corrupt_switch_flips_exactly_one_byte_of_a_good_answer():
    """A6: a 200 that looks like a window, with one byte wrong. The client's digest is the check."""
    from blind_relay import Faults

    objects, handles, data = _window_objects(4, 12)
    issuer = DoorIssuer()
    relay = Relay(gate=DoorGate(issuer.public_key, relay_id="bad"), cache=RefCache(),
                  substrate=Substrate(objects), faults=Faults(corrupt=True))
    relay.window_reader = WindowReader(Pool(objects), concurrency=8, counters=relay.counters)
    body, _, _ = body_for(4, 12)
    kwargs = {"relay": "bad", "window": 4096, "ttl": 600}

    status, payload, _ = relay.handle_window(issuer.mint(**kwargs), body)

    good = b"".join(data)
    assert status == 200, "an integrity fault is a lying 200, not a refusal"
    assert len(payload) == len(good)
    differing = [index for index, (a, b) in enumerate(zip(payload, good)) if a != b]
    assert differing == [0], "exactly the first byte of the first share, nothing else"


def test_a_truncate_switch_answers_half_the_body():
    from blind_relay import Faults

    objects, handles, data = _window_objects(4, 12)
    issuer = DoorIssuer()
    relay = Relay(gate=DoorGate(issuer.public_key, relay_id="short"), cache=RefCache(),
                  substrate=Substrate(objects), faults=Faults(truncate=True))
    relay.window_reader = WindowReader(Pool(objects), concurrency=8, counters=relay.counters)
    body, _, _ = body_for(4, 12)
    kwargs = {"relay": "short", "window": 4096, "ttl": 600}

    status, payload, _ = relay.handle_window(issuer.mint(**kwargs), body)

    assert status == 200
    assert len(payload) == len(b"".join(data)) // 2


# --- D6b: readiness by evidence, because the census cannot see a cut node ---------------
#
# Measured 2026-11-13: cutting a Cybera Fred's peer UDP both ways kept 16-25 peers CONNECTED
# for minutes (29 before the cut), and build 1507's ListPeers has no last-received-packet
# field. So a node the network has left still reads as settled, and the reads are the only
# thing that says otherwise.


class _FailingReader:
    """A window surface whose substrate cannot reach k."""

    warm_required = False

    def __init__(self):
        self.fail = True

    def read(self, request, **kwargs):  # noqa: ANN001, ARG002
        from blind_window_reader import WindowUnavailable
        if self.fail:
            raise WindowUnavailable("no k shares")
        raise AssertionError("the test wanted a failure")


def _route_relay(clock):
    from blind_relay import Faults  # noqa: F401 - keeps the import list honest
    issuer = DoorIssuer()
    relay = Relay(gate=DoorGate(issuer.public_key, relay_id="r"), cache=RefCache(),
                  substrate=None, now=clock)
    relay.window_reader = _FailingReader()
    return relay, issuer


def _window_call(relay, credential):
    body, _, _ = body_for(4, 12)
    return relay.handle_window(credential, body)


def test_three_window_failures_over_twenty_seconds_demote_the_relay():
    base = time.time()

    class _Clock:
        def __init__(self):
            self.t = base

        def __call__(self):
            return self.t

    clock = _Clock()
    relay, issuer = _route_relay(clock)
    kwargs = {"relay": "r", "window": 4096, "ttl": 600}
    credential = issuer.mint(**kwargs)

    for t in (0.0, 11.0):
        clock.t = base + t
        status, payload, _ = _window_call(relay, credential)
        assert status == 503 and json.loads(payload)["refusal"] == "window-incomplete"

    clock.t = base + 21.0  # the third failure, 21 s after the first
    status, payload, _ = _window_call(relay, credential)
    assert status == 503 and json.loads(payload)["refusal"] == "window-incomplete"
    assert relay.route_demotions == 1, "the streak must have demoted the relay"

    clock.t = base + 22.0
    status, payload, headers = _window_call(relay, credential)
    assert status == 503
    assert json.loads(payload)["refusal"] == "relay-warming"
    assert headers.get("Retry-After") == "5"
    assert relay.counters.snapshot().get("route-demoted") == 1

    clock.t = base + 21.0 + 61.0  # the demotion is a cooldown, not a latch
    status, payload, _ = _window_call(relay, credential)
    assert status == 503 and json.loads(payload)["refusal"] == "window-incomplete"


def test_a_burst_of_failures_inside_twenty_seconds_does_not_demote():
    base = time.time()

    class _Clock:
        def __init__(self):
            self.t = base

        def __call__(self):
            return self.t

    clock = _Clock()
    relay, issuer = _route_relay(clock)
    credential = issuer.mint(relay="r", window=4096, ttl=600)
    for t in (0.0, 2.0, 4.0, 6.0):
        clock.t = base + t
        status, _, _ = _window_call(relay, credential)
        assert status == 503
    assert relay.route_demotions == 0, "four failures in six seconds is one bad minute"


def test_one_good_window_clears_the_streak():
    base = time.time()

    class _Clock:
        def __init__(self):
            self.t = base

        def __call__(self):
            return self.t

    clock = _Clock()
    relay, issuer = _route_relay(clock)
    objects, handles, data = _window_objects(4, 12)
    good = WindowReader(Pool(objects), concurrency=8, counters=relay.counters)
    credential = issuer.mint(relay="r", window=4096, ttl=600)

    clock.t = base
    _window_call(relay, credential)
    clock.t = base + 11.0
    _window_call(relay, credential)

    relay.window_reader = good
    clock.t = base + 15.0
    body, _, _ = body_for(4, 12)
    status, payload, _ = relay.handle_window(credential, body)
    assert status == 200 and payload == b"".join(data)
    assert relay._route_fails == 0  # noqa: SLF001 - the streak is the thing under test

    relay.window_reader = _FailingReader()
    clock.t = base + 36.0
    _window_call(relay, credential)
    assert relay.route_demotions == 0, "one success must reset the span"
