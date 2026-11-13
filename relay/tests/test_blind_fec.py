"""S1: the fast-retrieval codec and the manifest it publishes (spec §3, §7 S1).

What is asserted here is the geometry and the arithmetic, not any measured speed: a schedule that
silently changes shape between publications is a leak and a compatibility break at once, so the
schedule is pinned to the spec's table; and "any k of n rebuilds the data" is checked exhaustively
for the head window and by sampling for the steady one, because 16-of-32 has 601,080,390 subsets
and an exhaustive test would be a benchmark, not a test.

The manifest claims that matter are tamper claims: a document with one window's refs swapped, one
number edited, or one window list reordered must all be refused. Those are checked against a real
Ed25519 key rather than a stub, so the test exercises the same path a client will.
"""
from __future__ import annotations

import itertools
import json
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import blind_fec  # noqa: E402
from blind_fec import (  # noqa: E402
    FecError,
    HEAD_WINDOW,
    MANIFEST_AAD,
    SECOND_WINDOW,
    SHARE_BYTES,
    STEADY_WINDOW,
    Window,
    build_manifest,
    decode_window,
    encode_window,
    manifest_digest,
    manifest_from_pages,
    manifest_pages,
    schedule,
    sign_manifest,
    verify_manifest,
)


def block(n: int, size: int = 32768) -> bytes:
    """A deterministic pseudo-block: same arg, same bytes, every run."""
    rng = random.Random(n)
    return bytes(rng.getrandbits(8) for _ in range(size))


# --- schedule: the geometry is a constant, and the spec's table is the contract ---------------

def test_the_schedule_matches_the_spec_table():
    assert schedule(244)[0] == Window(*HEAD_WINDOW)
    assert schedule(244)[1] == Window(*SECOND_WINDOW)
    assert schedule(244)[2] == Window(*STEADY_WINDOW)
    # 4 + 8 + 16*14 = 236, so 244 leaves an 8-block tail window with >=2x redundancy.
    tail = schedule(244)[-1]
    assert tail.k == 8
    assert tail.n == max(2 * tail.k, tail.k + 4)


def test_every_window_covers_the_track_exactly_once():
    for total in (1, 4, 12, 13, 20, 21, 36, 100, 244, 1000):
        windows = schedule(total)
        assert sum(w.k for w in windows) == total, total


def test_the_head_is_the_most_redundant_window():
    windows = schedule(244)
    ratios = [w.n / w.k for w in windows]
    assert ratios[0] >= max(ratios[1:])
    assert all(r >= 2.0 for r in ratios)


def test_a_short_track_still_gets_redundancy():
    windows = schedule(3)
    assert len(windows) == 1
    assert windows[0].k == 3 and windows[0].n >= 2 * 3


def test_an_empty_track_has_no_windows():
    assert schedule(0) == []


def test_a_window_needs_recovery_shares():
    with pytest.raises(FecError):
        Window(4, 4)
    with pytest.raises(FecError):
        Window(0, 4)


# --- coding: any k of n rebuilds the data, and nothing else does ------------------------------

def test_a_golden_vector_is_stable():
    """A fixed 4-of-12 window's recovery shares hash to a fixed vector.

    This is the guard against a silent change in the coding: if the parity changes, every
    already-published recovery share on the substrate is wrong for the new code and the whole
    library has to be republished. The test failing is the alarm.
    """
    data = [block(i) for i in range(4)]
    shares = encode_window(data, Window(4, 12))
    assert len(shares) == 12
    for i in range(4):
        assert shares[i] == data[i], "data shares are systematic: share i is block i"
    vector = [blind_fec.sha256_hex(s)[:16] for s in shares[4:]]
    assert vector == GOLDEN_RECOVERY


# The first 16 hex of each recovery share's sha256 for blocks 0..3 seeded by random.Random(0..3),
# taken from zfec 1.6.0.0. Pinned deliberately: see the test's docstring.
GOLDEN_RECOVERY = [
    "487153be6f758537", "88b9c69169a122cb", "386cbc278ae8acd1", "83596bf8829f9893",
    "91ff34536e2824ac", "b5c5155fcfb23afe", "9c55ddede3ed1ca0", "4daf9a77e679048b",
]


def test_every_subset_of_k_decodes_the_head_window_exactly():
    data = [block(i) for i in range(4)]
    shares = encode_window(data, Window(4, 12))
    by_index = dict(enumerate(shares))
    for subset in itertools.combinations(range(12), 4):
        got = decode_window({i: by_index[i] for i in subset}, Window(4, 12))
        assert got == data, subset


def test_sampled_subsets_decode_the_steady_window_exactly():
    data = [block(100 + i) for i in range(16)]
    window = Window(16, 32)
    shares = encode_window(data, window)
    by_index = dict(enumerate(shares))
    rng = random.Random(20261111)
    for _ in range(200):
        subset = rng.sample(range(32), 16)
        got = decode_window({i: by_index[i] for i in subset}, window)
        assert got == data, sorted(subset)


def test_a_complete_data_set_decodes_without_zfec():
    """When the k data shares are the ones that arrived, no decode is needed at all."""
    data = [block(i) for i in range(4)]
    got = decode_window({i: data[i] for i in range(4)}, Window(4, 12))
    assert got == data


def test_a_corrupted_recovery_share_yields_a_wrong_block_not_silence():
    """The client's protection is the data digest, so a bad share must surface as bad bytes."""
    data = [block(i) for i in range(4)]
    shares = encode_window(data, Window(4, 12))
    tampered = dict(enumerate(shares))
    bad = bytearray(tampered[7])
    bad[0] ^= 0xFF
    tampered[7] = bytes(bad)
    # Only the recovery shares arrived, with one of them corrupted.
    got = decode_window({i: tampered[i] for i in (4, 5, 6, 7)}, Window(4, 12))
    assert got != data, "a corrupted share must not decode to the original blocks"


def test_too_few_shares_is_a_refusal_not_a_partial_decode():
    data = [block(i) for i in range(4)]
    shares = encode_window(data, Window(4, 12))
    with pytest.raises(FecError):
        decode_window({0: shares[0], 1: shares[1], 2: shares[2]}, Window(4, 12))


def test_a_short_share_is_refused():
    data = [block(i) for i in range(4)]
    shares = encode_window(data, Window(4, 12))
    with pytest.raises(FecError):
        decode_window({i: shares[i][:100] for i in range(4)}, Window(4, 12))


def test_a_block_larger_than_a_share_is_refused():
    with pytest.raises(FecError):
        encode_window([b"x" * (SHARE_BYTES + 1)] * 4, Window(4, 12))


def test_an_unpadded_short_block_is_padded_to_a_uniform_share():
    short = b"a sealed block that is shorter than a share"
    shares = encode_window([short] * 4, Window(4, 12))
    assert all(len(s) == SHARE_BYTES for s in shares)
    assert shares[0] == short.ljust(SHARE_BYTES, b"\0")


# --- manifest: canonical, signed, and refused when touched ------------------------------------

def _windows():
    windows = []
    for w in schedule(20):
        windows.append({
            "k": w.k, "n": w.n,
            "data": [
                {"ref": "chk:CHK@data-%d" % i, "padded_sha256": "00" * 32,
                 "plaintext_len": 32700, "aad": "a%d" % i}
                for i in range(w.k)
            ],
            "recovery": ["chk:CHK@rec-%d-%d" % (w.k, j) for j in range(w.recovery)],
        })
    return windows


def _manifest():
    return build_manifest(mime="audio/mp4", duration_ms=20000, total_plaintext_bytes=20 * 32700,
                          first_play_blocks=4, windows=_windows())


def test_the_manifest_round_trips_through_pages():
    manifest = _manifest()
    pages = manifest_pages(manifest)
    assert all(len(p) == SHARE_BYTES for p in pages)
    assert manifest_from_pages(pages, count=len(pages)) == manifest


def test_the_manifest_digest_is_canonical():
    a = _manifest()
    b = json.loads(json.dumps(a))
    assert manifest_digest(a) == manifest_digest(b)


def test_a_manifest_with_the_wrong_share_count_is_refused():
    windows = _windows()
    windows[0]["data"] = windows[0]["data"][:-1]
    with pytest.raises(FecError):
        build_manifest(mime="audio/mp4", duration_ms=20000,
                       total_plaintext_bytes=20 * 32700, first_play_blocks=4,
                       windows=windows)


def test_a_window_below_the_redundancy_floor_is_refused():
    with pytest.raises(FecError):
        build_manifest(mime="audio/mp4", duration_ms=1, total_plaintext_bytes=1,
                       first_play_blocks=1,
                       windows=[{"k": 16, "n": 19,
                                 "data": [{"ref": "r", "padded_sha256": "0", "plaintext_len": 1,
                                           "aad": "a"}] * 16,
                                 "recovery": ["r", "r", "r"]}])


def test_a_manifest_signature_covers_every_byte():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    seed = bytes(range(32))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    manifest = _manifest()
    signature = sign_manifest(manifest, seed=seed)
    assert verify_manifest(manifest, signature, public_key=public) == manifest


@pytest.mark.parametrize("mutate", [
    lambda m: m["windows"][0]["data"][0].__setitem__("plaintext_len", 1),
    lambda m: m["windows"][0]["recovery"].reverse(),
    lambda m: m["rendition"].__setitem__("duration_ms", 1),
    lambda m: m["windows"].reverse(),
])
def test_a_tampered_manifest_is_refused(mutate):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    seed = bytes(range(32))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    manifest = _manifest()
    signature = sign_manifest(manifest, seed=seed)
    tampered = json.loads(json.dumps(manifest))
    mutate(tampered)
    if tampered == manifest:  # a mutation that happened to be a no-op is not a test
        pytest.skip("mutation did not change the document")
    with pytest.raises(FecError):
        verify_manifest(tampered, signature, public_key=public)


def test_a_signature_from_another_key_is_refused():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    other = bytes([7] * 32)
    public = Ed25519PrivateKey.from_private_bytes(other).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    manifest = _manifest()
    signature = sign_manifest(manifest, seed=bytes(range(32)))
    with pytest.raises(FecError):
        verify_manifest(manifest, signature, public_key=public)


def test_the_manifest_aad_is_distinct_from_a_block():
    """The manifest is sealed under its own AAD so a page can never be mistaken for audio."""
    assert MANIFEST_AAD != b""
    assert b"fec-manifest" in MANIFEST_AAD
    assert b"stream-block" not in MANIFEST_AAD


def test_sealing_injects_the_aad():
    seen = []

    def seal(data, aad):
        seen.append(aad)
        return data

    pages = manifest_pages(_manifest())
    blind_fec.seal_manifest_pages(pages, seal=seal)
    assert seen == [MANIFEST_AAD] * len(pages)
