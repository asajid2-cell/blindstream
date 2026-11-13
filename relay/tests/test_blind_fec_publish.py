"""a rendition encoded into strands, and a manifest that names what it published.

What is asserted here is that the strand's objects are *derivable* and *consistent*: every
window decodes from any k of its shares, the manifest's data entries are the publisher's own
segment identities verbatim (a ref, an aad, a length, a digest), the recovery entries name the
handles their shares will have, the insert order does not put a window's shares next to each
other, and the whole document survives being split into uniform pages and signed.

`ref_for` is injected rather than imported because the real derivation
(`owner_publisher.chk_ref`) lives beside the crudenet runtime. The test's stub is a real
function of the bytes, so a manifest naming one thing while the shares are another is a failing
assertion rather than a coincidence.
"""
from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import blind_fec  # noqa: E402
import blind_fec_publish  # noqa: E402
from blind_fec import FecError, SHARE_BYTES  # noqa: E402
from blind_fec_publish import (  # noqa: E402
    fec_rendition,
    manifest_object_bytes,
    manifest_root_refs,
    verify_round_trip,
)


def block(n: int, size: int = SHARE_BYTES - 33) -> bytes:
    rng = random.Random(n)
    return bytes(rng.getrandbits(8) for _ in range(size))


def stub_ref(padded: bytes) -> str:
    """A stand-in for `chk_ref` that is still a function of the share's bytes."""
    return "chk:CHK@" + hashlib.sha256(padded).hexdigest()[:20]


def segments(count: int) -> list[dict]:
    """A rendition's sealed segments, the only shape the publisher hands over."""
    out = []
    for index in range(count):
        sealed = blind_fec.pad(block(index))
        out.append({
            "sealed": sealed,
            "ref": stub_ref(sealed),
            "aad": "aad-%d" % index,
            "plaintext_len": len(block(index)),
            "padded_sha256": blind_fec.sha256_hex(sealed),
            "plaintext_sha256": hashlib.sha256(block(index)).hexdigest(),
        })
    return out


def rendition(count: int = 20, seed: bytes | None = None) -> dict:
    return fec_rendition(segments(count), mime="audio/mp4", duration_ms=count * 1000,
                         total_plaintext_bytes=count * (SHARE_BYTES - 33),
                         first_play_blocks=2, ref_for=stub_ref, sign_seed=seed)


# --- geometry: the strand covers the track, and no window is a special case ------------------

def test_every_block_lands_in_exactly_one_window():
    result = rendition(20)
    encoded = result["windows"]
    assert sum(w["k"] for w in encoded) == 20
    assert [w["index"] for w in encoded] == list(range(len(encoded)))
    # The schedule's own shape is carried, not re-derived by the client.
    assert result["manifest"]["schedule"] == [{"k": w["k"], "n": w["n"]} for w in encoded]


def test_an_empty_rendition_is_refused():
    with pytest.raises(FecError):
        fec_rendition([], mime="audio/mp4", duration_ms=0, total_plaintext_bytes=0,
                      first_play_blocks=1, ref_for=stub_ref)


def test_a_block_larger_than_a_share_is_refused_at_publication():
    bad = segments(4)
    bad[1]["sealed"] = b"x" * (SHARE_BYTES + 1)
    with pytest.raises(FecError):
        fec_rendition(bad, mime="audio/mp4", duration_ms=1, total_plaintext_bytes=1,
                      first_play_blocks=1, ref_for=stub_ref)


def test_a_segment_missing_an_identity_field_is_refused():
    """The manifest copies identities verbatim, so a segment without them cannot publish."""
    bad = segments(4)
    del bad[2]["aad"]
    with pytest.raises(FecError):
        fec_rendition(bad, mime="audio/mp4", duration_ms=1, total_plaintext_bytes=1,
                      first_play_blocks=1, ref_for=stub_ref)


# --- the coding itself, over a real publication shape ----------------------------------------

@pytest.mark.parametrize("count", [3, 4, 12, 20, 36, 244])
def test_any_k_of_each_published_window_rebuilds_its_data(count):
    """Sampled over every window of a real track length: the published geometry works."""
    result = rendition(count)
    rng = random.Random(count)
    for window in result["windows"]:
        shares = list(window["data"]) + list(window["recovery"])
        assert len(shares) == window["n"]
        for _ in range(3):
            subset = sorted(rng.sample(range(window["n"]), window["k"]))
            got = blind_fec.decode_window({i: shares[i] for i in subset},
                                          blind_fec.Window(window["k"], window["n"]))
            assert got == window["data"], (count, window["index"], subset)


def test_the_data_shares_are_the_publishers_own_segments():
    """A rewrap here would break decryption: the client opens with the segment's own aad."""
    published = segments(20)
    result = fec_rendition(published, mime="audio/mp4", duration_ms=1,
                           total_plaintext_bytes=1, first_play_blocks=1, ref_for=stub_ref)
    flat = [share for window in result["windows"] for share in window["data"]]
    assert flat == [segment["sealed"] for segment in published]
    entries = [entry for window in result["manifest"]["windows"] for entry in window["data"]]
    for segment, entry in zip(published, entries):
        assert entry["ref"] == segment["ref"]
        assert entry["aad"] == segment["aad"]
        assert entry["plaintext_len"] == segment["plaintext_len"]
        assert entry["padded_sha256"] == segment["padded_sha256"]


def test_every_recovery_entry_names_the_share_it_will_store():
    result = rendition(20)
    for window in result["windows"]:
        entries = result["manifest"]["windows"][window["index"]]["recovery"]
        assert entries == [stub_ref(share) for share in window["recovery"]]
        assert all(entry.startswith("chk:CHK@") for entry in entries)


def test_a_recovery_share_has_no_digest_in_the_manifest():
    """Only data shares carry a digest; a recovery share is checked by what it decodes to."""
    result = rendition(20)
    for window in result["manifest"]["windows"]:
        assert set(window) == {"data", "recovery"}
        assert all(isinstance(ref, str) for ref in window["recovery"])


def test_a_short_sealed_block_is_padded_to_one_share():
    short = segments(4)
    short[0]["sealed"] = short[0]["sealed"][:1000]
    result = fec_rendition(short, mime="audio/mp4", duration_ms=1, total_plaintext_bytes=1,
                           first_play_blocks=1, ref_for=stub_ref)
    assert all(len(share) == SHARE_BYTES for share in result["windows"][0]["data"])


# --- insert order: the privacy shape (spec 3.3) ---------------------------------------------

def test_no_window_s_shares_are_contiguous_in_the_insert_order():
    result = rendition(64)
    order = [(e["kind"], e["window"], e["j"]) for e in result["insert_order"]]
    per_window = {}
    for position, (kind, window, j) in enumerate(order):
        if kind == "manifest":
            continue
        per_window.setdefault((kind, window), []).append(position)
    for key, positions in per_window.items():
        span = positions[-1] - positions[0]
        assert span >= len(positions) - 1, key
        assert span > len(positions) // 2, ("window shares stayed together", key, positions)


def test_the_insert_order_is_stable_for_a_republish():
    """Two runs over the same bytes must agree, so queue logs are comparable."""
    a = [e["bytes"] for e in rendition(20)["insert_order"]]
    b = [e["bytes"] for e in rendition(20)["insert_order"]]
    assert a == b


def test_every_strand_object_is_inserted_exactly_once():
    result = rendition(20)
    expected = (sum(w["n"] for w in result["windows"]) + len(result["manifest_pages"]))
    assert len(result["insert_order"]) == expected
    assert len({hashlib.sha256(e["bytes"]).digest() for e in result["insert_order"]}) == expected


# --- the manifest: pages, signature, and the round trip a client relies on -------------------

def test_the_manifest_survives_its_own_pages():
    result = rendition(244)
    rebuilt = verify_round_trip(result, public_key=b"")
    assert rebuilt == result["manifest"]


def test_a_signed_manifest_verifies_from_its_pages():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes(range(32))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    result = rendition(20, seed=seed)
    assert result["signature"]
    verify_round_trip(result, public_key=public)


def test_a_manifest_page_set_that_was_edited_does_not_verify():
    """A single hex character moved in one digest is a different document, and must be refused."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes(range(32))
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    result = rendition(20, seed=seed)
    body = b"".join(result["manifest_pages"]).rstrip(b"\0")
    marker = b'"padded_sha256":"'
    at = body.index(marker) + len(marker)
    was = body[at:at + 1]
    edited = body[:at] + (b"0" if was != b"0" else b"1") + body[at + 1:]
    assert edited != body
    result["manifest_pages"] = [edited[i:i + SHARE_BYTES] for i in range(0, len(edited), SHARE_BYTES)]
    result["manifest_pages"] = [p.ljust(SHARE_BYTES, b"\0") for p in result["manifest_pages"]]
    with pytest.raises(FecError):
        verify_round_trip(result, public_key=public)


def test_the_manifest_is_one_terminated_envelope_cut_into_shares():
    """The client joins the pages, strips NULs, requires `0x01`, drops it and opens once.

    Per-page envelopes cannot pass that reader, and cannot even fit: a page is already a whole
    share, so an envelope on it would overflow. The terminator therefore goes on the body before
    the cut - the same framing the index uses.
    """
    result = rendition(244)
    seen = []

    def seal(data, aad):
        seen.append((data, aad))
        return b"CRD1\x01" + b"x" * 40 + data

    def open_(blob, aad):
        assert aad == blind_fec.MANIFEST_AAD
        return blob[45:]

    sealed = manifest_object_bytes(result, seal=seal)
    assert len(seen) == 1, "the body is sealed once, not once per page"
    assert seen[0][0] == blind_fec._canonical(result["manifest"])
    assert seen[0][1] == blind_fec.MANIFEST_AAD
    joined = b"".join(sealed).rstrip(b"\0")
    assert joined.endswith(b"\x01")
    assert not joined.endswith(b"\x01\x01"), "the terminator is written once"
    assert open_(joined[:-1], blind_fec.MANIFEST_AAD) == blind_fec._canonical(result["manifest"])
    assert all(len(page) == SHARE_BYTES for page in sealed)


def test_a_tag_ending_in_nul_survives_because_the_terminator_marks_the_end():
    """The 1-in-256 case: the trim must stop on the terminator, not on the tag's own byte."""
    result = rendition(20)

    def seal(data, aad):
        return b"TAG\x00"

    sealed = manifest_object_bytes(result, seal=seal)
    joined = b"".join(sealed).rstrip(b"\0")
    assert joined.endswith(b"TAG\x00\x01")
    assert joined[:-1].endswith(b"TAG\x00")


def test_the_manifest_terminator_is_the_index_terminator():
    """One rule for both readers: the client requires the same byte in `LibraryIndex.open`."""
    import blind_library_index

    assert blind_fec_publish.MANIFEST_TERMINATOR == blind_library_index.SEALED_TERMINATOR


def test_the_manifest_root_is_the_page_handles():
    result = rendition(20)
    pages = result["manifest_pages"]
    assert manifest_root_refs(pages, ref_for=stub_ref) == [stub_ref(p) for p in pages]


def test_the_manifest_names_the_rendition_s_own_geometry():
    result = rendition(244)
    rendition_block = result["manifest"]["rendition"]
    assert rendition_block["mime"] == "audio/mp4"
    assert result["manifest"]["share_bytes"] == SHARE_BYTES
    assert result["manifest"]["rendition"]["first_play_blocks"] == 2
