"""turn a track's sealed STREAM segments into the fast-retrieval strand's objects.

The publisher already seals a track into an ordered list of uniform 32 KiB CHK blocks
(`owner_publisher._seal_rendition`). Those blocks are the *data shares* of the strand. This
module adds the two things that make retrieval survivable:

* **Recovery shares.** Each window of the schedule (`blind_fec.schedule`) is encoded to `n`
  shares, of which the first `k` are the data blocks themselves, so any `k` of `n` rebuild the
  window. The coding is keyless and over ciphertext, so a relay can decode a window without
  being able to read it, and the encoding never needs the content key.
* **A sealed manifest.** The play-time source of truth: which refs belong to which window,
  which digest each data share must hash to, and the schedule. It is canonical JSON, sealed
  under its own AAD, split into uniform 32 KiB pages, and signed by the owner over the
  canonical body.

What is *not* here: no key, no host, no network, no insert. The publisher hands this module
its sealed segments and gets back the objects to insert plus the manifest to commit.

Two properties worth stating because they are easy to lose:

* **A data share is the publisher's own segment, not a rewrap of it.** The manifest copies the
  segment's `ref`, `aad`, `plaintext_len` and padded digest verbatim. `aad` is the object's
  AEAD nonce: a manifest that invented one would hand the client a block it can never open.
  This module therefore never derives a ref or makes up an aad -- it reads them.
* **A recovery share has no AEAD envelope of its own.** It is parity over sealed blocks, so it
  carries no plaintext and no nonce; a reader can only decode with it. The only bytes a client
  ever opens are data shares, whose digests the owner signed.
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping, Sequence

import blind_fec
from blind_fec import FecError

# The fields of a publisher segment this module needs. Named here so a caller that hands over
# a record missing one fails at this seam with a message, rather than publishing a manifest
# with a hole in it that only a client's digest check would find.
SEGMENT_FIELDS = ("sealed", "ref", "aad", "plaintext_len", "padded_sha256")

#: The byte that ends a manifest's content, before the NUL padding (spec §5 item 3's framing).
#:
#: The same byte the index uses (`blind_library_index.SEALED_TERMINATOR`), and it must stay the
#: same one: the client requires a final `0x01` in both readers, because the last byte of a sealed
#: body is a Poly1305 tag byte and a tag that ends in `0x00` (one in 256) cannot be distinguished
#: from the padding by a NUL trim alone.
MANIFEST_TERMINATOR = b"\x01"


def fec_rendition(segments: Sequence[Mapping[str, Any]], *, mime: str, duration_ms: int,
                  total_plaintext_bytes: int, first_play_blocks: int,
                  ref_for: Callable[[bytes], str],
                  sign_seed: bytes | None = None) -> dict[str, Any]:
    """Encode a sealed STREAM rendition into the strand's objects and its manifest.

    `segments` are the publisher's sealed STREAM segments in playback order, each carrying:

    * `sealed` - the padded 32 KiB wire bytes (`build_object`'s output)
    * `ref` - the `chk:CHK@…` handle the segment will have (the publisher's `chk_ref`)
    * `aad` - the segment's object id, which is what the client must pass to its opener
    * `plaintext_len` - the number of real bytes in it, so the client can trim the padding
    * `padded_sha256` - the digest the client checks the padded share against

    The returned mapping is what an insert loop and a record writer need:

    * `windows` - per window: `index`, `k`, `n`, the k padded data shares and the n-k recovery
      shares as bytes. The bytes are what gets inserted; the manifest carries the refs.
    * `manifest` / `manifest_body` / `manifest_pages` - the body, its canonical bytes (what the
      signature covers), and the same bytes as uniform pages.
    * `insert_order` - every object in the order the spec asks for: shuffled within the track
      so no window's shares are contiguous in a relay's queue (spec §3.3).
    * `signature` - the owner's signature over the canonical body, when a seed was given.

    A share larger than one block is refused here rather than at insert, because the strand's
    uniform geometry is the property that stops a share's size from saying anything.
    """
    if not segments:
        raise FecError("a rendition needs at least one sealed block")
    for index, segment in enumerate(segments):
        missing = [name for name in SEGMENT_FIELDS if name not in segment]
        if missing:
            raise FecError("segment %d is missing %s" % (index, ", ".join(missing)))
        if len(segment["sealed"]) > blind_fec.SHARE_BYTES:
            raise FecError("sealed block %d is %d bytes, more than one share (%d)"
                           % (index, len(segment["sealed"]), blind_fec.SHARE_BYTES))

    windows = blind_fec.schedule(len(segments))
    if sum(w.k for w in windows) != len(segments):
        # `schedule` is the contract, but a length it cannot express must not become a track
        # that quietly drops or duplicates blocks.
        raise FecError("schedule covers %d blocks, not %d"
                       % (sum(w.k for w in windows), len(segments)))

    encoded_windows: list[dict[str, Any]] = []
    manifest_windows: list[dict[str, Any]] = []
    insert_order: list[dict[str, Any]] = []
    offset = 0
    for window_index, window in enumerate(windows):
        group = list(segments[offset:offset + window.k])
        offset += window.k
        padded = [blind_fec.pad(bytes(segment["sealed"])) for segment in group]
        shares = blind_fec.encode_window(padded, window)

        data_refs = [{"ref": segment["ref"], "padded_sha256": segment["padded_sha256"],
                      "plaintext_len": int(segment["plaintext_len"]), "aad": segment["aad"]}
                     for segment in group]
        for j, share in enumerate(padded):
            insert_order.append({"kind": "data", "window": window_index, "j": j,
                                 "bytes": share})
        # A recovery share's own digest is not published: the client never checks it, it
        # checks the data share a decode produces. So the manifest names its ref only.
        recovery_refs = []
        for j in range(window.k, window.n):
            recovery_refs.append(ref_for(bytes(shares[j])))
            insert_order.append({"kind": "recovery", "window": window_index, "j": j,
                                 "bytes": shares[j]})

        manifest_windows.append({"k": window.k, "n": window.n,
                                 "data": data_refs, "recovery": recovery_refs})
        encoded_windows.append({"index": window_index, "k": window.k, "n": window.n,
                                "data": padded, "recovery": list(shares[window.k:])})

    manifest = blind_fec.build_manifest(
        mime=mime, duration_ms=duration_ms, total_plaintext_bytes=total_plaintext_bytes,
        first_play_blocks=first_play_blocks, windows=manifest_windows)
    body = blind_fec._canonical(manifest)  # noqa: SLF001 - the body the signature covers
    pages = blind_fec.manifest_pages(manifest)
    for page_index, page in enumerate(pages):
        insert_order.append({"kind": "manifest", "window": None, "j": page_index,
                             "bytes": page})

    shuffle_within_track(insert_order)
    return {
        "windows": encoded_windows,
        "manifest": manifest,
        "manifest_body": body,
        "manifest_pages": pages,
        "signature": (blind_fec.sign_manifest(manifest, seed=sign_seed)
                      if sign_seed is not None else None),
        "insert_order": insert_order,
    }


def shuffle_within_track(objects: list[dict[str, Any]]) -> None:
    """Reorder inserts so no window's shares are contiguous (spec §3.3).

    The order is deterministic from the objects' own bytes, so republishing a track produces
    the same order and two operators can compare queue logs. Shuffling *across* tracks is the
    publisher's job; this removes only the within-track structure.
    """
    import random
    seed = int(hashlib.sha256(b"".join(
        hashlib.sha256(obj["bytes"]).digest() for obj in objects)).hexdigest()[:16], 16)
    random.Random(seed).shuffle(objects)


def manifest_object_bytes(result: dict[str, Any], *,
                          seal: Callable[[bytes, bytes], bytes]) -> list[bytes]:
    """The manifest's pages: sealed **once**, terminated, then cut into whole shares.

    `seal` is the publisher's own seal (`cc.seal(read_key, data, aad=…)`). Injected rather
    than imported for the same reason `blind_fec.seal_manifest_pages` injects it: this module
    must not hold a key.

    The framing is the index's, byte for byte (`blind_library_index.seal_pages`): one envelope
    over the whole canonical body, a `0x01` terminator after it, then cut at share boundaries
    with only the final share NUL-padded. The client reads it the same way in both places -- it
    trims trailing NULs, *requires* the terminator, drops it, and opens the joined bytes once
    (`FecManifestLoader.load`, `LibraryIndex.open`). The terminator is what keeps a Poly1305 tag
    ending in `0x00` from being eaten by the trim; without it one manifest in 256 is unreadable,
    and a reader that "drops a terminator if present" would lose a real tag byte one in 256 the
    other way, so this is a required byte and not a guess.

    Sealing each page on its own cannot work at this geometry: a page is already a whole 32 KiB
    share, so its envelope would push it over. The terminator goes on the *body*, before the cut,
    for the same reason.
    """
    body = blind_fec._canonical(result["manifest"])  # noqa: SLF001 - the signed bytes
    sealed = seal(body, blind_fec.MANIFEST_AAD) + MANIFEST_TERMINATOR
    pages = [sealed[i:i + blind_fec.SHARE_BYTES]
             for i in range(0, len(sealed), blind_fec.SHARE_BYTES)]
    return [page.ljust(blind_fec.SHARE_BYTES, b"\0") for page in pages]


def manifest_root_refs(pages: Sequence[bytes], *, ref_for: Callable[[bytes], str]) -> list[str]:
    """The refs a catalogue entry or grant carries: the manifest pages' own CHK handles."""
    return [ref_for(bytes(page)) for page in pages]


def verify_round_trip(result: dict[str, Any], *, public_key: bytes) -> dict[str, Any]:
    """Re-open the manifest from its own pages and check the signature covers it.

    A publication claims a manifest; this is the check that the claim is self-consistent
    before anything is inserted. It rebuilds from the pages a client would receive, not from
    the in-memory body, so a page-splitting bug cannot pass.
    """
    pages = result["manifest_pages"]
    rebuilt = blind_fec.manifest_from_pages(pages, count=len(pages))
    if rebuilt != result["manifest"]:
        raise FecError("manifest does not survive its own page encoding")
    if result.get("signature") is not None:
        blind_fec.verify_manifest(rebuilt, result["signature"], public_key=public_key)
    return rebuilt
