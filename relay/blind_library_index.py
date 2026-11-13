"""Spec section 6: the catalogue without the owner.

Today `/library` on the door proxies to the owner process, so resolution dies when the owner
dives. G-COLD requires the opposite: five never-played tracks, played to the end, with the
publisher and the owner stopped. A device that has never played a track has no cached listing
of it either, so the index has to serve discovery *and* resolution, not just a root lookup.

The recommended shape, and the one here:

* the owner builds one **index** - every catalogue entry it offers, each with the manifest root
  that makes it playable - canonically serialises it, seals it under the corpus read key, and
  splits the ciphertext into uniform 32 KiB pages. The pages are CHKs like any other object, so
  a relay serves them through the route it already has and a client reads them the same way it
  reads a manifest page.
* a small **pointer** names the current index: its page refs, page count and body digest, signed
  by the owner. It is what changes when a track is added, so the company host can hold the
  pointer as one opaque blob and never see a catalogue, a title or a ref.

Three properties this module is careful about:

* **It holds no key.** Sealing and opening are injected (`seal(bytes, aad) -> bytes`), exactly
  as `blind_fec.seal_manifest_pages` does, because the module that writes an index must not be
  the module that can read one - and a test can then assert the AAD without a capability.
* **The digest is over the index body, not the pages.** A page a relay substitutes changes the
  body and the signature check then fails; a digest over the pages would instead bless whatever
  arrived.
* **A pointer is not trusted for what it says, only for who signed it.** Verification re-derives
  the body from the pages and compares the digest, so a pointer that names pages no relay holds
  fails at read time rather than handing the client a half catalogue.

The client half reads the same document (`Sources/LibraryIndex.swift`); the field names here are
the wire contract between them and are asserted in the tests.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Iterable, Sequence

import blind_fec
from blind_fec import FecError

INDEX_VERSION = 1
INDEX_AAD = b"blindstream/library-index/v1"
POINTER_AAD = b"blindstream/library-pointer/v1"
POINTER_VERSION = 1

#: The envelope prefix every sealed object starts with (`crudenet.crypto.MAGIC` + kind 1).
ENVELOPE_PREFIX = b"CRD1\x01"

#: `crudenet.crypto.SEALED_OVERHEAD` - magic, kind, nonce and tag, the bytes a seal adds.
#: Restated rather than imported because this module must not depend on the content-key
#: machinery at all; `test_sealed_overhead_matches_the_crypto_module` asserts they agree.
SEALED_OVERHEAD = 33

#: What a page's content ends with, before the NUL padding to a whole share.
#:
#: The padding cannot be stripped by looking for the last non-NUL byte alone: a sealed
#: envelope ends in a 16-byte Poly1305 tag, and a tag whose final byte is `0x00` (one in
#: 256) would lose that byte to the strip and fail to open. Writing an explicit terminator
#: after the tag fixes where the content ends without the reader having to guess, so the
#: strip becomes `rstrip(b"\0")` then "must end in 0x01".
SEALED_TERMINATOR = b"\x01"

#: The fields a catalogue entry carries besides its manifest root. These are the names the
#: client's `ShelfEntry` already decodes, so an entry read from the index is built by the same
#: code as one read from the live door - the index is another way to obtain the same document,
#: not a second document type.
ENTRY_FIELDS = ("id", "title", "artist", "album", "duration", "extension", "mime_type", "size")

#: The fields of a manifest root. `pages` are CHK refs, `digest` is the manifest body's sha256
#: and `page_count` is what a reader needs to know how many pages to fetch - a count is cheaper
#: and more honest than a terminator, because a short read is then an error rather than a short
#: manifest.
ROOT_FIELDS = ("pages", "digest", "page_count")


def _canonical(payload: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, ASCII - `blind_fec`'s own rule."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def entry(track_id: str, *, title: str, mime_type: str, size: int,
          manifest_pages: Sequence[str], manifest_digest: str,
          artist: str | None = None, album: str | None = None,
          duration: float | None = None, extension: str = "m4a") -> dict[str, Any]:
    """One catalogue entry with the root that lets it play without the owner.

    The root is required, not optional: an entry in this index claims the track is playable
    from the substrate alone, and an entry with no root would be a row the device can draw and
    cannot play. A track the owner has not published in the strand's shape is simply not in
    the index - it stays discoverable through the owner, which is what "owner online for
    discovery only" means, and stops being so the moment the owner goes under.
    """
    if not track_id:
        raise FecError("a catalogue entry needs an id")
    if not manifest_pages:
        raise FecError("a catalogue entry needs at least one manifest page")
    if len(manifest_digest) != 64:
        raise FecError("a manifest digest is 64 hex characters, got %d" % len(manifest_digest))
    row: dict[str, Any] = {
        "id": track_id,
        "title": title,
        "artist": artist,
        "album": album,
        "duration": float(duration) if duration is not None else None,
        "extension": extension,
        "mime_type": mime_type,
        "size": int(size),
        "manifest": {
            "pages": [str(page) for page in manifest_pages],
            "page_count": len(manifest_pages),
            "digest": str(manifest_digest),
        },
    }
    _validate_entry(row)
    return row


def _validate_entry(row: dict[str, Any]) -> None:
    missing = [name for name in ENTRY_FIELDS if name not in row]
    if missing:
        raise FecError("catalogue entry is missing %s" % ", ".join(missing))
    manifest = row.get("manifest")
    if not isinstance(manifest, dict):
        raise FecError("catalogue entry %r has no manifest root" % row.get("id"))
    missing = [name for name in ROOT_FIELDS if name not in manifest]
    if missing:
        raise FecError("manifest root is missing %s" % ", ".join(missing))
    if int(manifest["page_count"]) != len(manifest["pages"]):
        raise FecError("manifest root names %d pages and carries %d"
                       % (manifest["page_count"], len(manifest["pages"])))
    if len(str(manifest["digest"])) != 64:
        raise FecError("manifest root digest is not 64 hex characters")


def build(entries: Iterable[dict[str, Any]], *, revision: int, generated_at: str) -> dict[str, Any]:
    """The index document. Ordered by id so two builds of one catalogue are one document."""
    rows = sorted(entries, key=lambda row: row["id"])
    seen: set[str] = set()
    for row in rows:
        _validate_entry(row)
        if row["id"] in seen:
            raise FecError("catalogue entry %r appears twice" % row["id"])
        seen.add(row["id"])
    return {
        "version": INDEX_VERSION,
        "revision": int(revision),
        "generated_at": str(generated_at),
        "entries": rows,
    }


def body(index: dict[str, Any]) -> bytes:
    """The canonical bytes the pointer's digest and the owner's signature cover."""
    if index.get("version") != INDEX_VERSION:
        raise FecError("index version %r is not %d" % (index.get("version"), INDEX_VERSION))
    if not isinstance(index.get("entries"), list):
        raise FecError("an index needs an entries list")
    return _canonical(index)


def digest(index: dict[str, Any]) -> str:
    return _sha256_hex(body(index))


def page_count(index: dict[str, Any]) -> int:
    """How many 32 KiB shares the sealed index occupies.

    Counted over the **sealed** length, not the plaintext one: the envelope and the
    terminator are inside the shares, and a body that fits a share exactly becomes two once
    they are added. A pointer that named the plaintext count would name one page too few.
    """
    sealed_len = len(body(index)) + SEALED_OVERHEAD + len(SEALED_TERMINATOR)
    return max(1, -(-sealed_len // blind_fec.SHARE_BYTES))


def pages(index: dict[str, Any]) -> list[bytes]:
    """One entry per share the sealed index occupies, for a caller that needs the count.

    The bytes are placeholders: the real shares only exist after sealing, which this module
    cannot do (`seal_pages` injects the seal). Sized as shares so a caller that writes them
    to disk by mistake writes a share-shaped hole, never a plausible-looking short page.
    """
    return [b"\0" * blind_fec.SHARE_BYTES for _ in range(page_count(index))]


def seal_pages(index: dict[str, Any], *, seal: Callable[[bytes, bytes], bytes]) -> list[bytes]:
    """The index's sealed pages, ready to insert: one envelope, cut into shares.

    The **whole body** is sealed once, not page by page. A page sealed on its own would need
    33 bytes of envelope inside a 32768-byte share, which does not fit - and a body that fits
    in one share would be squeezed into a share minus its envelope, so the geometry would stop
    being uniform. Sealing once and then cutting keeps every share exactly one CHK wide and
    keeps the digest the pointer carries over a single, easily reproduced body.

    `seal(raw, aad) -> bytes` is the publisher's own seal and is injected, so this module
    never holds a key.
    """
    sealed = seal(body(index), INDEX_AAD) + SEALED_TERMINATOR
    out = []
    for i in range(page_count(index)):
        chunk = sealed[i * blind_fec.SHARE_BYTES:(i + 1) * blind_fec.SHARE_BYTES]
        out.append(chunk.ljust(blind_fec.SHARE_BYTES, b"\0"))
    return out


def open_pages(sealed_pages: Sequence[bytes], *, open_: Callable[[bytes, bytes], bytes],
               count: int) -> dict[str, Any]:
    """Rebuild the index from its sealed pages: join, strip padding, open once, verify.

    `count` is required rather than inferred from `len(sealed_pages)` so that a reader which
    lost a page fails here instead of handing back a short body - the same reason
    `blind_fec.manifest_from_pages` takes one. A body with a hole in it is not a smaller
    catalogue, it is a wrong one.
    """
    if count <= 0:
        raise FecError("an index needs at least one page")
    if len(sealed_pages) != count:
        raise FecError("index has %d pages and %d were supplied" % (count, len(sealed_pages)))
    joined = b"".join(bytes(page) for page in sealed_pages)
    stripped = joined.rstrip(b"\0")
    if not stripped.endswith(SEALED_TERMINATOR):
        raise FecError("index pages carry no content terminator")
    sealed = stripped[:-len(SEALED_TERMINATOR)]
    if not sealed.startswith(ENVELOPE_PREFIX):
        raise FecError("index pages do not start with a sealed envelope")
    try:
        raw = open_(sealed, INDEX_AAD)
    except Exception as exc:  # noqa: BLE001 - any failure to open is a refusal, never a guess
        # A substituted or truncated page fails inside the AEAD, and the crypto module
        # raises its own type there. Translated so a caller catching `FecError` sees one
        # vocabulary: a body that will not open is a body that will not open, whatever the
        # AEAD library calls it.
        raise FecError("index pages do not open") from exc
    try:
        index = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FecError("index pages are not a canonical JSON body") from exc
    if index.get("version") != INDEX_VERSION:
        raise FecError("index version %r is not %d" % (index.get("version"), INDEX_VERSION))
    for row in index.get("entries", []):
        _validate_entry(row)
    return index


def pointer(index: dict[str, Any], *, page_refs: Sequence[str],
            sign: Callable[[bytes], bytes]) -> dict[str, Any]:
    """The small document the company host holds: which pages, which digest, whose signature.

    It carries no title, no id and no track count. A host holding it knows how many pages an
    index has and nothing about what is in it - which is the whole point of keeping it off the
    owner's process.
    """
    if len(page_refs) != len(pages(index)):
        raise FecError("a pointer names %d pages and the index has %d"
                       % (len(page_refs), len(pages(index))))
    unsigned = {
        "version": POINTER_VERSION,
        "revision": int(index["revision"]),
        "generated_at": str(index["generated_at"]),
        "page_refs": [str(ref) for ref in page_refs],
        "page_count": len(page_refs),
        "digest": digest(index),
    }
    signature = sign(_canonical(unsigned))
    out = dict(unsigned)
    out["signature"] = _b64url(signature)
    return out


def _b64url(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify_pointer(doc: dict[str, Any], *, public_key: bytes) -> dict[str, Any]:
    """The pointer, or `FecError` if its signature does not cover exactly these fields."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if doc.get("version") != POINTER_VERSION:
        raise FecError("pointer version %r is not %d"
                       % (doc.get("version"), POINTER_VERSION))
    if len(public_key) != 32:
        raise FecError("an Ed25519 public key is 32 bytes, got %d" % len(public_key))
    signature = str(doc.get("signature") or "")
    if not signature:
        raise FecError("a pointer carries a signature")
    import base64
    padded = signature + "=" * (-len(signature) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is a refusal, never a guess
        raise FecError("pointer signature is not base64url") from exc
    unsigned = {key: value for key, value in doc.items() if key != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            raw, _canonical(unsigned))
    except InvalidSignature as exc:
        raise FecError("pointer signature does not verify") from exc
    if int(doc.get("page_count", 0)) != len(doc.get("page_refs") or []):
        raise FecError("pointer names %r pages and carries %d"
                       % (doc.get("page_count"), len(doc.get("page_refs") or [])))
    return doc


def roots_by_track(index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The lookup the client actually needs: track id -> its manifest root."""
    return {row["id"]: dict(row["manifest"]) for row in index["entries"]}
