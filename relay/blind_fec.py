"""The fast-retrieval strand's codec: keyless k-of-n over the sealed stream blocks.

The substrate is the only durable and only warm store, so the thing that has to be fixed is
retrieval, not insert. What breaks a play today is not the median block, which is fast, but the
tail: 3-5% of blocks arrive later than the player's buffer at any concurrency, and one late block
is a hole in the ordered stream. A window that carries n shares of which any k rebuild the data
turns that tail into arithmetic - a player waiting for k answers out of n waits on the k-th
arrival, not the last.

Three properties this module is built to keep:

* **Keyless.** The coding is over ciphertext. Encoding, decoding and (later) healing need no
  content key, so a relay can decode without being able to read anything it decodes.
* **Uniform.** Every share is one 32 KiB single-block CHK and every track uses the same window
  schedule, so a share's size and count say nothing beyond how long the track is - which is
  already visible today.
* **Verified where it already was.** Recovery shares carry no digest. The relay decodes to data
  shares and the client checks those against the owner-signed per-block digests it already
  checks. A recovery share that decodes wrong produces a digest mismatch at the client, never
  silently wrong bytes.

The schedule is graduated because the first window is the only one on the critical path of first
audio: a 4-of-12 head lands near the 25th percentile of share latency where a 16-of-32 head would
have to wait for the 16th of 32. Later windows can spend less redundancy because the player has
buffer by then.

Nothing here touches a key, a host, or the network. It is the pure half of step S1 and every
function is exercised against a deterministic vector so a change in the coding or the schedule is
a failing test rather than a silent reshuffle of published geometry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

SHARE_BYTES = 32768
"""One share is exactly one Freenet single block. Uniform geometry is an invariant, not a
convenience: a share that could be any size would leak the track's shape through its refs."""

MANIFEST_VERSION = 1
MANIFEST_AAD = b"blindstream/fec-manifest/v1"

HEAD_WINDOW = (4, 12)
"""The first window. Small and heavily redundant, because its k-th arrival *is* first audio."""

SECOND_WINDOW = (8, 20)
"""The second, for the same reason at lower cost once the head has landed."""

STEADY_WINDOW = (16, 32)
"""Every window after the first two. 2x redundancy, ~12.9 s of a 320 kbps stream."""


class FecError(Exception):
    """A request the codec refuses, or an input that cannot be a valid rendition."""


@dataclass(frozen=True)
class Window:
    """One window's geometry. `k` data shares, `n - k` recovery shares."""

    k: int
    n: int

    def __post_init__(self) -> None:
        if self.k < 1:
            raise FecError("a window needs at least one data share")
        if self.n <= self.k:
            raise FecError("a window needs at least one recovery share")
        if self.n > 255:
            raise FecError("zfec codes are limited to 255 shares")

    @property
    def recovery(self) -> int:
        return self.n - self.k


def schedule(total_blocks: int) -> list[Window]:
    """The window schedule for a track of `total_blocks` sealed stream blocks.

    Graduated and then uniform: 4-of-12, 8-of-20, 16-of-32 repeated, with a final short window
    that keeps at least 2x redundancy (and at least four spare shares) so a track never ends on a
    cheap window just because it happened to divide unevenly.
    """
    if total_blocks < 0:
        raise FecError("a track cannot have a negative block count")
    if total_blocks == 0:
        return []

    out: list[Window] = []
    left = total_blocks
    if left >= HEAD_WINDOW[0]:
        out.append(Window(*HEAD_WINDOW))
        left -= HEAD_WINDOW[0]
    if left >= SECOND_WINDOW[0]:
        out.append(Window(*SECOND_WINDOW))
        left -= SECOND_WINDOW[0]
    while left > STEADY_WINDOW[0]:
        out.append(Window(*STEADY_WINDOW))
        left -= STEADY_WINDOW[0]
    if left:
        # A short tail window: k, and enough recovery for 2x or four spare, whichever is larger.
        k = left
        n = max(2 * k, k + 4)
        out.append(Window(k, n))
    return out


def _zfec():
    """zfec, imported where it is needed so a host without it still imports this module.

    The wheels live in `fastsub/wheels`; a host without pip takes one unzipped onto PYTHONPATH.
    """
    try:
        import zfec  # noqa: F401
        return zfec
    except ImportError as exc:  # pragma: no cover - exercised by the CLI path, not the unit tests
        raise FecError(
            "zfec is required to encode or decode shares; install the cp38/cp313 wheel from "
            "fastsub/wheels onto PYTHONPATH"
        ) from exc


def pad(block: bytes) -> bytes:
    """A sealed block to one full share. The padding is what makes shares uniform."""
    if len(block) > SHARE_BYTES:
        raise FecError("a sealed block is larger than one share (%d > %d)"
                       % (len(block), SHARE_BYTES))
    return block.ljust(SHARE_BYTES, b"\0")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_window(data_blocks: Sequence[bytes], window: Window) -> list[bytes]:
    """The `n` shares of one window, data shares first, then recovery.

    `data_blocks` must hold exactly `window.k` padded-or-not sealed blocks. Data shares are the
    blocks themselves (padded); recovery shares are zfec's systematic parity, which is what makes
    any k of the n sufficient.
    """
    if len(data_blocks) != window.k:
        raise FecError("window wants %d data blocks, got %d" % (window.k, len(data_blocks)))
    padded = [pad(b) for b in data_blocks]
    zfec = _zfec()
    encoder = zfec.Encoder(window.k, window.n)
    return list(encoder.encode(padded))


def decode_window(shares: dict[int, bytes], window: Window) -> list[bytes]:
    """Rebuild the `k` padded data blocks from any `k` shares, addressed by index.

    `shares` maps a share's index in `0..n-1` to its 32 KiB bytes. Indices below `window.k` are
    data shares and need no decoding at all when the set is complete; anything else goes through
    zfec. A caller that supplies fewer than `k`, or an index outside the window, gets `FecError`
    rather than a guess.
    """
    if len(shares) < window.k:
        raise FecError("cannot decode a %d-of-%d window from %d shares"
                       % (window.k, window.n, len(shares)))
    chosen = sorted(shares)[:window.k]
    for index in chosen:
        if not 0 <= index < window.n:
            raise FecError("share index %d is outside a %d-share window" % (index, window.n))
        if len(shares[index]) != SHARE_BYTES:
            raise FecError("share %d is %d bytes, not %d"
                           % (index, len(shares[index]), SHARE_BYTES))
    if chosen == list(range(window.k)):
        return [shares[i] for i in range(window.k)]
    zfec = _zfec()
    decoder = zfec.Decoder(window.k, window.n)
    return list(decoder.decode([shares[i] for i in chosen], chosen))


# ---------------------------------------------------------------------------------------------
# Manifest: the play-time source of truth, replacing the owner-served block list.
# ---------------------------------------------------------------------------------------------

def _canonical(payload: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, ASCII. What gets signed and what gets sealed."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class ShareRef:
    """One data share's identity, as the client needs it: ref, padded digest, real length."""

    ref: str
    padded_sha256: str
    plaintext_len: int
    aad: str


def build_manifest(*, mime: str, duration_ms: int, total_plaintext_bytes: int,
                   first_play_blocks: int, windows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The manifest body for a rendition. Callers assemble `windows` from `encode_rendition`.

    `windows` entries are `{"k": k, "n": n, "data": [...], "recovery": [ref, ...]}` so the client
    never derives geometry - it is told, and a schedule change is a republication, not a release.
    """
    if not windows:
        raise FecError("a rendition needs at least one window")
    total_data = sum(len(w["data"]) for w in windows)
    for index, w in enumerate(windows):
        if len(w["data"]) != w["k"]:
            raise FecError("window %d carries %d data shares, not its k=%d"
                           % (index, len(w["data"]), w["k"]))
        if len(w["recovery"]) != w["n"] - w["k"]:
            raise FecError("window %d carries %d recovery shares, not n-k=%d"
                           % (index, len(w["recovery"]), w["n"] - w["k"]))
        if w["n"] < 2 * w["k"] and w["n"] - w["k"] < 4:
            # The redundancy floor the schedule promises. A publication that undercuts it would
            # have the tail protection the strand exists for quietly absent.
            raise FecError("window %d is below the redundancy floor (%d of %d)"
                           % (index, w["k"], w["n"]))
    if total_data == 0:
        raise FecError("a rendition needs at least one data share")
    return {
        "version": MANIFEST_VERSION,
        "rendition": {
            "mime": mime,
            "total_plaintext_bytes": int(total_plaintext_bytes),
            "duration_ms": int(duration_ms),
            "first_play_blocks": int(first_play_blocks),
        },
        "share_bytes": SHARE_BYTES,
        "schedule": [{"k": w["k"], "n": w["n"]} for w in windows],
        "windows": [
            {"data": list(w["data"]), "recovery": list(w["recovery"])} for w in windows
        ],
    }


def manifest_digest(manifest: dict[str, Any]) -> str:
    """The digest the owner signs over the manifest body. Canonical, so it is reproducible."""
    return sha256_hex(_canonical(manifest))


def manifest_pages(manifest: dict[str, Any]) -> list[bytes]:
    """The manifest as whole 32 KiB pages, so it is itself insertable as uniform CHKs.

    A manifest that fits one page is one share; larger ones are split and (by the caller) carried
    as a 4-of-12 window, so manifest retrieval has the same tail protection as the audio.
    """
    body = _canonical(manifest)
    pages = [body[i:i + SHARE_BYTES] for i in range(0, len(body), SHARE_BYTES)] or [b""]
    return [p.ljust(SHARE_BYTES, b"\0") for p in pages]


def manifest_from_pages(pages: Iterable[bytes], *, count: int) -> dict[str, Any]:
    """Rebuild and parse a manifest from its pages. Trailing padding is stripped by the parser."""
    joined = b"".join(bytes(p) for p in pages)
    if count <= 0:
        raise FecError("a manifest needs at least one page")
    body = joined[:SHARE_BYTES * (count - 1)] + joined[SHARE_BYTES * (count - 1):SHARE_BYTES * count].rstrip(b"\0")
    try:
        manifest = json.loads(body.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FecError("manifest pages are not a canonical JSON body") from exc
    if manifest.get("version") != MANIFEST_VERSION:
        raise FecError("manifest version %r is not %d"
                       % (manifest.get("version"), MANIFEST_VERSION))
    return manifest


def _signing_key(raw: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if len(raw) != 32:
        raise FecError("an Ed25519 seed is 32 bytes, got %d" % len(raw))
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_manifest(manifest: dict[str, Any], *, seed: bytes) -> str:
    """The owner's signature over the manifest body, base64url without padding.

    The signature is over `manifest_digest`'s canonical bytes, so any re-serialisation of the
    manifest that changes key order, whitespace or number form is a different document and will
    not verify - which is what stops a relay from quietly reordering a window list.
    """
    signature = _signing_key(seed).sign(_canonical(manifest))
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def verify_manifest(manifest: dict[str, Any], signature: str, *, public_key: bytes) -> dict[str, Any]:
    """The manifest, or `FecError` if the signature does not cover exactly these bytes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(public_key) != 32:
        raise FecError("an Ed25519 public key is 32 bytes, got %d" % len(public_key))
    padded = signature + "=" * (-len(signature) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is a refusal, never a guess
        raise FecError("manifest signature is not base64url") from exc
    if len(raw) != 64:
        raise FecError("an Ed25519 signature is 64 bytes, got %d" % len(raw))
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, _canonical(manifest))
    except InvalidSignature as exc:
        raise FecError("manifest signature does not verify") from exc
    return manifest


def seal_manifest_pages(pages: Sequence[bytes], *, seal) -> list[bytes]:
    """Pass manifest pages through the caller's `seal(bytes, aad) -> bytes`, already padded.

    The seal is injected rather than imported so this module never grows a dependency on the
    content-key machinery, and so the tests can assert the AAD without holding a key.
    """
    out = []
    for page in pages:
        sealed = seal(bytes(page), MANIFEST_AAD)
        if len(sealed) > SHARE_BYTES:
            raise FecError("a sealed manifest page exceeds one share (%d > %d)"
                           % (len(sealed), SHARE_BYTES))
        out.append(sealed.ljust(SHARE_BYTES, b"\0"))
    return out


def open_manifest_pages(sealed_pages: Sequence[bytes], *, open_) -> list[bytes]:
    """Inverse of `seal_manifest_pages`; `open_(bytes, aad) -> bytes` is the caller's opener."""
    return [open_(bytes(p), MANIFEST_AAD) for p in sealed_pages]
