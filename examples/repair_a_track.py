"""Encode a file into redundant windows, lose shares, and rebuild it anyway.

This is the whole argument of the project in one offline script: a track is split into
32 KiB blocks, each window of blocks is spread into `n` shares of which any `k` rebuild
the window, and losing fewer than `n - k` shares costs nothing but bytes.

    python examples/repair_a_track.py                  # built-in synthetic track
    python examples/repair_a_track.py song.m4a 0.25    # a real file, 25% of shares lost

Nothing here touches a network or a node. The relay code that fetches shares lives in
`relay/`; this script only proves the arithmetic and the digests.
"""
from __future__ import annotations

import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "relay"))

import blind_fec  # noqa: E402


def blocks_of(data: bytes) -> list[bytes]:
    """Split the payload into the 32 KiB blocks a window is built from."""
    size = blind_fec.SHARE_BYTES
    return [data[i:i + size] for i in range(0, len(data), size)]


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else None
    loss = float(argv[2]) if len(argv) > 2 else 0.25
    if path:
        data = open(path, "rb").read()
        label = os.path.basename(path)
    else:
        # A synthetic 195 s, 320 kbps track: 7,800,000 bytes, or 239 blocks.
        data = random.Random(7).randbytes(320 * 195 * 1000 // 8)
        label = "synthetic 320 kbps, 195 s"
    rng = random.Random(20261113)

    blocks = blocks_of(data)
    windows = blind_fec.schedule(len(blocks))
    print(f"{label}: {len(data):,} bytes, {len(blocks)} blocks, "
          f"{len(windows)} windows, dropping {loss:.0%} of shares\n")
    print(f"{'window':>6} {'k':>4} {'n':>4} {'shares':>7} {'lost':>5} "
          f"{'rebuilt':>8}  {'result':<10} digest")

    rebuilt = bytearray()
    lost_total = 0
    for number, window in enumerate(windows):
        start = sum(w.k for w in windows[:number])
        own = blocks[start:start + window.k]
        shares = {i: share for i, share in enumerate(blind_fec.encode_window(own, window))}

        dropped = [i for i in range(window.n) if rng.random() < loss]
        for i in dropped:
            del shares[i]
        # A window below k is genuinely lost; that is the only way this fails.
        if len(shares) < window.k:
            print(f"{number:>6} {window.k:>4} {window.n:>4} {len(shares) + len(dropped):>7} "
                  f"{len(dropped):>5} {'-':>8}  LOST       "
                  f"{len(shares)} of {window.n} left, k={window.k}")
            return 1

        recovered = blind_fec.decode_window(shares, window)
        expected = [blind_fec.pad(block) for block in own]
        ok = recovered == expected
        digest = hashlib.sha256(b"".join(recovered)).hexdigest()[:16]
        lost_total += len(dropped)
        rebuilt.extend(b"".join(recovered))
        print(f"{number:>6} {window.k:>4} {window.n:>4} {len(shares) + len(dropped):>7} "
              f"{len(dropped):>5} {len(recovered):>8}  {'ok' if ok else 'MISMATCH':<10} "
              f"{digest}")
        if not ok:
            return 1

    payload = bytes(rebuilt[:len(data)])
    same = hashlib.sha256(payload).hexdigest() == hashlib.sha256(data).hexdigest()
    print(f"\nshares dropped: {lost_total}  windows lost: 0  "
          f"file identical: {'yes' if same else 'NO'}")
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
