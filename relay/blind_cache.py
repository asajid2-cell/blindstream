"""The blind relay's cache: ciphertext keyed by the ref **alone** (ADR 0011 Decision 4).

It is the same bytes for everyone - a content-addressed object is not personalised - so a
cache keyed by the ref can serve any caller who holds the ref, and holds nothing else. No
per-client state, no per-owner state, no ref-to-anything map but bytes.

**A cache hit is a side channel (a side channel).** A hit reveals that *someone* fetched that ref
recently. It never reveals who, or whose. It is deliberately not mitigated at the storage
layer: the alternatives - per-client caches, per-client TTLs, dropping the cache altogether -
are either identity bookkeeping (worse) or a per-block read of the single substrate reader
(the wall the cache exists to relieve). What the wire says about it was narrowed on
2026-11-13 (F1): the `X-Blind-Cache` response header is gone, because anyone holding a ref
could observe it and confirm that another user had asked for that object. A hit and a miss
are now the same bytes under the same headers; only the relay's own aggregate counters keep
the distinction. Nothing per-client may ever enter a key.

The cache is bounded twice - by entry count and by TTL - so a block a relay has served once
is not retained for as long as the process runs. Both bounds are configuration.
"""
from __future__ import annotations

import threading
import time


class RefCache:
    """A bounded, TTL'd map from ref to ciphertext. Keyed by the ref alone.

    Eviction is insertion-ordered (oldest first) and happens on write, so the cache is
    bounded by configuration rather than by request volume. Expiry is checked on read and
    swept on write; a caller never receives an expired entry.
    """

    def __init__(self, *, max_entries: int = 512, ttl_seconds: float = 600.0,
                 max_bytes: int = 256 * 1024 * 1024) -> None:
        self._max_entries = max(1, int(max_entries))
        self._ttl = max(0.0, float(ttl_seconds))
        self._max_bytes = max(1, int(max_bytes))
        self._store: dict[str, tuple[bytes, float]] = {}
        self._bytes = 0
        self._lock = threading.Lock()

    def get(self, ref: str, *, now: float | None = None) -> bytes | None:
        nowv = time.time() if now is None else float(now)
        with self._lock:
            entry = self._store.get(ref)
            if entry is None:
                return None
            blob, stored_at = entry
            if self._ttl and nowv - stored_at > self._ttl:
                self._store.pop(ref, None)
                self._bytes -= len(blob)
                return None
            return blob

    def put(self, ref: str, blob: bytes, *, now: float | None = None) -> None:
        nowv = time.time() if now is None else float(now)
        with self._lock:
            previous = self._store.pop(ref, None)
            if previous is not None:
                self._bytes -= len(previous[0])
            self._store[ref] = (blob, nowv)
            self._bytes += len(blob)
            self._evict(nowv)

    def _evict(self, now: float) -> None:
        """Drop expired entries, then oldest-first until both bounds hold. Caller holds lock."""
        if self._ttl:
            for ref in [r for r, (_, at) in self._store.items() if now - at > self._ttl]:
                blob, _at = self._store.pop(ref)
                self._bytes -= len(blob)
        while self._store and (len(self._store) > self._max_entries
                               or self._bytes > self._max_bytes):
            ref, (blob, _at) = next(iter(self._store.items()))
            self._store.pop(ref, None)
            self._bytes -= len(blob)

    def stats(self) -> dict[str, int]:
        """Entry count and resident bytes: aggregate counters, never a contents listing."""
        with self._lock:
            return {"entries": len(self._store), "bytes": self._bytes}
