"""The deployment's insert seam for the blind relay's `POST /i` (ADR 0011 / the insert design).

`blind_relay.py` decodes the owner's spool archive and hands the ciphertext to a seam the
deployment names on the command line (`--insert-seam <module>:<function>`). This module is that
seam for the lab box's write relay, and it is the *only* part of the relay that touches a write
substrate.

**It performs a real insert.** Neither `blind_relay` nor this module reimplements a CHK: it
calls the substrate's own insert (`HyphanetMesh.put`, the production insert), which sends
`ClientPut` with `GetCHKOnly=false` -- Fred derives the handle *and* stores the block -- and
waits for `PutSuccessful`. The handle returned is the node's, and the owner still re-derives
`chk_ref(blob)` locally and refuses a disagreement (`owner_publisher.py`), so the relay is never
*trusted* for the ref even though it is what stored the bytes. It must store, not merely derive:
the deferred witness proves retrievability by fetching the object from a **different** node, and
an object that was only derived but never stored cannot be witnessed.

The seam signature (`docs/blind-relay-interface.md`, "The insert seam"):

    seam(pool, items) -> {object_id: "chk:CHK@..."}
      pool   the relay's held-connection pool (`checkout` / `checkin` / `discard` of HyphanetMesh)
      items  [(object_id, ciphertext)] sorted by object_id

One connection is taken from the pool and **reused for every object in the batch** -- never one
per object, because a fresh FCP handshake is ~1.5 s. A batch fans out over up to 8
connections (`BLINDSTREAM_INSERT_PUTS`); the default is **4**, the relay's own pool size. The
width was 1 for a while on one unrepeated bench (23.3 s/object at width 1 against 42.7 at
width 4), and three alternating reps on 2026-10-20 reversed that: at 32 KiB blocks the batch
bench's medians are **22.2 s/object at width 1 and 7.7 s/object at width 4** (2.87x), and the
L54 harness agrees (2.49x on per-object rate); per-put p50 does not get worse at width 4, so
the old reading was a heavy-tail draw from a cooldown/retry regime, not node serialisation.
A failed put raises `SubstrateError`, which the relay answers as
`503 substrate-unavailable` (the owner re-POSTs the whole archive; inserts are content-addressed,
so a retry lands the same refs). A mesh that failed is **discarded**, not checked back in, so a
dead socket is not handed to the next batch; in a parallel batch every mesh is discarded, since
a sibling may have caused it.

The insert *queue* is a property of the write pool (`blind_substrate.WritePool`, which runs the
adaptive queue), not of this seam: `mesh.put` reads it from the mesh.
"""
from __future__ import annotations

import os
import threading
from typing import Any

from blind_substrate import SubstrateError

# How many objects one batch inserts at once. 4 is the default, matching the relay's pool: three
# alternating reps on the write lane (2026-10-20) put width 4 at 2.87x width 1's per-object rate
# (see the module docstring). The knob stays so a future substrate can be re-measured the same way.
PARALLEL_PUTS = 4


def parallel_puts() -> int:
    """The batch's put concurrency: `BLINDSTREAM_INSERT_PUTS`, clamped to 1-8, else the default."""
    raw = os.environ.get("BLINDSTREAM_INSERT_PUTS", "")
    try:
        width = int(raw) if raw else PARALLEL_PUTS
    except ValueError:
        width = PARALLEL_PUTS
    return max(1, min(8, width))


def _substrate_failures() -> tuple[type[BaseException], ...]:
    """The substrate's own insert-failure types, imported lazily.

    Lazy so this module -- and its test -- can be exercised against a fake mesh with no staged
    crudenet runtime on the path, exactly as `blind_substrate` imports its substrate lazily.
    """
    from crudenet.hyphanet import HyphanetError

    return (HyphanetError, TimeoutError, OSError)


def _width(pool: Any, count: int) -> int:
    """How many connections this batch takes: the knob, the batch size, and the pool's size."""
    capacity = getattr(pool, "size", 1)
    try:
        capacity = int(capacity)
    except (TypeError, ValueError):
        capacity = 1
    return max(1, min(parallel_puts(), count, max(1, capacity)))


def insert(pool: Any, items: list[tuple[str, bytes]]) -> dict[str, str]:
    """Store every object in `items` on the pooled substrate; return `{object_id: chk:CHK@…}`."""
    width = _width(pool, len(items))
    if width == 1:
        return _insert_serial(pool, items)
    return _insert_parallel(pool, items, width)


def _insert_serial(pool: Any, items: list[tuple[str, bytes]]) -> dict[str, str]:
    """One connection, every object in order -- the shape when the knob or the pool is 1."""
    mesh = pool.checkout()
    try:
        refs = {oid: _put(mesh, oid, blob) for oid, blob in items}
    except Exception:
        # A batch that failed part-way keeps no connection: the socket may be the reason.
        pool.discard(mesh)
        raise
    pool.checkin(mesh)
    return refs


def _insert_parallel(pool: Any, items: list[tuple[str, bytes]], width: int) -> dict[str, str]:
    """`width` connections, one worker each, round-robin over the batch.

    The connections are checked out **before** any put, so a pool that cannot serve the batch
    fails as a batch, not after half of it stored. A worker stops at its first failure; every
    mesh in the batch is then discarded (a failed sibling may have caused it) and the
    lowest-index failure is raised, so the answer does not depend on which worker lost the race.
    """
    meshes: list[Any] = []
    try:
        for _ in range(width):
            meshes.append(pool.checkout())
    except Exception:
        for mesh in meshes:
            pool.discard(mesh)
        raise
    failures: list[tuple[int, BaseException]] = []
    refs: dict[str, str] = {}
    guard = threading.Lock()

    def work(mesh: Any, chunk: list[tuple[int, str, bytes]]) -> None:
        for index, oid, blob in chunk:
            try:
                ref = _put(mesh, oid, blob)
            except BaseException as exc:  # noqa: BLE001 - re-raised after the join
                with guard:
                    failures.append((index, exc))
                return
            with guard:
                refs[oid] = ref

    chunks = [[(index, oid, blob) for index, (oid, blob) in enumerate(items) if index % width == lane]
              for lane in range(width)]
    threads = [threading.Thread(target=work, args=(mesh, chunk), daemon=True)
               for mesh, chunk in zip(meshes, chunks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        for mesh in meshes:
            pool.discard(mesh)
        raise min(failures, key=lambda failure: failure[0])[1]
    for mesh in meshes:
        pool.checkin(mesh)
    return refs


def _put(mesh: Any, oid: str, blob: bytes) -> str:
    """Insert one object; return the node's full `chk:CHK@…` handle, or raise `SubstrateError`."""
    try:
        ref = mesh.put(blob, object_id=oid)
    except _substrate_failures() as exc:
        # The substrate would not store it, so this is a retryable refusal, never a faked
        # handle: the relay answers 503 and the owner re-POSTs. A wrong handle would be worse
        # than a refusal -- the owner would reject it anyway, and a "success" would hide a
        # store that never happened.
        raise SubstrateError(f"insert failed: {type(exc).__name__}") from None
    # `Ref.value` is the full `chk:CHK@<routing>,<encryption>,<suffix>` handle the relay's
    # `HANDLE_RE` requires; `Ref.to_uri()` would strip the `chk:` prefix and be refused.
    return ref.value
