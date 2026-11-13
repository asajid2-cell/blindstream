"""Warming a relay's node before it serves its first window.

Measured on a fresh node 2026-11-12 (docs/measurements.md): the first
window pass over the test track lost 4 of 17 windows to share timeouts, and the second pass on
the same node answered 17/17 with window times falling 37 -> 12 s as the node filled. The
cost is real and it is a one-time node warm-up, not anything the window route does wrong.

So a cold node must not be handed a client's window. The relay pays the cost deliberately at
start instead, and refuses windows until it has.

Two pieces, and both live here rather than in `blind_relay.py` on purpose: that module must
contain no file-reading construct and exactly one `print` (its no-log rule is proven from its
own AST, `tests/test_blind_relay_nologs.py`). A warm sample is read from a file, so the read
belongs beside the relay, not inside it.

**What the sample may be.** Refs, one per line - a ref names no track, no owner and no
corpus, so a warm sample file is not a publication index. It is the operator's list of bytes
this relay expects to serve. Nothing here logs, returns or counts anything but aggregates.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence


def load_refs(path: str | Path) -> list[str]:
    """The warm sample: one ref per non-blank line, in file order.

    Raises `OSError` on an unreadable file and `ValueError` on an empty one. Both are
    start-time errors rather than a silently-cold relay: a launch that named a warm sample
    and could not read it would otherwise serve cold windows under the belief it was warm,
    which is the failure this module exists to prevent.
    """
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    refs = [line.strip() for line in lines if line.strip()]
    if not refs:
        raise ValueError("the warm sample names no refs")
    return refs


def summary_line(outcome: dict) -> str:
    """The warm pass's outcome as one start-up line fragment: counts only.

    Deliberately no ref and no duration per ref - the same rule the relay's counters keep.
    """
    return ("warm pass: asked=%s arrived=%s missed=%s errors=%s seconds=%s"
            % (outcome.get("asked"), outcome.get("arrived"), outcome.get("missed"),
               outcome.get("errors"), outcome.get("seconds")))


def run(relay, path: str | Path, *, limit: int = 64, target_seconds: float = 0.0,
        max_seconds: float = 0.0) -> dict:
    """Read the warm sample at `path` through `relay.substrate`, then mark the relay warm.

    The relay is marked warm only after the pass returns, whatever it found: a partially
    warm node still costs a client far less than a cold one, and refusing windows forever
    because a few sample refs were not on this node's neighbourhood would be worse than the
    cold first window. The counts say what happened so the operator can tell.

    `target_seconds` and `max_seconds` are passed through as the two ceilings (`warm_pass`).
    Neither is decided here: the sample file says what this relay expects to serve, the
    operator says how warm is warm enough and how long the boot outage may last.
    """
    from blind_relay import warm_pass

    refs: Sequence[str] = load_refs(path)
    outcome = warm_pass(relay, refs, limit=limit, target_seconds=target_seconds,
                        max_seconds=max_seconds)
    return outcome
