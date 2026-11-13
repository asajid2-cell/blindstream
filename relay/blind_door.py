"""The ADR 0011 door credential - Form D, a device pseudonym countersigned by an issuer.

This is the conduit pass of ADR 0011 Decision 2. It authorises the *use of a relay's
bandwidth* and nothing else:

    C1  conduit only         it names no owner, corpus, ref or content; the relay never
                             checks entitlement here (entitlement stays the read key's)
    C2  not a ref->owner map issuing or redeeming it tells no company system which owner
                             a device belongs to, or which refs it reads
    C3  not a signed grant   possession proves nothing about any owner
    C4  per-device budget    the relay enforces a rate and a concurrency budget per
                             credential without learning who or what the credential is
    C5  cheap to replace     a leaked credential is dropped at the issuer, touching no
                             owner and no content
    C6  offline-checkable    the relay validates it with the issuer's pinned public key,
                             calling no company service on the request path

**Form D is the first shippable step, not the target.** The target is Form T (unlinkable
blind-signed passes, ADR 0011 open item 1). Form D's residual is written down, not hidden:
the `pseudonym` is stable for the life of the credential, so a compelled relay can *cluster
one pseudonym's ref set*. It cannot name the owner - the issuer is reached over the
anonymising transport and the token carries no owner field, so nothing the company holds
maps a ref to an owner  - but it is a profile, and Form T removes it by making the
issuer unable to recognise its own signature.

Wire shape (one token, one header value) - base64url, no padding, of UTF-8 JSON:

    bcred1.<payload>.<signature>
    payload   = {"v":1,"typ":"D","op":"fetch"|"insert","psn":<opaque>,"iat":<int>,
                 "exp":<int>,"relay":<id>|"*","epoch":<int>,"win":<int>}
    signature = Ed25519 over the payload bytes as embedded (the base64url body, ASCII),
                under the issuer's private key

`op` is which surface the pass opens (`GET /b/{ref}` for `fetch`, `POST /i` for `insert`),
so a pass minted for one route cannot be replayed on the other. It names a *route*, never a
ref or a corpus: the relay still checks no entitlement.

The relay is configured with the issuer's *public* key and its own relay id; it never sees
a private key, an owner, a device id or a ref in the credential. What the issuer learns at
mint time is "some device asked for a batch" - and under Tor it does not learn the device's
address either.
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

TOKEN_SIGIL = "bcred1"
# The only credential shape this build admits. A future Form T token is `typ: "T"` and
# verifies on a different path (a spent-set, not a counted window), so a relay can refuse
# an unknown typ rather than mis-verify it.
FORM_D = "D"
# The relay surfaces a pass may open. `op` names a route, never a ref or a corpus.
#
# `fetch` is the original single read op and still opens every read route, because the
# deployed clients present it. The two role ops are the close-out shape (plan2 §5): a
# discovery pass opens `/h/` and the index pages, a playback pass opens `/w`, and neither
# opens the other. A relay only asks for them when it is started with role passes required,
# so the split can be minted and handed over before a client has to present it.
OP_FETCH = "fetch"
OP_INSERT = "insert"
OP_DISCOVERY = "discovery"
OP_PLAYBACK = "playback"
OPS = (OP_FETCH, OP_INSERT, OP_DISCOVERY, OP_PLAYBACK)


def b64u(raw: bytes) -> str:
    """base64url with no padding: the one encoding every field of a token uses."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    """Inverse of :func:`b64u`; refuses anything that is not base64url.

    Padding is restored rather than required, because `b64u` strips it - a token that
    round-trips through a header must not depend on the transport preserving `=`.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("empty field")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except Exception as exc:  # noqa: BLE001 - a decode failure is a malformed credential
        raise ValueError("not base64url") from exc


def payload_bytes(claims: dict[str, Any]) -> bytes:
    """The exact bytes a signature covers: compact, UTF-8, sorted keys.

    Deterministic so a second implementation (the issuer is a company service, the relay
    is an operator's daemon) signs and verifies the same bytes. `sort_keys` removes any
    dependence on insertion order; `separators` removes the whitespace `json.dumps` adds.
    """
    return json.dumps(claims, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=True).encode("utf-8")


class DoorIssuer:
    """The company-side mint. Holds the signing key; issues credentials to devices.

    A *test or provisioning* helper: the production issuer is a company service reached
    over the anonymising transport. It lives here because the relay's verifier and this
    minter are one wire contract, and a contract with one implementation is not testable.
    """

    def __init__(self, *, token_window: int = 60, window_block_count: int = 8,
                 seed: bytes | None = None) -> None:
        # A relay pins this key in `--issuer-key` (C6, offline-verifiable), so the issuer's
        # key must persist across restarts: a fresh key orphaning every pass already in the
        # field is a deploy fault. `seed` (32 raw bytes) makes it deterministic; without one
        # it is a fresh test key, which is right for tests and wrong for a deployment.
        if seed is None:
            self._private = Ed25519PrivateKey.generate()
        else:
            if len(seed) != 32:
                raise ValueError("door issuer seed must be 32 bytes")
            self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.token_window = max(1, int(token_window))
        self.window_block_count = max(1, int(window_block_count))

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private.public_key()

    def public_hex(self) -> str:
        """The issuer's public key as raw hex: what a relay is configured with."""
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def mint(self, *, op: str = OP_FETCH, relay: str = "*", epoch: int = 0,
             pseudonym: str | None = None, ttl: int | None = None,
             window: int | None = None, now: float | None = None) -> str:
        """Countersign a device pseudonym. The caller supplies or omits the pseudonym.

        `op` is the route the pass opens (`fetch`/`insert`). `relay` scopes the token to one
        relay id, or `"*"` for any. `epoch` and the window length together are the token's
        lifetime; a device that is handed a fresh batch at refill gets a fresh pseudonym,
        which is what bounds Form D's clustering.

        `window` is the fetch/insert budget the token carries (`win`). It falls back to the
        issuer's configured default, but a caller that is reproducing an existing credential
        - renewal is the one - passes the presented value, so the successor is the same
        credential and not one with a different budget.
        """
        if op not in OPS:
            raise ValueError("unknown operation")
        nowv = time.time() if now is None else float(now)
        iat = int(nowv)
        exp = iat + int(self.token_window if ttl is None else max(1, ttl))
        claims = {
            "v": 1,
            "typ": FORM_D,
            "op": op,
            "psn": pseudonym or b64u(secrets.token_bytes(16)),
            "iat": iat,
            "exp": exp,
            "relay": str(relay),
            "epoch": int(epoch),
            "win": int(self.window_block_count if window is None else max(1, window)),
        }
        # The signature covers the payload's *base64url ASCII*, which is what the relay
        # re-verifies byte-for-byte. Signing the raw JSON would work too, but then the two
        # parties must agree on a decode path; signing the embedded text removes that gap.
        body_text = b64u(payload_bytes(claims))
        signature = self._private.sign(body_text.encode("ascii"))
        return f"{TOKEN_SIGIL}.{body_text}.{b64u(signature)}"


class DoorToken:
    """A parsed, verified-as-shape credential. Does not itself prove the signature."""

    __slots__ = ("claims", "op", "pseudonym", "relay", "epoch", "window", "iat", "exp")

    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims
        self.op = str(claims["op"])
        self.pseudonym = str(claims["psn"])
        self.relay = str(claims["relay"])
        self.epoch = int(claims["epoch"])
        self.window = int(claims["win"])
        self.iat = int(claims["iat"])
        self.exp = int(claims["exp"])

    def expired(self, *, now: float | None = None) -> bool:
        nowv = time.time() if now is None else float(now)
        return nowv > self.exp

    def before_validity(self, *, now: float | None = None) -> bool:
        nowv = time.time() if now is None else float(now)
        return nowv + 300.0 < self.iat  # 300 s of clock skew, matching the issuer's


def split_token(presented: str) -> tuple[str, bytes, dict[str, Any]]:
    """Split one header value into `(payload_text, signature, claims)`.

    The payload is verified over the exact text that was embedded, not a re-serialization:
    a token whose JSON re-serializes differently under a different encoder would otherwise
    verify against a signature it never had. The signature is over the *ASCII base64url* of
    the payload, so the bytes the issuer signs are transport-stable.
    """
    if not isinstance(presented, str):
        raise ValueError("no credential")
    parts = presented.strip().split(".")
    if len(parts) != 3 or parts[0] != TOKEN_SIGIL:
        raise ValueError("malformed credential")
    body_text = parts[1]
    try:
        claims = json.loads(unb64u(body_text))
    except (ValueError, UnicodeDecodeError, UnicodeError) as exc:
        raise ValueError("malformed credential") from exc
    if not isinstance(claims, dict):
        raise ValueError("malformed credential")
    return body_text, unb64u(parts[2]), claims


def parse_token(presented: str) -> DoorToken:
    """Parse and shape-check a credential. Raises `ValueError` on anything malformed."""
    _text, _signature, claims = split_token(presented)
    for field in ("v", "typ", "op", "psn", "iat", "exp", "relay", "epoch", "win"):
        if field not in claims:
            raise ValueError("credential is missing a field")
    if claims["v"] != 1 or claims["typ"] != FORM_D:
        raise ValueError("unsupported credential form")
    if claims["op"] not in OPS:
        raise ValueError("credential names an unknown operation")
    if not isinstance(claims["psn"], str) or not claims["psn"]:
        raise ValueError("credential has no pseudonym")
    if len(claims["psn"]) > 128:
        raise ValueError("pseudonym too long")
    if not isinstance(claims["iat"], int) or not isinstance(claims["exp"], int):
        raise ValueError("credential times are not integers")
    if claims["exp"] <= claims["iat"]:
        raise ValueError("credential window is empty")
    if not isinstance(claims["win"], int) or claims["win"] < 1:
        raise ValueError("credential window is not a count")
    return DoorToken(claims)


class DoorGate:
    """Verify a presented credential offline, and meter it without naming anyone.

    The gate holds the issuer's pinned public key (C6, no request-path call home), the
    relay's own id (so a token minted for another relay is refused), and a bounded ledger
    of spent windows keyed by **pseudonym + epoch + window index** - counters, never a
    ref-to-anything map. The ledger is the relay's own abuse accounting; it is not shared
    across the pool and is not persisted.
    """

    def __init__(self, issuer_public: Ed25519PublicKey, *, relay_id: str = "*",
                 ledger_entries: int = 65536) -> None:
        self._public = issuer_public
        self.relay_id = str(relay_id)
        self._ledger_entries = max(64, int(ledger_entries))
        self._spent: dict[tuple[str, int, int], int] = {}
        self._lock = threading.Lock()

    def _signature_ok(self, body: bytes, signature: bytes) -> bool:
        try:
            self._public.verify(signature, body)
            return True
        except (InvalidSignature, ValueError):
            return False

    def admits(self, presented: str, *, op: str, now: float | None = None) -> tuple[DoorToken | None, str]:
        """Return `(token, "ok")` or `(None, refusal)` for one presented credential.

        `op` is the route being asked for: a `fetch` pass presented on `/i`, or the reverse,
        is refused, so a pass cannot cross surfaces. Refusal codes are the relay's own, and
        carry nothing derived from the credential: a client tells "no credential" from
        "that credential is spent" from "wrong relay" and nothing more.
        """
        if op not in OPS:
            raise ValueError("unknown operation")
        try:
            body_text, signature, _claims = split_token(presented)
        except ValueError:
            return None, "credential-missing"
        # Shape first, then signature, so a malformed token never reaches the key op.
        try:
            token = parse_token(presented)
        except (ValueError, UnicodeDecodeError):
            return None, "credential-malformed"
        if not self._signature_ok(body_text.encode("ascii"), signature):
            return None, "credential-invalid"
        if self.relay_id != "*" and token.relay not in (self.relay_id, "*"):
            return None, "credential-wrong-relay"
        if token.op != op:
            return None, "credential-wrong-operation"
        if token.before_validity(now=now):
            return None, "credential-not-yet-valid"
        if token.expired(now=now):
            return None, "credential-expired"
        return token, "ok"

    def spend_window(self, token: DoorToken, *, units: int = 1,
                     now: float | None = None) -> bool:
        """Take `units` blocks from the token's window. False when it cannot pay.

        The key is the pseudonym and the epoch, not the ref: the ledger can never say
        which object a window fetched, only that this pseudonym's window is used up.
        `units` is the *cost* of the request and it is all-or-nothing: a request that
        cannot pay its whole cost is refused and spends nothing. Charging a four-unit
        window one unit at a time would let a pass with three units left admit it and
        then fail half-spent, which is a metering lie and makes a caller pay for a
        refusal.
        """
        cost = max(1, int(units))
        nowv = time.time() if now is None else float(now)
        # The window index is time-derived (how long since the token was minted), and the
        # budget per window is the token's `win` claim. So a token buys `win` fetches per
        # window period, and a device that fetches slowly is not punished for a long token.
        window_index = int((nowv - token.iat) // max(1, token.window))
        key = (token.pseudonym, int(token.epoch), window_index)
        with self._lock:
            used = self._spent.get(key, 0)
            if used + cost > max(1, token.window):
                return False
            self._spent[key] = used + cost
            if len(self._spent) > self._ledger_entries:
                # Oldest-first eviction, so the ledger is bounded by configuration rather
                # than by request volume. An evicted window simply re-admits; the ledger is
                # an abuse brake, not an authority.
                for stale in list(self._spent)[: len(self._spent) - self._ledger_entries]:
                    self._spent.pop(stale, None)
            return True

    def ledger_size(self) -> int:
        with self._lock:
            return len(self._spent)
