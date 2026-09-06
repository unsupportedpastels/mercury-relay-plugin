"""Routing-admission tokens for the hosted relay (Phase 0 static issuer).

The Cloudflare Worker admits a WebSocket to an installation's relay routes
only with a short-lived signed routing token (security review MR-01). The
token format is fixed here and verified statelessly at the Worker edge; the
Phase 0 "control plane" is degenerate — this plugin holds the static Ed25519
issuer key and mints its own tokens — but the format is what the future
entitlement service will issue, so it can slot in behind the same Worker
verification without a protocol change.

Tokens are routing admission only. They gate access to the hosted router;
they are never an application credential — Noise remains the end-to-end
authentication layer, and the host stays the sole pairing authority.

Format: ``b64url(header) . b64url(claims) . b64url(signature)`` with an
Ed25519 signature over the ASCII bytes of ``header.claims``.

Header (exact): ``{"alg":"EdDSA","typ":"mrt1"}``.
Claims: ``aud`` (fixed), ``role`` (``host`` | ``pairing_device`` |
``authorized_device``), ``inst`` (the 43-character installation route),
``iat``/``exp`` (seconds), ``jti`` (random 16 bytes, URL-safe base64),
``pk`` (this issuer's 32-byte public key, URL-safe base64).

Machine ID (interim allowlist entitlement): the Worker admits a token whose
``pk`` is not its static issuer key only when the *machine ID* derived from
the installation route and ``pk`` is on the owner-managed allowlist. The ID
is ``MR-`` plus 24 base32 characters (grouped in fours) of the first 15
bytes of ``SHA-256(domain || route || pk)`` over the ASCII base64 forms, so
an allowlisted key admits exactly one installation. The owner copies it from
the plugin UI and pastes it into the relay operations console.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .identity import (
    IdentityError,
    _b64decode_exact,
    _b64encode,
    _b64url_encode,
    _new_random_bytes,
    _store_for,
    _transaction_lock,
)

TOKEN_AUDIENCE = "mercury-relay"
TOKEN_TYPE = "mrt1"
ROLE_HOST = "host"
ROLE_PAIRING_DEVICE = "pairing_device"
ROLE_AUTHORIZED_DEVICE = "authorized_device"
ROLES = frozenset({ROLE_HOST, ROLE_PAIRING_DEVICE, ROLE_AUTHORIZED_DEVICE})

# Phase 0 lifetimes. The host mints its own token immediately before each
# connect attempt, so its lifetime is short. Pairing tokens ride in the QR
# and match the pairing-offer TTL. Authorized-device tokens are delivered
# over the authenticated Noise channel in the pairing ack; until the
# entitlement service provides an online refresh path, they are long-lived —
# an accepted, documented Phase 0 residual (a revoked device can consume
# router sockets until its token expires, bounded by this lifetime).
HOST_TOKEN_TTL_SECONDS = 600
AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS = 30 * 24 * 3600
MAX_TOKEN_CHARS = 1024
MAX_JTI_CHARS = 64
JTI_BYTES = 16
ISSUER_FIELD = "routing_issuer"
MACHINE_ID_DOMAIN = "mercury-relay-machine-id/v1"
MACHINE_ID_BYTES = 15
PUBLIC_KEY_B64URL_CHARS = 43
_HEADER_JSON = '{"alg":"EdDSA","typ":"mrt1"}'
_HEADER_B64 = _b64url_encode(_HEADER_JSON.encode("ascii"))
# Per-role maximum token lifetimes, in exact parity with the Worker edge's
# MAX_TOKEN_LIFETIME_SECONDS. A token whose exp-iat exceeds its role cap is
# rejected here just as it is at the edge.
MAX_TOKEN_LIFETIME_SECONDS = {
    ROLE_HOST: 3_600,
    ROLE_PAIRING_DEVICE: 900,
    ROLE_AUTHORIZED_DEVICE: 45 * 24 * 3_600,
}


def machine_id(installation_id: bytes, public_key: bytes) -> str:
    """Derive the owner-facing machine ID, in exact parity with the Worker."""

    if not isinstance(installation_id, bytes) or len(installation_id) != 32:
        raise RoutingTokenError("invalid_installation_id")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise RoutingTokenError("invalid_issuer_key")
    route = _b64url_encode(installation_id)
    pk = _b64url_encode(public_key)
    digest = hashlib.sha256(f"{MACHINE_ID_DOMAIN}{route}{pk}".encode("ascii")).digest()
    raw = base64.b32encode(digest[:MACHINE_ID_BYTES]).decode("ascii").rstrip("=")
    return "MR-" + "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


class RoutingTokenError(RuntimeError):
    """One stable routing-token failure without key or transport detail."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class RoutingTokenIssuer:
    """Mint routing tokens with the installation's static Ed25519 issuer key."""

    def __init__(
        self,
        private_key: bytes,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise RoutingTokenError("invalid_issuer_key")
        try:
            self._key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            self._public = self._key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        except Exception:
            raise RoutingTokenError("invalid_issuer_key") from None
        self._clock = clock or time.time

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def public_key_b64url(self) -> str:
        """The value the owner configures as the Worker's issuer public key."""

        return _b64url_encode(self._public)

    def machine_id(self, installation_id: bytes) -> str:
        """The allowlist ID the owner gives the relay operator for this install."""

        return machine_id(installation_id, self._public)

    def mint(self, *, role: str, installation_id: bytes, ttl_seconds: int) -> str:
        if role not in ROLES:
            raise RoutingTokenError("invalid_role")
        if not isinstance(installation_id, bytes) or len(installation_id) != 32:
            raise RoutingTokenError("invalid_installation_id")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1:
            raise RoutingTokenError("invalid_ttl")
        now = int(self._clock())
        claims = {
            "aud": TOKEN_AUDIENCE,
            "role": role,
            "inst": _b64url_encode(installation_id),
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": _b64url_encode(_new_random_bytes(JTI_BYTES)),
            # Names the verifying key so the Worker can admit allowlisted
            # machines without a per-installation static binding.
            "pk": self.public_key_b64url,
        }
        header_b64 = _b64url_encode(_HEADER_JSON.encode("ascii"))
        claims_b64 = _b64url_encode(
            json.dumps(claims, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
                "ascii"
            )
        )
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
        signature = self._key.sign(signing_input)
        token = f"{header_b64}.{claims_b64}.{_b64url_encode(signature)}"
        if len(token) > MAX_TOKEN_CHARS:
            raise RoutingTokenError("token_too_large")
        return token

    def mint_host_token(self, installation_id: bytes) -> str:
        return self.mint(
            role=ROLE_HOST,
            installation_id=installation_id,
            ttl_seconds=HOST_TOKEN_TTL_SECONDS,
        )


def _b64url_decode_loose(segment: str) -> bytes:
    """Decode a URL-safe base64 segment, rejecting non-canonical spellings.

    The Worker's b64urlDecode only accepts the URL-safe alphabet; match that
    exactly here (no `+`/`/`, no whitespace, canonical padding) so the
    reference verifier and the edge agree on which encodings are even valid.
    """

    import re

    if segment == "" or re.fullmatch(r"[A-Za-z0-9_-]+", segment) is None:
        raise RoutingTokenError("invalid_token")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, TypeError):
        raise RoutingTokenError("invalid_token") from None


def verify_routing_token(
    token: str,
    *,
    public_key: bytes,
    installation: str | None = None,
    now: int | None = None,
    skew_seconds: int = 120,
) -> dict[str, Any]:
    """Reference verification, kept in exact parity with the Worker edge.

    The Worker performs the production check; this function mirrors it exactly
    (URL-safe alphabet only, fixed header, role/aud/jti shape, per-role
    lifetime cap, installation binding, skew-bounded validity) so the protocol
    vector suite can prove both implementations accept and reject the same
    tokens. Pass ``installation`` to enforce the route binding the Worker
    always checks.
    """

    if not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN_CHARS:
        raise RoutingTokenError("invalid_token")
    parts = token.split(".")
    if len(parts) != 3:
        raise RoutingTokenError("invalid_token")
    header_b64, claims_b64, signature_b64 = parts
    if header_b64 != _HEADER_B64:
        raise RoutingTokenError("invalid_token")
    claims_raw = _b64url_decode_loose(claims_b64)
    signature = _b64url_decode_loose(signature_b64)
    if len(signature) != 64:
        raise RoutingTokenError("invalid_token")
    try:
        verifier = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        verifier.verify(signature, f"{header_b64}.{claims_b64}".encode("ascii"))
    except (InvalidSignature, ValueError, TypeError):
        raise RoutingTokenError("invalid_signature") from None
    try:
        claims = json.loads(claims_raw)
    except ValueError:
        raise RoutingTokenError("invalid_token") from None
    role = claims.get("role") if isinstance(claims, dict) else None
    if (
        not isinstance(claims, dict)
        or claims.get("aud") != TOKEN_AUDIENCE
        or role not in ROLES
        or not isinstance(claims.get("inst"), str)
        or isinstance(claims.get("iat"), bool)
        or not isinstance(claims.get("iat"), int)
        or isinstance(claims.get("exp"), bool)
        or not isinstance(claims.get("exp"), int)
        or not isinstance(claims.get("jti"), str)
        or not 1 <= len(claims["jti"]) <= MAX_JTI_CHARS
    ):
        raise RoutingTokenError("invalid_claims")
    if installation is not None and claims["inst"] != installation:
        raise RoutingTokenError("invalid_claims")
    if "pk" in claims:
        pk = claims["pk"]
        if not isinstance(pk, str) or len(pk) != PUBLIC_KEY_B64URL_CHARS:
            raise RoutingTokenError("invalid_claims")
        # The Worker verifies with the named key; a token naming a key other
        # than the one it was signed with fails there as a bad signature.
        if _b64url_decode_loose(pk) != public_key:
            raise RoutingTokenError("invalid_signature")
    lifetime = claims["exp"] - claims["iat"]
    if lifetime < 1 or lifetime > MAX_TOKEN_LIFETIME_SECONDS[role]:
        raise RoutingTokenError("invalid_claims")
    moment = int(time.time()) if now is None else now
    if moment < claims["iat"] - skew_seconds or moment >= claims["exp"]:
        raise RoutingTokenError("token_expired")
    return claims


class RoutingIssuerStore:
    """Load or atomically create the profile's one routing issuer key."""

    def __init__(self, source: Any) -> None:
        try:
            self.paths, self.store = _store_for(source)
        except IdentityError:
            raise
        except Exception:
            raise RoutingTokenError("invalid_issuer_store") from None

    def _load_or_create_unlocked(self) -> RoutingTokenIssuer:
        try:
            state = self.store.load()
        except Exception:
            raise RoutingTokenError("issuer_state_invalid") from None
        record = state.get(ISSUER_FIELD)
        if record is not None:
            try:
                private_key = _b64decode_exact(record["private_key"], 32)
                issuer = RoutingTokenIssuer(private_key)
                expected_public = _b64decode_exact(record["public_key"], 32)
            except (RoutingTokenError, KeyError, TypeError, ValueError):
                raise RoutingTokenError("issuer_state_invalid") from None
            if issuer.public_key != expected_public:
                raise RoutingTokenError("issuer_state_invalid")
            return issuer
        private_key = _new_random_bytes(32)
        issuer = RoutingTokenIssuer(private_key)
        updated = copy.deepcopy(state)
        updated[ISSUER_FIELD] = {
            "private_key": _b64encode(private_key),
            "public_key": _b64encode(issuer.public_key),
        }
        try:
            self.store.save(updated)
        except Exception:
            raise RoutingTokenError("issuer_persistence_failed") from None
        return issuer

    def load_or_create(self) -> RoutingTokenIssuer:
        with _transaction_lock(self.paths):
            return self._load_or_create_unlocked()


__all__ = [
    "AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS",
    "HOST_TOKEN_TTL_SECONDS",
    "ISSUER_FIELD",
    "MACHINE_ID_DOMAIN",
    "ROLE_AUTHORIZED_DEVICE",
    "ROLE_HOST",
    "ROLE_PAIRING_DEVICE",
    "ROLES",
    "RoutingIssuerStore",
    "RoutingTokenError",
    "RoutingTokenIssuer",
    "TOKEN_AUDIENCE",
    "machine_id",
    "verify_routing_token",
]
