"""Framework-free management operations behind the authenticated plugin routes.

Every operation is bounded, idempotent where it mutates, and returns only
redacted metadata: no private keys, device public keys, channel bindings,
prior capabilities, Hermes credentials or content, or connection strings ever
leave this module.  The one exception is the pairing-offer create response,
which is the single place the raw QR capability is returned to the explicit
local caller.  Normal Hermes dashboard authentication must protect the routes
that call into this service before any of it executes.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from typing import Any

from .admission import DeviceAdmissionService
from .authorization import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    AuthorizationError,
    DeviceSummary,
)
from .config import load_public_config
from .identity import _b64decode_exact, _b64url_decode_exact
from .session_lease import SessionLeaseError

MAX_BODY_BYTES = 4_096
MAX_IDENTIFIER_TEXT = 128
_DIGEST_BYTES = 32


class ManagementError(RuntimeError):
    """One stable management failure with an HTTP status and no detail."""

    def __init__(self, reason: str, status_code: int) -> None:
        self.reason = reason
        self.status_code = status_code
        super().__init__(reason)


def _require_identifier(value: Any) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_IDENTIFIER_TEXT:
        raise ManagementError("invalid_identifier", 400)
    return value


def _require_device_id(value: Any) -> str:
    """Uniformly treat malformed and unknown device identifiers as not found."""

    _require_identifier(value)
    try:
        _b64url_decode_exact(value, 16)
    except Exception:
        raise ManagementError("device_not_found", 404) from None
    return value


class ManagementService:
    """Bounded management facade over one admission service."""

    def __init__(self, admission: DeviceAdmissionService) -> None:
        if not isinstance(admission, DeviceAdmissionService):
            raise TypeError("admission must be a DeviceAdmissionService")
        self.admission = admission
        self.repository = admission.repository
        self.runtime = admission.runtime
        # The routing issuer key is immutable once created; cache it so
        # offers, diagnostics, and status polls do not each re-acquire the
        # transaction lock, re-read state, and re-derive the Ed25519 key.
        self._issuer: Any | None = None

    def _routing_issuer(self) -> Any | None:
        if self._issuer is None:
            from .routing_auth import RoutingIssuerStore

            self._issuer = RoutingIssuerStore(self.repository.store).load_or_create()
        return self._issuer

    # -- pairing -------------------------------------------------------------

    def create_pairing_offer(self, body: Mapping[str, Any]) -> dict[str, Any]:
        """Create one offer; this response is the only carrier of the raw QR payload."""

        if not isinstance(body, Mapping) or not set(body) <= {"ttl_seconds"}:
            raise ManagementError("invalid_body", 400)
        ttl = body.get("ttl_seconds", DEFAULT_TTL_SECONDS)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= MAX_TTL_SECONDS:
            raise ManagementError("invalid_body", 400)
        try:
            offer = self.repository.create_offer(ttl)
        except AuthorizationError:
            raise ManagementError("pairing_offer_rejected", 409) from None
        result = offer.to_local_dict()
        # The relay origin is public config, not a secret; including it makes
        # the QR payload self-contained for the phone.
        result["relay_origin"] = self._relay_origin()
        result["protocol_major"] = 1
        # Routing admission (MR-01): the QR carries a short-lived
        # pairing-device routing token so the phone can open the relay
        # socket at all. It is scoped to this installation, expires with
        # the offer, and is not an application credential — the Noise
        # handshake and the one-time capability still gate pairing.
        result["pairing_token"] = self._mint_pairing_token(ttl)
        # Build the QR server-side so the dashboard page and the desktop plugin
        # render one identical QR with no client-side QR library. The SVG (like
        # the capability it encodes) is only ever in this create response.
        from .pairing_qr import pairing_payload_text, pairing_qr_svg

        result["pairing_payload"] = pairing_payload_text(result)
        try:
            result["qr_svg"] = pairing_qr_svg(result)
        except Exception:
            # BR-07: never return a successful offer the UI cannot render.
            # The capability was already exposed in this response path, so
            # invalidate the offer; the owner simply presses "New QR" again.
            with suppress(AuthorizationError):
                self.repository.cancel_offer(offer.offer_id)
            raise ManagementError("qr_render_failed", 500) from None
        return result

    def _mint_pairing_token(self, ttl_seconds: int) -> str | None:
        from .routing_auth import ROLE_PAIRING_DEVICE

        try:
            issuer = self._routing_issuer()
            identity = self.repository.identity_store.load_or_create()
            return issuer.mint(
                role=ROLE_PAIRING_DEVICE,
                installation_id=identity.installation_id,
                ttl_seconds=ttl_seconds,
            )
        except Exception:
            # An offer without a routing token still pairs against a relay
            # that has not enabled routing admission; the phone surfaces the
            # authenticated relay's rejection otherwise.
            return None

    def routing_issuer_public_key(self) -> str | None:
        """The value the owner binds as the Worker's issuer public key."""

        try:
            return self._routing_issuer().public_key_b64url
        except Exception:
            return None

    def relay_machine_id(self) -> str | None:
        """The allowlist ID the owner pastes into the relay operations console."""

        try:
            identity = self.repository.identity_store.load_or_create()
            return self._routing_issuer().machine_id(identity.installation_id)
        except Exception:
            return None

    def _relay_origin(self) -> str | None:
        try:
            return load_public_config(self.repository.paths).get("relay_origin")
        except Exception:
            return None

    def pairing_offer_status(self, offer_id: str) -> dict[str, Any]:
        _require_identifier(offer_id)
        try:
            status = self.repository.offer_status()
        except AuthorizationError:
            raise ManagementError("management_unavailable", 503) from None
        if status is None or status["offer_id"] != offer_id:
            raise ManagementError("offer_not_found", 404)
        return status

    # -- devices -------------------------------------------------------------

    def _device_list(self) -> list[DeviceSummary]:
        try:
            return self.repository.list_devices()
        except AuthorizationError:
            raise ManagementError("management_unavailable", 503) from None

    def devices(self) -> dict[str, Any]:
        return {"devices": [summary.to_dict() for summary in self._device_list()]}

    def pending_devices(self) -> dict[str, Any]:
        return {
            "devices": [
                summary.to_dict() for summary in self._device_list() if summary.status == "pending"
            ]
        }

    def approve_device(self, device_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """Approve one pending device after the operator confirmed its SAS.

        The dashboard shows the pending device's fingerprint and the phone
        shows the fingerprint it derived from its own side of the handshake.
        The operator compares them and, on a match, approves — echoing back
        the exact fingerprint they confirmed. The MITM protection is that
        human comparison; requiring the echoed fingerprint keeps a stale row
        or the wrong device from being approved by a blind click.

        A caller that independently holds the full 32-byte channel-binding
        digest (the mobile/Desktop-crypto path) may pass it instead.
        """

        _require_device_id(device_id)
        if not isinstance(body, Mapping):
            raise ManagementError("invalid_body", 400)
        if set(body) == {"confirmed_fingerprint"}:
            fingerprint = body["confirmed_fingerprint"]
            if not isinstance(fingerprint, str) or len(fingerprint) > 64:
                raise ManagementError("invalid_body", 400)
            try:
                summary = self.repository.approve_confirmed(device_id, fingerprint)
            except AuthorizationError:
                raise ManagementError("approval_rejected", 403) from None
            self.admission.refresh_registered_devices()
            return summary.to_dict()
        if set(body) == {"channel_binding_digest"}:
            try:
                digest = _b64decode_exact(body["channel_binding_digest"], _DIGEST_BYTES)
            except Exception:
                raise ManagementError("invalid_body", 400) from None
            try:
                summary = self.repository.approve(device_id, digest)
            except AuthorizationError:
                raise ManagementError("approval_rejected", 403) from None
            self.admission.refresh_registered_devices()
            return summary.to_dict()
        raise ManagementError("invalid_body", 400)

    def label_device(self, device_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        """Set or clear the owner's nickname for a device."""

        _require_device_id(device_id)
        if not isinstance(body, Mapping) or set(body) != {"label"}:
            raise ManagementError("invalid_body", 400)
        label = body["label"]
        if not isinstance(label, str) or len(label) > 256:
            raise ManagementError("invalid_body", 400)
        try:
            summary = self.repository.set_label(device_id, label)
        except AuthorizationError:
            raise ManagementError("invalid_body", 400) from None
        if summary is None:
            raise ManagementError("device_not_found", 404)
        return summary.to_dict()

    def deny_device(self, device_id: str) -> dict[str, Any]:
        _require_device_id(device_id)
        try:
            summary = self.repository.deny(device_id)
        except AuthorizationError:
            raise ManagementError("deny_rejected", 409) from None
        if summary is None:
            raise ManagementError("device_not_found", 404)
        return summary.to_dict()

    async def revoke_device(self, device_id: str) -> dict[str, Any]:
        """Revoke authorization and release any live lease immediately."""

        _require_device_id(device_id)
        try:
            summary = await self.admission.revoke_device(device_id)
        except (AuthorizationError, SessionLeaseError):
            raise ManagementError("revoke_rejected", 409) from None
        except Exception:
            raise ManagementError("revoke_rejected", 409) from None
        if summary is None:
            raise ManagementError("device_not_found", 404)
        return summary.to_dict()

    # -- observability -------------------------------------------------------

    def diagnostics(self) -> dict[str, Any]:
        """Coarse counters plus a sanitized owner-private connection journal."""

        counts = {"total": 0, "pending": 0, "authorized": 0, "revoked": 0, "denied": 0}
        for summary in self._device_list():
            counts["total"] += 1
            if summary.status in counts:
                counts[summary.status] += 1
        try:
            offer = self.repository.offer_status()
        except AuthorizationError:
            offer = None
        return {
            "runtime": self.runtime.snapshot(),
            "devices": counts,
            "active_leases": self.admission.leases.active_count,
            "pairing_offer_status": offer["status"] if offer else "none",
            "relay_origin_configured": self._relay_origin() is not None,
            # Public key only; the owner copies this into the Worker's
            # ROUTING_ISSUER_PUBLIC_KEY binding.
            "routing_issuer_public_key": self.routing_issuer_public_key(),
            # Machine ID: a hash over the installation route and issuer
            # public key. Not a secret; it only ever admits this installation.
            "relay_machine_id": self.relay_machine_id(),
            "operations": self.admission.metrics.snapshot()
            if self.admission.metrics is not None
            else None,
            "connection_journal": self.admission.journal.export()
            if self.admission.journal is not None
            else None,
        }


__all__ = ["MAX_BODY_BYTES", "ManagementError", "ManagementService"]
