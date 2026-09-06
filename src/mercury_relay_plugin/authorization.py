"""Single-device pairing and local authorization state.

This module implements only the Phase-1 local repository boundary.  It does
not perform a Noise handshake or network operation. Raw pairing capabilities are
never persisted; public device keys and channel-binding digests stay inside the
private state store. Callers receive only the one explicit local offer
capability and redacted metadata thereafter.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .config import ProfilePaths
from .identity import (
    RAW_BYTES,
    HostIdentityStore,
    IdentityError,
    _b64decode_exact,
    _b64encode,
    _b64url_decode_exact,
    _b64url_encode,
    _coerce_paths,
    _new_random_bytes,
    _transaction_lock,
)
from .state_store import StateStore, StateStoreError

MAX_TTL_SECONDS = 600
DEFAULT_TTL_SECONDS = 300
MAX_DEVICE_RECORDS = 16
# Paired phones/tablets allowed at once (pending + authorized). The hosted
# router multiplexes device sockets and the host holds one lease per
# (device, channel), so devices and their sessions run concurrently.
MAX_ACTIVE_DEVICES = 5
DEVICE_ID_BYTES = 16
PAIRING_OFFER_ID_BYTES = 16
MAX_DEVICE_ID_TEXT = 128
_CONSTRUCTOR_TOKEN = object()

_PAIRING_STATUSES = frozenset({"active", "expired", "consumed"})
_DEVICE_STATUSES = frozenset({"pending", "authorized", "revoked", "denied"})
_PAIRING_FIELDS = frozenset(
    {
        "offer_id",
        "capability_digest",
        "installation_id",
        "host_public_key",
        "created_at",
        "expires_at",
        "status",
        "consumed_at",
    }
)
_DEVICE_FIELDS = frozenset(
    {
        "device_id",
        "device_public_key",
        "channel_binding_digest",
        "status",
        "created_at",
        "updated_at",
        "epoch",
        "capabilities",
    }
)
# Optional, owner-visible metadata. device_name is what the phone reported in
# its admission envelope; label is the nickname set on the dashboard. Neither
# affects authorization, epochs, or key material.
_OPTIONAL_DEVICE_FIELDS = frozenset({"device_name", "label"})
MAX_DEVICE_NAME_CHARS = 64


def _clean_device_text(value: object) -> str | None:
    """Bounded, control-free display text; None when unusable."""

    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > MAX_DEVICE_NAME_CHARS:
        return None
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in cleaned):
        return None
    return cleaned


class AuthorizationError(IdentityError):
    """Raised for invalid or unavailable local authorization state."""


class PairingRejected(AuthorizationError):
    """One stable, deliberately non-oracular pairing rejection."""

    def __init__(self) -> None:
        super().__init__("pairing rejected")


@dataclass(frozen=True, slots=True)
class DeviceSummary:
    """Safe device metadata; no key, digest, or channel binding is included."""

    device_id: str
    status: str
    fingerprint: str
    created_at: int
    updated_at: int
    epoch: int
    capabilities: tuple[str, ...]
    device_name: str = ""
    label: str = ""

    @property
    def display_name(self) -> str:
        """Owner nickname, else the phone's own name, else the fingerprint."""

        return self.label or self.device_name or self.fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "status": self.status,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "epoch": self.epoch,
            "capabilities": list(self.capabilities),
            "device_name": self.device_name,
            "label": self.label,
            "display_name": self.display_name,
        }

    def __getitem__(self, key: str) -> Any:
        """Allow safe summaries to be consumed by small mapping-style callers."""

        return self.to_dict()[key]


class PairingOffer:
    """The local one-time offer, with capability hidden from repr/log output."""

    __slots__ = (
        "offer_id",
        "installation_id",
        "host_public_key",
        "expires_at",
        "_capability",
    )

    def __init__(
        self,
        *,
        offer_id: str,
        installation_id: bytes,
        host_public_key: bytes,
        expires_at: int,
        capability: bytes,
        _token: object | None = None,
    ) -> None:
        if _token is not _CONSTRUCTOR_TOKEN:
            raise TypeError("pairing offer construction is private")
        if (
            not isinstance(offer_id, str)
            or not isinstance(installation_id, bytes)
            or len(installation_id) != RAW_BYTES
            or not isinstance(host_public_key, bytes)
            or len(host_public_key) != RAW_BYTES
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or not isinstance(capability, bytes)
            or len(capability) != RAW_BYTES
        ):
            raise AuthorizationError("pairing offer unavailable")
        self.offer_id = offer_id
        self.installation_id = bytes(installation_id)
        self.host_public_key = bytes(host_public_key)
        self.expires_at = expires_at
        self._capability = bytes(capability)

    @property
    def capability(self) -> bytes:
        """Return the capability to the explicit local caller of create_offer."""

        return self._capability

    @property
    def capability_b64(self) -> str:
        """Return an explicit canonical encoding for local QR construction."""

        return _b64encode(self._capability)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "offer_id": self.offer_id,
            "installation_id": _b64encode(self.installation_id),
            "host_public_key": _b64encode(self.host_public_key),
            "expires_at": self.expires_at,
        }

    def to_local_dict(self) -> dict[str, Any]:
        """Explicit caller-only representation; never used for persistence/logging."""

        result = self.to_public_dict()
        result["capability"] = self.capability_b64
        return result

    def __repr__(self) -> str:
        return (
            "PairingOffer("
            f"offer_id={self.offer_id!r}, "
            f"installation_id={_b64encode(self.installation_id)!r}, "
            f"host_public_key={_b64encode(self.host_public_key)!r}, "
            f"expires_at={self.expires_at!r}, capability=<redacted>)"
        )


# Imported here rather than copied so all random identity/authorization bytes
# use the same OS-backed CSPRNG helper and no deterministic production hook.
def _random_bytes(length: int) -> bytes:
    return _new_random_bytes(length)


def _exact_input(value: Any, *, allow_base64_text: bool = False) -> bytes:
    if isinstance(value, bytes):
        if len(value) != RAW_BYTES:
            raise ValueError
        return bytes(value)
    if isinstance(value, (bytearray, memoryview)):
        if len(value) != RAW_BYTES:
            raise ValueError
        return bytes(value)
    if allow_base64_text and isinstance(value, str):
        return _b64decode_exact(value, RAW_BYTES)
    raise ValueError


def _validate_int(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 2**63 - 1:
        raise ValueError


def _validate_auth_state(state: Mapping[str, Any]) -> None:
    if not isinstance(state, Mapping) or state.get("schema_version") != 1:
        raise ValueError
    devices = state.get("devices")
    if not isinstance(devices, list) or len(devices) > MAX_DEVICE_RECORDS:
        raise ValueError
    identifiers: set[str] = set()
    active = 0
    for record in devices:
        if not isinstance(record, Mapping):
            raise ValueError
        if (
            not set(record) >= _DEVICE_FIELDS
            or set(record) - _DEVICE_FIELDS - _OPTIONAL_DEVICE_FIELDS
        ):
            raise ValueError
        for field in _OPTIONAL_DEVICE_FIELDS:
            if field in record and (
                not isinstance(record[field], str)
                or (record[field] != "" and _clean_device_text(record[field]) != record[field])
            ):
                raise ValueError
        device_id = record.get("device_id")
        if (
            not isinstance(device_id, str)
            or not device_id
            or len(device_id) > MAX_DEVICE_ID_TEXT
            or device_id in identifiers
        ):
            raise ValueError
        _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
        identifiers.add(device_id)
        _b64decode_exact(record.get("device_public_key"), RAW_BYTES)
        _b64decode_exact(record.get("channel_binding_digest"), RAW_BYTES)
        status = record.get("status")
        if status not in _DEVICE_STATUSES:
            raise ValueError
        if status in {"pending", "authorized"}:
            active += 1
        for field in ("created_at", "updated_at", "epoch"):
            _validate_int(record.get(field))
        if record["updated_at"] < record["created_at"] or record["epoch"] > 2**31 - 1:
            raise ValueError
        capabilities = record.get("capabilities")
        if not isinstance(capabilities, list) or len(capabilities) > 1:
            raise ValueError
        if any(not isinstance(item, str) or len(item) > 32 for item in capabilities):
            raise ValueError
        expected = ["client"] if status == "authorized" else []
        if capabilities != expected:
            raise ValueError
    if active > MAX_ACTIVE_DEVICES:
        raise ValueError

    if "pairing_offer" not in state:
        return
    offer = state["pairing_offer"]
    if not isinstance(offer, Mapping) or set(offer) != _PAIRING_FIELDS:
        raise ValueError
    _b64url_decode_exact(offer.get("offer_id"), PAIRING_OFFER_ID_BYTES)
    _b64decode_exact(offer.get("capability_digest"), RAW_BYTES)
    _b64decode_exact(offer.get("installation_id"), RAW_BYTES)
    _b64decode_exact(offer.get("host_public_key"), RAW_BYTES)
    _validate_int(offer.get("created_at"))
    _validate_int(offer.get("expires_at"))
    _validate_int(offer.get("consumed_at"))
    if (
        offer["expires_at"] <= offer["created_at"]
        or offer["expires_at"] - offer["created_at"] > MAX_TTL_SECONDS
    ):
        raise ValueError
    if offer.get("status") not in _PAIRING_STATUSES:
        raise ValueError
    if offer["status"] == "consumed" and offer["consumed_at"] == 0:
        raise ValueError
    if offer["status"] != "consumed" and offer["consumed_at"] != 0:
        raise ValueError


def _summary(record: Mapping[str, Any]) -> DeviceSummary:
    digest = _b64decode_exact(record["channel_binding_digest"], RAW_BYTES)
    return DeviceSummary(
        device_id=record["device_id"],
        status=record["status"],
        fingerprint=digest.hex()[:16],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
        epoch=record["epoch"],
        capabilities=tuple(record["capabilities"]),
        device_name=record.get("device_name", ""),
        label=record.get("label", ""),
    )


def _new_identifier(size: int, existing: set[str]) -> str:
    for _ in range(8):
        try:
            identifier = _b64url_encode(_random_bytes(size))
        except IdentityError:
            raise AuthorizationError("random generation failed") from None
        if identifier not in existing:
            return identifier
    raise AuthorizationError("random generation failed")


class AuthorizationRepository:
    """Private, bounded, single-device pairing and authorization repository."""

    def __init__(
        self,
        source: ProfilePaths | StateStore | str,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        try:
            self.paths = _coerce_paths(source)
            if isinstance(source, StateStore):
                self.store = source
            else:
                self.store = StateStore(self.paths)
            self.identity_store = HostIdentityStore(self.store)
        except (AuthorizationError, IdentityError):
            raise
        except Exception:
            raise AuthorizationError("invalid authorization store") from None
        self._clock = clock or time.time
        if not callable(self._clock):
            raise AuthorizationError("invalid authorization clock")

    def _now(self) -> int:
        try:
            value = int(self._clock())
        except Exception:
            raise AuthorizationError("authorization time unavailable") from None
        if value < 0 or value > 2**63 - 1:
            raise AuthorizationError("authorization time unavailable")
        return value

    def _load_state_unlocked(self) -> dict[str, Any]:
        try:
            state = self.store.load()
            _validate_auth_state(state)
            return state
        except (StateStoreError, ValueError, TypeError, KeyError):
            raise AuthorizationError("authorization state invalid") from None
        except Exception:
            raise AuthorizationError("authorization state invalid") from None

    def _save_state_unlocked(self, state: Mapping[str, Any]) -> None:
        try:
            _validate_auth_state(state)
            self.store.save(state)
        except (StateStoreError, ValueError, TypeError, KeyError):
            raise AuthorizationError("authorization state unavailable") from None
        except Exception:
            raise AuthorizationError("authorization state unavailable") from None

    def _expire_pending_in_state(
        self, state: dict[str, Any], now: int, max_age_seconds: int = MAX_TTL_SECONDS
    ) -> list[DeviceSummary]:
        """Deny timed-out pending records in place; caller persists if needed.

        Pending records count against the active-device limit, so a stalled
        or abandoned pairing must not hold a slot forever (BR-04). Expiry is
        applied at every deterministic lifecycle point that reads the device
        list under the transaction lock.
        """

        changed: list[DeviceSummary] = []
        for index, record in enumerate(state["devices"]):
            if record["status"] == "pending" and now - record["created_at"] >= max_age_seconds:
                updated = dict(record)
                updated["status"] = "denied"
                updated["updated_at"] = now
                updated["epoch"] += 1
                state["devices"][index] = updated
                changed.append(_summary(updated))
        return changed

    def create_offer(self, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> PairingOffer:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or ttl_seconds < 1
            or ttl_seconds > MAX_TTL_SECONDS
        ):
            raise AuthorizationError("invalid pairing TTL")
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            identity = self.identity_store.load_or_create_unlocked()
            state = self._load_state_unlocked()
            now = self._now()
            self._expire_pending_in_state(state, now)
            existing = state.get("pairing_offer")
            if existing is not None and existing["status"] == "active":
                if now < existing["expires_at"]:
                    raise AuthorizationError("pairing offer already active")
                expired = dict(existing)
                expired["status"] = "expired"
                state["pairing_offer"] = expired
            offer_id = _new_identifier(
                PAIRING_OFFER_ID_BYTES,
                {state.get("pairing_offer", {}).get("offer_id", "")},
            )
            try:
                capability = _random_bytes(RAW_BYTES)
            except IdentityError:
                raise AuthorizationError("random generation failed") from None
            expires_at = now + ttl_seconds
            state["pairing_offer"] = {
                "offer_id": offer_id,
                "capability_digest": _b64encode(hashlib.sha256(capability).digest()),
                "installation_id": _b64encode(identity.installation_id),
                "host_public_key": _b64encode(identity.public_key),
                "created_at": now,
                "expires_at": expires_at,
                "status": "active",
                "consumed_at": 0,
            }
            self._save_state_unlocked(state)
            return PairingOffer(
                offer_id=offer_id,
                installation_id=identity.installation_id,
                host_public_key=identity.public_key,
                expires_at=expires_at,
                capability=capability,
                _token=_CONSTRUCTOR_TOKEN,
            )

    def consume_offer(
        self,
        capability: bytes,
        device_public_key: bytes,
        channel_binding: bytes,
    ) -> DeviceSummary:
        try:
            capability_bytes = _exact_input(capability)
            public_key = _exact_input(device_public_key)
            binding = _exact_input(channel_binding)
        except (TypeError, ValueError):
            raise PairingRejected() from None
        capability_digest = hashlib.sha256(capability_bytes).digest()
        binding_digest = hashlib.sha256(binding).digest()
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            identity = self.identity_store.load_or_create_unlocked()
            state = self._load_state_unlocked()
            offer = state.get("pairing_offer")
            if not isinstance(offer, Mapping):
                raise PairingRejected()
            try:
                persisted_digest = _b64decode_exact(offer["capability_digest"], RAW_BYTES)
                persisted_installation = _b64decode_exact(offer["installation_id"], RAW_BYTES)
                persisted_host_key = _b64decode_exact(offer["host_public_key"], RAW_BYTES)
            except (KeyError, TypeError, ValueError):
                raise AuthorizationError("authorization state invalid") from None
            digest_matches = hmac.compare_digest(capability_digest, persisted_digest)
            identity_matches = hmac.compare_digest(identity.installation_id, persisted_installation)
            identity_matches = identity_matches and hmac.compare_digest(
                identity.public_key, persisted_host_key
            )
            now = self._now()
            usable = offer.get("status") == "active" and now < offer.get("expires_at", 0)
            if not (digest_matches and identity_matches and usable):
                if offer.get("status") == "active" and now >= offer.get("expires_at", 0):
                    expired = dict(offer)
                    expired["status"] = "expired"
                    state["pairing_offer"] = expired
                    self._save_state_unlocked(state)
                raise PairingRejected()

            # BR-04: timed-out pending records must not consume active slots.
            self._expire_pending_in_state(state, now)
            # BR-05: denied tombstones must never permanently brick pairing.
            # Prune the oldest denied records to stay under the record cap;
            # revoked records are retained as revocation evidence so a revoked
            # key can never silently re-pair.
            if len(state["devices"]) >= MAX_DEVICE_RECORDS:
                denied = sorted(
                    (record for record in state["devices"] if record["status"] == "denied"),
                    key=lambda record: (record["updated_at"], record["device_id"]),
                )
                overflow = len(state["devices"]) - MAX_DEVICE_RECORDS + 1
                pruned_ids = {record["device_id"] for record in denied[:overflow]}
                state["devices"] = [
                    record for record in state["devices"] if record["device_id"] not in pruned_ids
                ]

            active_count = sum(
                1 for record in state["devices"] if record["status"] in {"pending", "authorized"}
            )
            revoked_key = False
            for record in state["devices"]:
                revoked_key = revoked_key or (
                    record["status"] == "revoked"
                    and hmac.compare_digest(
                        _b64decode_exact(record["device_public_key"], RAW_BYTES), public_key
                    )
                )
            if (
                active_count >= MAX_ACTIVE_DEVICES
                or revoked_key
                or len(state["devices"]) >= MAX_DEVICE_RECORDS
            ):
                raise PairingRejected()
            device_id = _new_identifier(
                DEVICE_ID_BYTES, {record["device_id"] for record in state["devices"]}
            )
            record = {
                "device_id": device_id,
                "device_public_key": _b64encode(public_key),
                "channel_binding_digest": _b64encode(binding_digest),
                "status": "pending",
                "created_at": now,
                "updated_at": now,
                "epoch": 0,
                "capabilities": [],
            }
            consumed = dict(offer)
            consumed["status"] = "consumed"
            consumed["consumed_at"] = now
            state["pairing_offer"] = consumed
            state["devices"].append(record)
            self._save_state_unlocked(state)
            return _summary(record)

    def approve(
        self,
        device_id: str,
        channel_binding_digest: bytes,
    ) -> DeviceSummary:
        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
            supplied_digest = _exact_input(channel_binding_digest)
        except (TypeError, ValueError):
            raise AuthorizationError("approval rejected") from None
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            # Deny timed-out pending records first so a stale pending device
            # cannot be approved (its record is already denied below).
            if self._expire_pending_in_state(state, self._now()):
                self._save_state_unlocked(state)
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if record is None:
                raise AuthorizationError("approval rejected")
            try:
                expected_digest = _b64decode_exact(record["channel_binding_digest"], RAW_BYTES)
            except (TypeError, ValueError):
                raise AuthorizationError("authorization state invalid") from None
            matches = hmac.compare_digest(supplied_digest, expected_digest)
            if not matches or record["status"] not in {"pending", "authorized"}:
                raise AuthorizationError("approval rejected")
            if record["status"] == "authorized":
                return _summary(record)
            updated = dict(record)
            updated["status"] = "authorized"
            updated["updated_at"] = self._now()
            updated["capabilities"] = ["client"]
            index = state["devices"].index(record)
            state["devices"][index] = updated
            self._save_state_unlocked(state)
            return _summary(updated)

    def approve_confirmed(
        self,
        device_id: str,
        confirmed_fingerprint: str,
    ) -> DeviceSummary:
        """Approve after an operator confirmed the SAS fingerprint.

        The transcript-bound short authentication string (the fingerprint) is
        what the operator compares between the phone and this host; a match
        proves no MITM sits on the pairing channel.  This path does not
        require the caller to hold the full binding digest — a thin management
        UI never has it — but it does require the operator to echo back the
        exact fingerprint they compared, so a stale list row or the wrong
        device can never be approved by a blind gesture.
        """

        if not isinstance(confirmed_fingerprint, str):
            raise AuthorizationError("approval rejected")
        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
        except (TypeError, ValueError):
            raise AuthorizationError("approval rejected") from None
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            # Deny timed-out pending records first so a stale pending device
            # cannot be approved by a confirmed fingerprint either.
            if self._expire_pending_in_state(state, self._now()):
                self._save_state_unlocked(state)
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if record is None:
                raise AuthorizationError("approval rejected")
            summary = _summary(record)
            if not hmac.compare_digest(confirmed_fingerprint, summary.fingerprint):
                raise AuthorizationError("approval rejected")
            if record["status"] == "authorized":
                return summary
            if record["status"] != "pending":
                raise AuthorizationError("approval rejected")
            updated = dict(record)
            updated["status"] = "authorized"
            updated["updated_at"] = self._now()
            updated["capabilities"] = ["client"]
            index = state["devices"].index(record)
            state["devices"][index] = updated
            self._save_state_unlocked(state)
            return _summary(updated)

    def set_label(self, device_id: str, label: str) -> DeviceSummary | None:
        """Owner nickname for a device; empty clears it. No epoch change."""

        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
        except (TypeError, ValueError):
            raise AuthorizationError("invalid device identifier") from None
        cleaned = "" if label == "" else _clean_device_text(label)
        if cleaned is None:
            raise AuthorizationError("invalid label")
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if record is None:
                return None
            updated = dict(record)
            updated["label"] = cleaned
            index = state["devices"].index(record)
            state["devices"][index] = updated
            self._save_state_unlocked(state)
            return _summary(updated)

    def note_device_name(self, device_id: str, device_public_key: bytes, name: object) -> bool:
        """Record the name a phone reports about itself in its admission envelope.

        Only the record whose static key matches the authenticated channel may
        be named, for pending or authorized devices; anything else is ignored.
        """

        cleaned = _clean_device_text(name)
        if cleaned is None:
            return False
        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
            public_key = _exact_input(device_public_key)
        except (TypeError, ValueError):
            return False
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if record is None or record["status"] not in {"pending", "authorized"}:
                return False
            if not hmac.compare_digest(
                _b64decode_exact(record["device_public_key"], RAW_BYTES), public_key
            ):
                return False
            if record.get("device_name", "") == cleaned:
                return True
            updated = dict(record)
            updated["device_name"] = cleaned
            index = state["devices"].index(record)
            state["devices"][index] = updated
            self._save_state_unlocked(state)
            return True

    def deny(self, device_id: str) -> DeviceSummary | None:
        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
        except (TypeError, ValueError):
            raise AuthorizationError("invalid device identifier") from None
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if record is None:
                return None
            if record["status"] == "denied":
                return _summary(record)
            if record["status"] != "pending":
                raise AuthorizationError("device state transition rejected")
            updated = dict(record)
            updated["status"] = "denied"
            updated["updated_at"] = self._now()
            updated["epoch"] += 1
            index = state["devices"].index(record)
            state["devices"][index] = updated
            self._save_state_unlocked(state)
            return _summary(updated)

    def expire_pending(self, max_age_seconds: int = MAX_TTL_SECONDS) -> list[DeviceSummary]:
        if (
            isinstance(max_age_seconds, bool)
            or not isinstance(max_age_seconds, int)
            or max_age_seconds < 1
            or max_age_seconds > MAX_TTL_SECONDS
        ):
            raise AuthorizationError("invalid pending timeout")
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            changed = self._expire_pending_in_state(state, self._now(), max_age_seconds)
            if changed:
                self._save_state_unlocked(state)
            return changed

    def revoke(self, device_id: str) -> DeviceSummary | None:
        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
        except (TypeError, ValueError):
            raise AuthorizationError("invalid device identifier") from None
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if record is None:
                return None
            if record["status"] == "revoked":
                return _summary(record)
            updated = dict(record)
            updated["status"] = "revoked"
            updated["updated_at"] = self._now()
            updated["epoch"] += 1
            updated["capabilities"] = []
            index = state["devices"].index(record)
            state["devices"][index] = updated
            self._save_state_unlocked(state)
            return _summary(updated)

    def is_authorized(self, device_id: str, device_public_key: bytes) -> bool:
        try:
            _b64url_decode_exact(device_id, DEVICE_ID_BYTES)
        except (TypeError, ValueError):
            return False
        try:
            supplied_key = _exact_input(device_public_key)
        except (TypeError, ValueError):
            return False
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            record = next(
                (item for item in state["devices"] if item["device_id"] == device_id), None
            )
            if (
                record is None
                or record["status"] != "authorized"
                or record["capabilities"] != ["client"]
            ):
                return False
            try:
                stored_key = _b64decode_exact(record["device_public_key"], RAW_BYTES)
            except (TypeError, ValueError):
                raise AuthorizationError("authorization state invalid") from None
            return hmac.compare_digest(stored_key, supplied_key)

    def list_devices(self) -> list[DeviceSummary]:
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            if self._expire_pending_in_state(state, self._now()):
                self._save_state_unlocked(state)
            return [_summary(record) for record in state["devices"]]

    def cancel_offer(self, offer_id: str) -> bool:
        """Expire the identified active offer so its capability is unusable.

        Used when the create response cannot be delivered usably (for
        example the QR failed to render, BR-07): the capability was already
        exposed to the create path, so the offer must not stay consumable.
        """

        try:
            _b64url_decode_exact(offer_id, PAIRING_OFFER_ID_BYTES)
        except (TypeError, ValueError):
            raise AuthorizationError("invalid offer identifier") from None
        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            offer = state.get("pairing_offer")
            if (
                not isinstance(offer, Mapping)
                or offer.get("offer_id") != offer_id
                or offer.get("status") != "active"
            ):
                return False
            cancelled = dict(offer)
            cancelled["status"] = "expired"
            state["pairing_offer"] = cancelled
            self._save_state_unlocked(state)
            return True

    def offer_status(self) -> dict[str, Any] | None:
        """Redacted pairing-offer state: no capability, digest, or key material."""

        with _transaction_lock(self.paths):
            state = self._load_state_unlocked()
            offer = state.get("pairing_offer")
            if offer is None:
                return None
            status = offer["status"]
            if status == "active" and self._now() >= offer["expires_at"]:
                status = "expired"
            return {
                "offer_id": offer["offer_id"],
                "status": status,
                "created_at": offer["created_at"],
                "expires_at": offer["expires_at"],
                "consumed_at": offer["consumed_at"],
            }


PairingRepository = AuthorizationRepository


__all__ = [
    "AuthorizationError",
    "AuthorizationRepository",
    "DEFAULT_TTL_SECONDS",
    "DeviceSummary",
    "MAX_TTL_SECONDS",
    "PairingOffer",
    "PairingRepository",
    "PairingRejected",
]
