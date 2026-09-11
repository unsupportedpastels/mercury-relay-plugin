"""Authorize completed Noise identities before opening Hermes controllers."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .push import PushBridge

from .authorization import (
    MAX_DEVICE_NAME_CHARS,
    AuthorizationError,
    AuthorizationRepository,
    DeviceSummary,
    PairingRejected,
)
from .config import validate_profile_id
from .connection_journal import ConnectionJournal
from .controller_transport import EncryptedControllerTransport
from .lease_recovery import RecoveryProjection, RecoveryStore, recovery_scope_device
from .operational_metrics import OperationalMetrics
from .runtime import ProfileNotAvailable, RelayRuntime
from .secure_channel import NoiseChannel, SecureChannelError
from .session_lease import (
    MAX_CURSOR,
    LeaseAttachment,
    LeaseAttachRejected,
    LeaseLimits,
    LeaseReleased,
    SessionLease,
    SessionLeaseError,
    SessionLeaseManager,
)
from .session_reads import SessionReads
from .strict_json import loads_strict

AUTH_ENVELOPE_TYPE = "controller.open"
MAX_AUTH_ENVELOPE_BYTES = 512
# Optional lease channel: one device may hold one lease per channel, so a phone
# can keep several Hermes sessions open at once. Absent means the default
# channel "" and preserves the legacy one-lease-per-device supersede rule.
MAX_CHANNEL_CHARS = 64
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEFAULT_CHANNEL = ""


def validate_channel(value: object) -> str:
    if value is None:
        return DEFAULT_CHANNEL
    if not isinstance(value, str) or _CHANNEL_RE.fullmatch(value) is None:
        raise ValueError("invalid lease channel")
    return value


class AdmissionRejected(RuntimeError):
    """One stable admission rejection without peer-controlled detail."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def controller_auth_payload(
    *,
    device_id: str,
    profile: str,
    resume_cursor: int | None = None,
    recovery_version: int | None = None,
    channel: str | None = None,
    device_name: str | None = None,
) -> bytes:
    if not isinstance(device_id, str) or not 1 <= len(device_id) <= 128:
        raise ValueError("invalid device identifier")
    validate_profile_id(profile)
    envelope: dict[str, object] = {
        "type": AUTH_ENVELOPE_TYPE,
        "device_id": device_id,
        "profile": profile,
    }
    if channel is not None:
        envelope["channel"] = validate_channel(channel)
    if device_name is not None:
        if not isinstance(device_name, str) or not 1 <= len(device_name) <= MAX_DEVICE_NAME_CHARS:
            raise ValueError("invalid device name")
        envelope["device_name"] = device_name
    if resume_cursor is not None:
        if (
            isinstance(resume_cursor, bool)
            or not isinstance(resume_cursor, int)
            or not 0 <= resume_cursor <= MAX_CURSOR
        ):
            raise ValueError("invalid resume cursor")
        envelope["resume_cursor"] = resume_cursor
    if recovery_version is not None:
        if type(recovery_version) is not int or recovery_version != 1:
            raise ValueError("invalid recovery version")
        envelope["recovery_version"] = recovery_version
    return json.dumps(
        envelope,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _parse_controller_auth(
    plaintext: bytes,
) -> tuple[str, str, int | None, int | None, str, str | None]:
    if len(plaintext) > MAX_AUTH_ENVELOPE_BYTES:
        raise AdmissionRejected("invalid_auth_envelope")
    try:
        value = loads_strict(plaintext.decode("utf-8"))
    except Exception:
        raise AdmissionRejected("invalid_auth_envelope") from None
    required = {"type", "device_id", "profile"}
    if not isinstance(value, dict) or not required <= set(value):
        raise AdmissionRejected("invalid_auth_envelope")
    if set(value) - required - {"resume_cursor", "recovery_version", "channel", "device_name"}:
        raise AdmissionRejected("invalid_auth_envelope")
    if value["type"] != AUTH_ENVELOPE_TYPE:
        raise AdmissionRejected("invalid_auth_envelope")
    device_id = value["device_id"]
    profile = value["profile"]
    if not isinstance(device_id, str) or not 1 <= len(device_id) <= 128:
        raise AdmissionRejected("invalid_auth_envelope")
    try:
        validate_profile_id(profile)
    except Exception:
        raise AdmissionRejected("invalid_auth_envelope") from None
    resume_cursor: int | None = None
    if "resume_cursor" in value:
        candidate = value["resume_cursor"]
        if (
            isinstance(candidate, bool)
            or not isinstance(candidate, int)
            or not 0 <= candidate <= MAX_CURSOR
        ):
            raise AdmissionRejected("invalid_auth_envelope")
        resume_cursor = candidate
    recovery_version = value.get("recovery_version")
    if "recovery_version" in value and (type(recovery_version) is not int or recovery_version != 1):
        raise AdmissionRejected("invalid_auth_envelope")
    channel = DEFAULT_CHANNEL
    if "channel" in value:
        try:
            channel = validate_channel(value["channel"])
        except ValueError:
            raise AdmissionRejected("invalid_auth_envelope") from None
        if channel == DEFAULT_CHANNEL:
            raise AdmissionRejected("invalid_auth_envelope")
    device_name: str | None = None
    if "device_name" in value:
        raw_name = value["device_name"]
        if not isinstance(raw_name, str) or len(raw_name) > 4 * MAX_DEVICE_NAME_CHARS:
            raise AdmissionRejected("invalid_auth_envelope")
        device_name = raw_name
    return device_id, profile, resume_cursor, recovery_version, channel, device_name


@dataclass(frozen=True, slots=True)
class AdmittedController:
    device_id: str
    channel: NoiseChannel
    lease: SessionLease
    attachment: LeaseAttachment
    lease_channel: str = DEFAULT_CHANNEL


class DeviceAdmissionService:
    """Bind one installation authorization repository to its Relay runtime."""

    def __init__(
        self,
        repository: AuthorizationRepository,
        runtime: RelayRuntime,
        *,
        profile: str,
        lease_manager: SessionLeaseManager | None = None,
        lease_limits: LeaseLimits | None = None,
        session_reads: SessionReads | None = None,
        journal: ConnectionJournal | None = None,
    ) -> None:
        if not isinstance(repository, AuthorizationRepository):
            raise TypeError("repository must be an AuthorizationRepository")
        if not isinstance(runtime, RelayRuntime):
            raise TypeError("runtime must be a RelayRuntime")
        if lease_manager is not None and not isinstance(lease_manager, SessionLeaseManager):
            raise TypeError("lease_manager must be a SessionLeaseManager")
        if session_reads is not None and not isinstance(session_reads, SessionReads):
            raise TypeError("session_reads must be a SessionReads")
        if journal is not None and not isinstance(journal, ConnectionJournal):
            raise TypeError("journal must be a ConnectionJournal")
        self.profile = validate_profile_id(profile)
        self.repository = repository
        self.runtime = runtime
        try:
            self.journal = journal or ConnectionJournal(repository.paths)
        except Exception:
            # The private journal is optional and must never block admission.
            self.journal = None
        self.leases = lease_manager or SessionLeaseManager(max_leases=runtime.max_controllers)
        try:
            self.metrics: OperationalMetrics | None = OperationalMetrics(repository.paths)
            self.metrics.update_active_leases(self.leases.active_count)
            self.refresh_registered_devices()
        except Exception:
            # Observability must never prevent an authorized channel from
            # reaching Hermes.
            self.metrics = None
        self.lease_limits = lease_limits or LeaseLimits()
        self.reads = session_reads or SessionReads(
            profile_authorizer=runtime.profile_authorizer,
            status_snapshot=runtime.snapshot,
        )
        self.push: PushBridge | None = None
        self._admission_lock = asyncio.Lock()
        self._recovery_store: RecoveryStore | None = None
        # Set by the connector when a routing issuer exists: every attach then
        # renews the device's router token inside the encrypted preamble.
        self.routing_token_provider: Callable[[], str | None] | None = None

    def _epoch(self, device_id: str) -> int:
        for device in self.repository.list_devices():
            if device.device_id == device_id and device.status == "authorized":
                return device.epoch
        raise AdmissionRejected("device_not_authorized")

    def _store(self) -> RecoveryStore:
        if self._recovery_store is None:
            self._recovery_store = RecoveryStore(
                self.repository.paths.agent_dir / "lease-recovery.json"
            )
        return self._recovery_store

    def _record_active_leases(self) -> None:
        if self.metrics is not None:
            with suppress(Exception):
                self.metrics.update_active_leases(self.leases.active_count)

    def refresh_registered_devices(self) -> None:
        """Refresh the aggregate authorized-device count without identifiers."""

        if self.metrics is not None:
            with suppress(Exception):
                registered = sum(
                    summary.status == "authorized" for summary in self.repository.list_devices()
                )
                self.metrics.update_registered_devices(registered)

    def new_host_channel(self) -> NoiseChannel:
        identity = self.repository.identity_store.load_or_create()
        return NoiseChannel.responder(
            static_private_key=identity.private_key,
            installation_id=identity.installation_id,
        )

    @staticmethod
    def _require_unclaimed_host_channel(channel: NoiseChannel) -> None:
        if not isinstance(channel, NoiseChannel):
            raise AdmissionRejected("invalid_channel")
        if channel.is_initiator or not channel.handshake_finished:
            raise AdmissionRejected("invalid_channel")
        if channel.admitted:
            raise AdmissionRejected("channel_already_admitted")

    def complete_pairing(
        self,
        channel: NoiseChannel,
        final_handshake_payload: bytes,
    ) -> DeviceSummary:
        self._require_unclaimed_host_channel(channel)
        try:
            summary = self.repository.consume_offer(
                final_handshake_payload,
                channel.remote_static_public,
                channel.channel_binding,
            )
            channel.mark_admitted()
            if self.metrics is not None:
                with suppress(Exception):
                    self.metrics.record_pairing(active_leases=self.leases.active_count)
            return summary
        except PairingRejected:
            channel.close()
            raise
        except (AuthorizationError, SecureChannelError):
            channel.close()
            raise AdmissionRejected("pairing_unavailable") from None
        except Exception:
            channel.close()
            raise AdmissionRejected("pairing_rejected") from None

    async def open_controller(
        self,
        channel: NoiseChannel,
        encrypted_auth_envelope: bytes,
    ) -> AdmittedController:
        async with self._admission_lock:
            return await self._open_controller_locked(channel, encrypted_auth_envelope)

    async def _open_controller_locked(
        self,
        channel: NoiseChannel,
        encrypted_auth_envelope: bytes,
    ) -> AdmittedController:
        self._require_unclaimed_host_channel(channel)
        try:
            plaintext = channel.decrypt(encrypted_auth_envelope)
            device_id, profile, resume_cursor, recovery_version, lease_channel, device_name = (
                _parse_controller_auth(plaintext)
            )
            if device_name is not None:
                # The phone names itself on every open, including the approval
                # probes a pending device sends, so the dashboard can show the
                # name before approval. Bound to the record whose key signed
                # this channel; never blocks admission.
                with suppress(Exception):
                    self.repository.note_device_name(
                        device_id, channel.remote_static_public, device_name
                    )
            # Authorization (device status, capability, epoch) is re-proven on
            # every fresh channel, including lease reattach after a detach.
            if not self.repository.is_authorized(device_id, channel.remote_static_public):
                raise AdmissionRejected("device_not_authorized")
        except AdmissionRejected:
            channel.close()
            raise
        except (AuthorizationError, SecureChannelError):
            channel.close()
            raise AdmissionRejected("device_not_authorized") from None
        except Exception:
            channel.close()
            raise AdmissionRejected("invalid_auth_envelope") from None

        try:
            if not self.runtime.profile_authorizer(profile):
                raise AdmissionRejected("profile_not_available")
            epoch = self._epoch(device_id)
            existing = self.leases.get(device_id, lease_channel)
            if existing is not None and existing.authorization_epoch != epoch:
                # A stale epoch invalidates every lease the device holds.
                await self.leases.release_device(device_id, reason="authorization_changed")
                existing = None
            if recovery_version == 1 and existing is None:
                lease, attachment = await self._open_lease(
                    device_id,
                    profile,
                    channel.remote_static_public,
                    recovery=True,
                    recovery_reset=resume_cursor is not None,
                    epoch=epoch,
                    lease_channel=lease_channel,
                )
            elif resume_cursor is not None or recovery_version == 1:
                lease, attachment = self._reattach_lease(
                    device_id,
                    profile,
                    resume_cursor or 0,
                    recovery=recovery_version == 1,
                    replace_attached=recovery_version == 1 and resume_cursor is not None,
                    lease_channel=lease_channel,
                )
            else:
                lease, attachment = await self._open_lease(
                    device_id,
                    profile,
                    channel.remote_static_public,
                    epoch=epoch,
                    lease_channel=lease_channel,
                )
            if (
                not self.repository.is_authorized(device_id, channel.remote_static_public)
                or self._epoch(device_id) != epoch
            ):
                await self.leases.release_device(device_id, reason="authorization_changed")
                raise AdmissionRejected("device_not_authorized")
            if not self.runtime.profile_authorizer(profile):
                await self.leases.release_device(device_id, reason="profile_not_available")
                raise AdmissionRejected("profile_not_available")
        except AdmissionRejected:
            channel.close()
            raise
        except asyncio.CancelledError:
            channel.close()
            raise
        except Exception:
            channel.close()
            raise AdmissionRejected("runtime_unavailable") from None
        try:
            channel.mark_admitted()
        except SecureChannelError:
            try:
                lease.detach(attachment, reason="admission_failed")
            finally:
                channel.close()
            raise AdmissionRejected("channel_already_admitted") from None
        if self.metrics is not None:
            with suppress(Exception):
                if resume_cursor is None:
                    self.metrics.record_controller_open(active_leases=self.leases.active_count)
                else:
                    self.metrics.record_reattachment(active_leases=self.leases.active_count)
        return AdmittedController(
            device_id=device_id,
            channel=channel,
            lease=lease,
            attachment=attachment,
            lease_channel=lease_channel,
        )

    def _reattach_lease(
        self,
        device_id: str,
        profile: str,
        resume_cursor: int,
        *,
        recovery: bool = False,
        replace_attached: bool = False,
        lease_channel: str = DEFAULT_CHANNEL,
    ) -> tuple[SessionLease, LeaseAttachment]:
        lease = self.leases.get(device_id, lease_channel)
        if lease is None or lease.profile != profile:
            raise AdmissionRejected("lease_not_available")
        if recovery and lease.recovery_projection.store is None:
            # Upgrade observations from a legacy lease only after fresh auth.
            lease.recovery_projection.store = self._store()
            for event in lease.recovery_projection.tasks.values():
                lease.recovery_projection._persist(event)
        try:
            attachment = lease.attach(
                resume_cursor, recovery=recovery, replace_attached=replace_attached
            )
        except (LeaseReleased, LeaseAttachRejected):
            raise AdmissionRejected("lease_not_available") from None
        return lease, attachment

    async def _open_lease(
        self,
        device_id: str,
        profile: str,
        device_public_key: bytes,
        *,
        recovery: bool = False,
        recovery_reset: bool = False,
        epoch: int | None = None,
        lease_channel: str = DEFAULT_CHANNEL,
    ) -> tuple[SessionLease, LeaseAttachment]:
        # A fresh open supersedes any retained lease on the same channel of
        # this device; other channels (other open sessions) are untouched.
        if self.leases.get(device_id, lease_channel) is not None:
            await self.leases.release_lease(device_id, lease_channel, reason="superseded")
        projection = RecoveryProjection(
            profile,
            store=self._store() if recovery else None,
            scope=(
                self.repository.identity_store.load_or_create().installation_id.hex(),
                recovery_scope_device(device_id, lease_channel),
                epoch,
            ),
            profile_authorizer=lambda p: self.runtime.profile_authorizer(p),
        )
        try:
            controller = await self.runtime.open_controller(profile=profile)
        except ProfileNotAvailable:
            raise AdmissionRejected("profile_not_available") from None
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AdmissionRejected("runtime_unavailable") from None

        async def authorized_read(method, params):
            # Revocation during thread-backed I/O must not deliver its result.
            def require_authorized():
                from .session_reads import SessionReadsError

                try:
                    allowed = (
                        self.repository.is_authorized(device_id, device_public_key)
                        and self._epoch(device_id) == epoch
                    )
                except Exception:
                    allowed = False
                if not allowed:
                    raise SessionReadsError("device_not_authorized")

            require_authorized()
            if method in {"relay.push.register", "relay.push.unregister"}:
                from .session_reads import SessionReadsError

                if self.push is None or not self.push.available:
                    raise SessionReadsError("push_unavailable")
                result = await self.push.dispatch(device_id, epoch, method, params)
            else:
                result = await self.reads.dispatch(method, params)
                if method == "relay.status" and self.push is not None and self.push.available:
                    result.setdefault("capabilities", {})["push_notifications_v1"] = True
            require_authorized()
            return result

        lease = SessionLease(
            device_id=device_id,
            channel=lease_channel,
            profile=profile,
            controller_id=controller.controller_id,
            websocket=controller.websocket,
            close_controller=self.runtime.close_controller,
            limits=self.lease_limits,
            read_dispatcher=authorized_read,
            on_release=self._record_active_leases,
            authorization_epoch=epoch,
            recovery_projection=projection,
            routing_token_provider=self.routing_token_provider,
            push_bridge=self.push,
        )
        try:
            self.leases.register(lease)
            attachment = lease.attach(0, recovery=recovery, recovery_reset=recovery_reset)
        except Exception:
            if self.leases.get(device_id, lease_channel) is lease:
                await self.leases.release_lease(device_id, lease_channel, reason="admission_failed")
            else:
                await lease.release("admission_failed")
            raise AdmissionRejected("runtime_unavailable") from None
        return lease, attachment

    def bind_controller(
        self,
        admitted: AdmittedController,
        *,
        channel_id: bytes,
    ) -> EncryptedControllerTransport:
        """Bind an admitted channel to its exact Hermes transport data path."""

        if not isinstance(admitted, AdmittedController):
            raise TypeError("admitted must be an AdmittedController")
        return EncryptedControllerTransport(
            channel=admitted.channel,
            attachment=admitted.attachment,
            channel_id=channel_id,
        )

    async def revoke_device(self, device_id: str) -> DeviceSummary | None:
        """Revoke authorization and immediately release any live lease."""

        summary = self.repository.revoke(device_id)
        if self.push is not None:
            # Fence wakes even if worker deletion/persistence is unavailable.
            with suppress(Exception):
                self.push.revoke(device_id)
        try:
            await self.leases.release_device(device_id, reason="revoked")
            if self._recovery_store is not None:
                self._recovery_store.revoke(
                    self.repository.identity_store.load_or_create().installation_id.hex(), device_id
                )
        except SessionLeaseError:
            raise AdmissionRejected("runtime_unavailable") from None
        if self.metrics is not None:
            with suppress(Exception):
                self.metrics.update_active_leases(self.leases.active_count)
        self.refresh_registered_devices()
        return summary

    async def close(self) -> None:
        """Release every retained lease exactly once at plugin shutdown."""

        await self.leases.close()
        if self.push is not None:
            await self.push.close()
        if self.metrics is not None:
            with suppress(Exception):
                self.metrics.update_active_leases(0)
        if self.journal is not None:
            with suppress(Exception):
                self.journal.close()
