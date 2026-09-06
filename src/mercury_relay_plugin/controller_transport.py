"""Framed Noise application data bound to one leased Hermes controller.

The transport owns only the outer cryptographic attachment: one admitted
Noise channel and one :class:`~.session_lease.LeaseAttachment`.  Outer
failures — a bad record, backpressure, a mobile or Cloudflare disconnect —
sever the encrypted attachment and leave the lease's inner Hermes controller
running so a fresh channel can reattach.  Controller lifetime belongs to the
lease, never to this transport.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Callable

from .framing import (
    CHANNEL_ID_SIZE,
    MESSAGE_ID_SIZE,
    FramingError,
    Reassembler,
    encode_message,
)
from .secure_channel import NoiseChannel, SecureChannelError
from .session_lease import LeaseAttachment, LeaseReleased, SessionLeaseError
from .virtual_ws import VirtualWebSocketBackpressure, VirtualWebSocketError


def _diagnose_failure(stage: str, error: Exception) -> None:
    # Never log exception text, traceback, method, identifiers, or decrypted data.
    # Both fields are allowlisted so extension exceptions cannot smuggle payloads.
    error_type = type(error).__name__
    if error_type not in {
        "FramingError",
        "SecureChannelError",
        "SessionLeaseError",
        "VirtualWebSocketError",
        "VirtualWebSocketClosed",
        "MethodPolicyRejected",
        "VirtualWebSocketFrameTooLarge",
        "TypeError",
        "ValueError",
    }:
        error_type = "Exception"
    reason = getattr(error, "reason", None)
    if not isinstance(reason, str) or reason not in {
        "invalid_request",
        "invalid_json",
        "uncorrelated_request",
        "method_not_allowed",
        "invalid_params",
        "privileged_identity",
        "profile_not_available",
        "attachment_detached",
        "invalid_read_request",
        "invalid_submission_id",
        "submission_tracking_exhausted",
    }:
        reason = "unspecified"
    logging.getLogger(__name__).warning(
        "Relay controller failure stage=%s type=%s reason=%s", stage, error_type, reason
    )


class ControllerTransportError(RuntimeError):
    """Stable failure for an authenticated controller data channel."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _fixed_bytes(value: object, *, size: int, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{field} must be bytes-like")
    try:
        result = memoryview(value).cast("B").tobytes()
    except (TypeError, ValueError):
        raise TypeError(f"{field} must be contiguous bytes") from None
    if len(result) != size:
        raise ValueError(f"{field} has the wrong length")
    return result


class EncryptedControllerTransport:
    """Carry exact Hermes text frames through canonical records and Noise."""

    def __init__(
        self,
        *,
        channel: NoiseChannel,
        attachment: LeaseAttachment,
        channel_id: bytes,
        message_id_factory: Callable[[], bytes] | None = None,
    ) -> None:
        if not isinstance(channel, NoiseChannel):
            raise TypeError("channel must be a NoiseChannel")
        if channel.is_initiator or not channel.handshake_finished or not channel.admitted:
            raise ValueError("channel must be an admitted host channel")
        if not isinstance(attachment, LeaseAttachment):
            raise TypeError("attachment must be a LeaseAttachment")
        if message_id_factory is not None and not callable(message_id_factory):
            raise TypeError("message_id_factory must be callable")
        normalized_channel_id = _fixed_bytes(
            channel_id,
            size=CHANNEL_ID_SIZE,
            field="channel_id",
        )
        if channel.transport_bound:
            raise ValueError("channel transport is already bound")
        channel.mark_transport_bound()
        self.channel = channel
        self.attachment = attachment
        self.channel_id = normalized_channel_id
        self._message_id_factory = message_id_factory or (
            lambda: secrets.token_bytes(MESSAGE_ID_SIZE)
        )
        self._reassembler = Reassembler(channel_id=self.channel_id)
        self._receive_lock = asyncio.Lock()
        self._send_lock = asyncio.Lock()
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def _require_open(self) -> None:
        if self._closed:
            raise ControllerTransportError("channel_closed")
        if self.channel.closed:
            raise self._fail("channel_closed")

    def _fail(self, reason: str) -> ControllerTransportError:
        """Sever only the outer attachment; the lease keeps the controller."""

        self.close(reason=reason)
        return ControllerTransportError(reason)

    async def feed_ciphertext(self, ciphertext: bytes) -> bool:
        """Decrypt one record and deliver a complete UTF-8 Hermes frame."""

        async with self._receive_lock:
            self._require_open()
            try:
                record = self.channel.decrypt(ciphertext)
                message = self._reassembler.push(record)
                if message is None:
                    return False
                text = message.decode("utf-8", errors="strict")
                await self.attachment.feed_text(text)
                return True
            except asyncio.CancelledError:
                raise
            except LeaseReleased:
                raise self._fail("lease_released") from None
            except VirtualWebSocketBackpressure:
                raise self._fail("backpressure") from None
            except UnicodeDecodeError:
                raise self._fail("malformed_frame") from None
            except (
                FramingError,
                SecureChannelError,
                SessionLeaseError,
                VirtualWebSocketError,
                TypeError,
                ValueError,
            ) as error:
                _diagnose_failure("inbound", error)
                raise self._fail("protocol_violation") from None
            except Exception as error:
                _diagnose_failure("inbound", error)
                raise self._fail("local_hermes_unavailable") from None

    async def next_ciphertexts(self, *, timeout: float | None = None) -> tuple[bytes, ...]:
        """Read one exact Hermes frame and return its ordered Noise records."""

        async with self._send_lock:
            self._require_open()
            try:
                text = await self.attachment.next_text(timeout=timeout)
                message_id = _fixed_bytes(
                    self._message_id_factory(),
                    size=MESSAGE_ID_SIZE,
                    field="message_id",
                )
                records = encode_message(self.channel_id, message_id, text.encode("utf-8"))
                return tuple(self.channel.encrypt(record) for record in records)
            except (asyncio.CancelledError, TimeoutError):
                raise
            except LeaseReleased:
                raise self._fail("lease_released") from None
            except SessionLeaseError as error:
                reason = (
                    "backpressure"
                    if error.reason == "attachment_backpressure"
                    else "channel_closed"
                )
                raise self._fail(reason) from None
            except (FramingError, SecureChannelError, TypeError, ValueError) as error:
                _diagnose_failure("outbound", error)
                raise self._fail("protocol_violation") from None
            except Exception as error:
                _diagnose_failure("outbound", error)
                raise self._fail("local_hermes_unavailable") from None

    def close(self, *, reason: str = "detached") -> None:
        """Close the outer channel and detach from the lease exactly once.

        This never releases the inner Hermes controller; lease expiry,
        revocation, terminal inner close, or plugin shutdown does that.
        """

        if self._closed:
            return
        self._closed = True
        self._reassembler.reset()
        self.channel.close()
        self.attachment.detach(reason=reason)
