"""Compact v1 plaintext records for bounded Noise application data.

All integers use network byte order.  The fixed 50-byte header is:

* 0..1   magic ``MR``
* 2      version (1)
* 3      kind (1 = Hermes bytes)
* 4      flags (0 only in v1)
* 5      reserved (0 only)
* 6..7   zero-based fragment index, unsigned 16-bit
* 8..9   canonical fragment count, unsigned 16-bit
* 10..13 logical message length, unsigned 32-bit
* 14..17 payload length, unsigned 32-bit
* 18..33 fixed 16-byte channel ID
* 34..49 fixed 16-byte message ID
* 50..   payload bytes

The complete plaintext record is capped at 65,519 bytes, leaving the 16-byte
Noise AEAD tag within the 65,535-byte ciphertext record limit.  Consequently,
this header leaves 65,469 payload bytes per record.  A logical message is at
most 16 MiB (up to 257 canonical fragments) and always uses the canonical
minimum fragment count.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Final

MAGIC: Final = b"MR"
PROTOCOL_VERSION: Final = 1
KIND_HERMES_BYTES: Final = 1
FLAGS_NONE: Final = 0
RESERVED_NONE: Final = 0
CHANNEL_ID_SIZE: Final = 16
MESSAGE_ID_SIZE: Final = 16
MAX_NOISE_PLAINTEXT_BYTES: Final = 65_519
# Raised from the initial 1 MiB so attachments comparable to direct mode fit
# through the relay; kept under the router's 25 MB / 10 s per-socket byte
# budget so one maximal message cannot trip it. Must match the mobile
# clients' RelayFraming.maxLogicalMessageBytes.
MAX_LOGICAL_MESSAGE_BYTES: Final = 16 << 20
_HEADER = struct.Struct("!2sBBBBHHII16s16s")
FRAME_HEADER_SIZE: Final = _HEADER.size
MAX_PAYLOAD_BYTES: Final = MAX_NOISE_PLAINTEXT_BYTES - FRAME_HEADER_SIZE
MAX_FRAGMENT_COUNT: Final = math.ceil(MAX_LOGICAL_MESSAGE_BYTES / MAX_PAYLOAD_BYTES)


class FramingError(ValueError):
    """Base class for bounded framing and reassembly failures."""


class DecodeError(FramingError):
    """A record is not a canonical v1 record."""


class ReassemblyError(FramingError):
    """A record cannot continue the one-message ordered reassembly."""


BytesLike = bytes | bytearray | memoryview


@dataclass(frozen=True, slots=True)
class Frame:
    """A validated record, with payload copied only after length checks."""

    channel_id: bytes
    message_id: bytes
    kind: int
    flags: int
    fragment_index: int
    fragment_count: int
    logical_length: int
    payload: bytes


def _view(value: object, field: str, *, size: int | None = None) -> memoryview:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{field} must be bytes-like")
    try:
        view = memoryview(value).cast("B")
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{field} must be a contiguous bytes-like value") from exc
    if size is not None and view.nbytes != size:
        raise ValueError(f"{field} must be exactly {size} bytes")
    return view


def _validate_kind_flags(kind: int, flags: int) -> None:
    if isinstance(kind, bool) or not isinstance(kind, int):
        raise TypeError("kind must be an integer")
    if kind != KIND_HERMES_BYTES:
        raise ValueError("unknown kind")
    if isinstance(flags, bool) or not isinstance(flags, int):
        raise TypeError("flags must be an integer")
    if flags != FLAGS_NONE:
        raise ValueError("unknown flags")


def _fragment_count(logical_length: int) -> int:
    if logical_length < 0 or logical_length > MAX_LOGICAL_MESSAGE_BYTES:
        raise ValueError("logical length exceeds v1 limit")
    return max(1, math.ceil(logical_length / MAX_PAYLOAD_BYTES))


def _payload_length(logical_length: int, fragment_index: int) -> int:
    count = _fragment_count(logical_length)
    if not 0 <= fragment_index < count:
        raise ValueError("fragment index is outside the fragment count")
    start = fragment_index * MAX_PAYLOAD_BYTES
    return min(MAX_PAYLOAD_BYTES, logical_length - start)


def _record(
    channel_id: bytes,
    message_id: bytes,
    payload: bytes,
    *,
    fragment_index: int,
    fragment_count: int,
    logical_length: int,
    kind: int,
    flags: int,
) -> bytes:
    expected_payload_length = _payload_length(logical_length, fragment_index)
    if fragment_count != _fragment_count(logical_length):
        raise ValueError("fragment count is not canonical")
    if len(payload) != expected_payload_length:
        raise ValueError("payload length is not canonical")
    header = _HEADER.pack(
        MAGIC,
        PROTOCOL_VERSION,
        kind,
        flags,
        RESERVED_NONE,
        fragment_index,
        fragment_count,
        logical_length,
        len(payload),
        channel_id,
        message_id,
    )
    return header + payload


def encode_record(
    channel_id: BytesLike,
    message_id: BytesLike,
    payload: BytesLike,
    *,
    fragment_index: int,
    fragment_count: int,
    logical_length: int,
    kind: int = KIND_HERMES_BYTES,
    flags: int = FLAGS_NONE,
) -> bytes:
    """Encode one already-positioned canonical record."""

    channel = _view(channel_id, "channel_id", size=CHANNEL_ID_SIZE).tobytes()
    message = _view(message_id, "message_id", size=MESSAGE_ID_SIZE).tobytes()
    _validate_kind_flags(kind, flags)
    if isinstance(fragment_index, bool) or not isinstance(fragment_index, int):
        raise TypeError("fragment_index must be an integer")
    if isinstance(fragment_count, bool) or not isinstance(fragment_count, int):
        raise TypeError("fragment_count must be an integer")
    if isinstance(logical_length, bool) or not isinstance(logical_length, int):
        raise TypeError("logical_length must be an integer")
    if not 0 <= fragment_index < 1 << 16:
        raise ValueError("fragment_index is outside the unsigned 16-bit range")
    if not 0 <= fragment_count < 1 << 16:
        raise ValueError("fragment_count is outside the unsigned 16-bit range")
    if not 0 <= logical_length <= MAX_LOGICAL_MESSAGE_BYTES:
        raise ValueError("logical length exceeds v1 limit")
    payload_view = _view(payload, "payload")
    if payload_view.nbytes > MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds one Noise plaintext record")
    payload_bytes = payload_view.tobytes()
    return _record(
        channel,
        message,
        payload_bytes,
        fragment_index=fragment_index,
        fragment_count=fragment_count,
        logical_length=logical_length,
        kind=kind,
        flags=flags,
    )


def encode_message(
    channel_id: BytesLike,
    message_id: BytesLike,
    payload: BytesLike,
    *,
    kind: int = KIND_HERMES_BYTES,
    flags: int = FLAGS_NONE,
) -> tuple[bytes, ...]:
    """Encode one bounded logical byte string into canonical records."""

    channel = _view(channel_id, "channel_id", size=CHANNEL_ID_SIZE).tobytes()
    message = _view(message_id, "message_id", size=MESSAGE_ID_SIZE).tobytes()
    _validate_kind_flags(kind, flags)
    payload_view = _view(payload, "payload")
    logical_length = payload_view.nbytes
    if logical_length > MAX_LOGICAL_MESSAGE_BYTES:
        raise ValueError("logical length exceeds v1 limit")
    payload_bytes = payload_view.tobytes()
    count = _fragment_count(logical_length)
    return tuple(
        _record(
            channel,
            message,
            payload_bytes[index * MAX_PAYLOAD_BYTES : (index + 1) * MAX_PAYLOAD_BYTES],
            fragment_index=index,
            fragment_count=count,
            logical_length=logical_length,
            kind=kind,
            flags=flags,
        )
        for index in range(count)
    )


def _record_view(record: object) -> memoryview:
    view = _view(record, "record")
    if view.nbytes < FRAME_HEADER_SIZE:
        raise DecodeError("truncated record header")
    if view.nbytes > MAX_NOISE_PLAINTEXT_BYTES:
        raise DecodeError("record exceeds Noise plaintext limit")
    return view


def decode_record(record: BytesLike) -> Frame:
    """Validate and decode one complete canonical plaintext record."""

    view = _record_view(record)
    (
        magic,
        version,
        kind,
        flags,
        reserved,
        fragment_index,
        fragment_count,
        logical_length,
        payload_length,
        channel_id,
        message_id,
    ) = _HEADER.unpack_from(view, 0)
    if magic != MAGIC:
        raise DecodeError("invalid magic")
    if version != PROTOCOL_VERSION:
        raise DecodeError("unknown version")
    if kind != KIND_HERMES_BYTES:
        raise DecodeError("unknown kind")
    if flags != FLAGS_NONE:
        raise DecodeError("unknown flags")
    if reserved != RESERVED_NONE:
        raise DecodeError("reserved value is nonzero")
    if fragment_count == 0 or fragment_count > MAX_FRAGMENT_COUNT:
        raise DecodeError("fragment count is outside the v1 range")
    if logical_length > MAX_LOGICAL_MESSAGE_BYTES:
        raise DecodeError("logical length exceeds v1 limit")
    try:
        expected_count = _fragment_count(logical_length)
        expected_payload_length = _payload_length(logical_length, fragment_index)
    except ValueError as exc:
        raise DecodeError("fragment index or length is not canonical") from exc
    if fragment_count != expected_count:
        raise DecodeError("fragment count is not canonical")
    if payload_length != expected_payload_length:
        raise DecodeError("payload length is not canonical")
    expected_record_length = FRAME_HEADER_SIZE + payload_length
    if view.nbytes != expected_record_length:
        raise DecodeError("record length does not match payload length")
    payload = view[FRAME_HEADER_SIZE:].tobytes()
    return Frame(
        channel_id=channel_id,
        message_id=message_id,
        kind=kind,
        flags=flags,
        fragment_index=fragment_index,
        fragment_count=fragment_count,
        logical_length=logical_length,
        payload=payload,
    )


class Reassembler:
    """Reassemble one message from strictly ordered, matching records."""

    def __init__(
        self,
        *,
        channel_id: BytesLike | None = None,
        kind: int = KIND_HERMES_BYTES,
        flags: int = FLAGS_NONE,
    ) -> None:
        self._channel_id = (
            _view(channel_id, "channel_id", size=CHANNEL_ID_SIZE).tobytes()
            if channel_id is not None
            else None
        )
        _validate_kind_flags(kind, flags)
        self._expected_kind = kind
        self._expected_flags = flags
        self.reset()

    def reset(self) -> None:
        self._active_channel_id: bytes | None = None
        self._message_id: bytes | None = None
        self._fragment_count = 0
        self._logical_length = 0
        self._next_index = 0
        self._received_length = 0
        self._parts: list[bytes] = []

    @property
    def in_progress(self) -> bool:
        return self._message_id is not None

    def _reject(self, reason: str) -> ReassemblyError:
        return ReassemblyError(reason)

    def push(self, record: BytesLike) -> bytes | None:
        """Consume one record, resetting state after every rejection."""

        try:
            frame = decode_record(record)
            if frame.kind != self._expected_kind or frame.flags != self._expected_flags:
                raise self._reject("metadata kind or flags mismatch")
            if self._channel_id is not None and frame.channel_id != self._channel_id:
                raise self._reject("metadata channel mismatch")
            if self._message_id is None:
                if frame.fragment_index != 0:
                    raise self._reject("order requires fragment zero first")
                self._active_channel_id = frame.channel_id
                self._message_id = frame.message_id
                self._fragment_count = frame.fragment_count
                self._logical_length = frame.logical_length
            elif (
                frame.channel_id != self._active_channel_id
                or frame.message_id != self._message_id
                or frame.fragment_count != self._fragment_count
                or frame.logical_length != self._logical_length
            ):
                raise self._reject("metadata channel, message, or length mismatch")
            if frame.fragment_index != self._next_index:
                raise self._reject("order is not contiguous")
            if self._received_length + len(frame.payload) > self._logical_length:
                raise self._reject("received length exceeds logical length")
            self._parts.append(frame.payload)
            self._received_length += len(frame.payload)
            self._next_index += 1
            if self._next_index != self._fragment_count:
                return None
            if self._received_length != self._logical_length:
                raise self._reject("received length is incomplete")
            message = b"".join(self._parts)
            self.reset()
            return message
        except (DecodeError, ReassemblyError, TypeError, ValueError):
            self.reset()
            raise
