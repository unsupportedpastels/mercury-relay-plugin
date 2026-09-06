"""Production-shaped Noise XK channel for Mercury Relay v1."""

from __future__ import annotations

import warnings
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

try:
    from noise.connection import Keypair, NoiseConnection
    from noise.exceptions import (
        NoiseHandshakeError,
        NoiseInvalidMessage,
        NoiseValidationError,
        NoiseValueError,
    )
except ImportError:
    # Zero-click deployment: Hermes never auto-installs plugin Python
    # dependencies, so the pinned pure-Python Noise runtime is vendored in
    # ``_vendor/``. A site installation always wins over the vendored copy.
    import sys as _sys
    from pathlib import Path as _Path

    _vendor = str(_Path(__file__).resolve().parent / "_vendor")
    if _vendor not in _sys.path:
        _sys.path.append(_vendor)
    from noise.connection import Keypair, NoiseConnection
    from noise.exceptions import (
        NoiseHandshakeError,
        NoiseInvalidMessage,
        NoiseValidationError,
        NoiseValueError,
    )

PROTOCOL_NAME: Final = b"Noise_XK_25519_ChaChaPoly_SHA256"
PROLOGUE_PREFIX: Final = b"mercury-relay/v1\x00"
KEY_BYTES: Final = 32
PAIRING_CAPABILITY_BYTES: Final = 32
MAX_CIPHERTEXT_RECORD_BYTES: Final = 65_535
MAX_PLAINTEXT_RECORD_BYTES: Final = 65_519
_TEST_CONSTRUCTOR_TOKEN = object()
_NOISE_ERRORS = (
    InvalidTag,
    NoiseHandshakeError,
    NoiseInvalidMessage,
    NoiseValidationError,
    NoiseValueError,
    ValueError,
)


class SecureChannelError(RuntimeError):
    """One stable channel failure without raw cryptographic details."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _exact_bytes(
    value: object,
    *,
    size: int | None = None,
    max_size: int | None = None,
) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("value must be bytes-like")
    try:
        view = memoryview(value).cast("B")
    except (TypeError, ValueError):
        raise TypeError("value must be contiguous bytes") from None
    if size is not None and view.nbytes != size:
        raise ValueError("value has the wrong length")
    if max_size is not None and view.nbytes > max_size:
        raise OverflowError("value exceeds limit")
    return view.tobytes()


def public_key(private_key: bytes) -> bytes:
    private = x25519.X25519PrivateKey.from_private_bytes(
        _exact_bytes(private_key, size=KEY_BYTES)
    )
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _new_connection(
    *,
    initiator: bool,
    static_private_key: bytes,
    installation_id: bytes,
    remote_static_public_key: bytes | None,
    ephemeral_private_key: bytes | None,
) -> NoiseConnection:
    connection = NoiseConnection.from_name(PROTOCOL_NAME)
    if initiator:
        connection.set_as_initiator()
    else:
        connection.set_as_responder()
    connection.set_keypair_from_private_bytes(Keypair.STATIC, static_private_key)
    if ephemeral_private_key is not None:
        connection.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral_private_key)
    if remote_static_public_key is not None:
        connection.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static_public_key)
    connection.set_prologue(PROLOGUE_PREFIX + installation_id)

    protocol = connection.noise_protocol
    if protocol is None:
        raise SecureChannelError("authentication_failed")
    original_handshake_done = protocol.handshake_done

    def capture_peer_then_finish() -> None:
        state = protocol.handshake_state
        peer = getattr(state, "rs", None)
        if peer is not None and peer.public_bytes is not None:
            protocol._mercury_peer_static = bytes(peer.public_bytes)
        original_handshake_done()

    protocol.handshake_done = capture_peer_then_finish
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="One of ephemeral keypairs is already set.*")
        connection.start_handshake()
    return connection


class NoiseChannel:
    """One fresh mutually authenticated Mercury Noise connection."""

    def __init__(
        self,
        *,
        initiator: bool,
        static_private_key: bytes,
        installation_id: bytes,
        remote_static_public_key: bytes | None,
        _ephemeral_private_key: bytes | None = None,
        _test_token: object | None = None,
    ) -> None:
        static_private = _exact_bytes(static_private_key, size=KEY_BYTES)
        installation = _exact_bytes(installation_id, size=KEY_BYTES)
        if initiator:
            if remote_static_public_key is None:
                raise ValueError("initiator requires the host public key")
            remote_static = _exact_bytes(remote_static_public_key, size=KEY_BYTES)
        elif remote_static_public_key is not None:
            raise ValueError("responder must recover the mobile identity")
        else:
            remote_static = None
        if _ephemeral_private_key is not None:
            if _test_token is not _TEST_CONSTRUCTOR_TOKEN:
                raise TypeError("deterministic ephemeral injection is test-only")
            ephemeral = _exact_bytes(_ephemeral_private_key, size=KEY_BYTES)
        else:
            ephemeral = None

        try:
            self._connection: NoiseConnection | None = _new_connection(
                initiator=initiator,
                static_private_key=static_private,
                installation_id=installation,
                remote_static_public_key=remote_static,
                ephemeral_private_key=ephemeral,
            )
        except SecureChannelError:
            raise
        except Exception:
            raise SecureChannelError("authentication_failed") from None
        self._is_initiator = initiator
        self.closed = False
        self.admitted = False
        self.transport_bound = False
        self._next_action = "write1" if initiator else "read1"
        self._channel_binding: bytes | None = None
        self._remote_static_public: bytes | None = None
        self._configured_remote_static = remote_static

    @classmethod
    def initiator(
        cls,
        *,
        static_private_key: bytes,
        installation_id: bytes,
        remote_static_public_key: bytes,
    ) -> NoiseChannel:
        return cls(
            initiator=True,
            static_private_key=static_private_key,
            installation_id=installation_id,
            remote_static_public_key=remote_static_public_key,
        )

    @classmethod
    def responder(
        cls,
        *,
        static_private_key: bytes,
        installation_id: bytes,
    ) -> NoiseChannel:
        return cls(
            initiator=False,
            static_private_key=static_private_key,
            installation_id=installation_id,
            remote_static_public_key=None,
        )

    @property
    def is_initiator(self) -> bool:
        return self._is_initiator

    @property
    def handshake_finished(self) -> bool:
        return self._next_action == "complete" and not self.closed

    @property
    def channel_binding(self) -> bytes:
        if not self.handshake_finished or self._channel_binding is None:
            raise SecureChannelError("handshake_not_finished")
        return self._channel_binding

    @property
    def remote_static_public(self) -> bytes:
        if not self.handshake_finished or self._remote_static_public is None:
            raise SecureChannelError("handshake_not_finished")
        return self._remote_static_public

    def _fail(self, reason: str) -> SecureChannelError:
        self.close()
        return SecureChannelError(reason)

    def _require_open(self) -> None:
        if self.closed or self._connection is None:
            raise SecureChannelError("channel_closed")

    def _active_connection(self) -> NoiseConnection:
        self._require_open()
        if self._connection is None:
            raise SecureChannelError("channel_closed")
        return self._connection

    def _finish_handshake(self) -> None:
        try:
            connection = self._active_connection()
            binding = bytes(connection.get_handshake_hash())
            protocol = connection.noise_protocol
            captured = getattr(protocol, "_mercury_peer_static", None) if protocol else None
            peer = captured if isinstance(captured, bytes) else self._configured_remote_static
            if len(binding) != KEY_BYTES or not isinstance(peer, bytes) or len(peer) != KEY_BYTES:
                raise ValueError
        except Exception:
            raise self._fail("authentication_failed") from None
        self._channel_binding = binding
        self._remote_static_public = bytes(peer)
        self._next_action = "complete"

    def write_handshake(self, payload: bytes = b"") -> bytes:
        self._require_open()
        try:
            body = _exact_bytes(payload, max_size=PAIRING_CAPABILITY_BYTES)
            if self._next_action == "write1" and self._is_initiator:
                if body:
                    raise ValueError
                next_action = "read2"
                finishes = False
            elif self._next_action == "write2" and not self._is_initiator:
                if body:
                    raise ValueError
                next_action = "read3"
                finishes = False
            elif self._next_action == "write3" and self._is_initiator:
                if len(body) not in {0, PAIRING_CAPABILITY_BYTES}:
                    raise ValueError
                next_action = "complete"
                finishes = True
            else:
                raise ValueError
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore", message="One of ephemeral keypairs is already set.*"
                )
                wire = bytes(self._active_connection().write_message(body))
            if not 32 <= len(wire) <= MAX_CIPHERTEXT_RECORD_BYTES:
                raise ValueError
            self._next_action = next_action
            if finishes:
                self._finish_handshake()
            return wire
        except SecureChannelError:
            raise
        except Exception:
            raise self._fail("authentication_failed") from None

    def read_handshake(self, message: bytes) -> bytes:
        self._require_open()
        try:
            wire = _exact_bytes(message, max_size=MAX_CIPHERTEXT_RECORD_BYTES)
            if not 32 <= len(wire) <= MAX_CIPHERTEXT_RECORD_BYTES:
                raise ValueError
            if self._next_action == "read1" and not self._is_initiator:
                next_action = "write2"
                finishes = False
            elif self._next_action == "read2" and self._is_initiator:
                next_action = "write3"
                finishes = False
            elif self._next_action == "read3" and not self._is_initiator:
                next_action = "complete"
                finishes = True
            else:
                raise ValueError
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore", message="One of ephemeral keypairs is already set.*"
                )
                payload = bytes(self._active_connection().read_message(wire))
            if self._next_action != "read3" and payload:
                raise ValueError
            if self._next_action == "read3" and len(payload) not in {
                0,
                PAIRING_CAPABILITY_BYTES,
            }:
                raise ValueError
            self._next_action = next_action
            if finishes:
                self._finish_handshake()
            return payload
        except SecureChannelError:
            raise
        except _NOISE_ERRORS:
            raise self._fail("authentication_failed") from None
        except Exception:
            raise self._fail("authentication_failed") from None

    def encrypt(self, plaintext: bytes) -> bytes:
        self._require_open()
        if not self.handshake_finished:
            raise SecureChannelError("handshake_not_finished")
        try:
            body = _exact_bytes(plaintext, max_size=MAX_PLAINTEXT_RECORD_BYTES)
        except OverflowError:
            raise SecureChannelError("plaintext_limit") from None
        except (TypeError, ValueError):
            raise SecureChannelError("invalid_plaintext") from None
        try:
            ciphertext = bytes(self._active_connection().encrypt(body))
            if len(ciphertext) > MAX_CIPHERTEXT_RECORD_BYTES:
                raise ValueError
            return ciphertext
        except Exception:
            raise self._fail("transport_failed") from None

    def decrypt(self, ciphertext: bytes) -> bytes:
        self._require_open()
        if not self.handshake_finished:
            raise SecureChannelError("handshake_not_finished")
        try:
            body = _exact_bytes(ciphertext, max_size=MAX_CIPHERTEXT_RECORD_BYTES)
        except OverflowError:
            raise SecureChannelError("ciphertext_limit") from None
        except (TypeError, ValueError):
            raise SecureChannelError("invalid_ciphertext") from None
        if len(body) < 16:
            raise SecureChannelError("ciphertext_limit")
        try:
            plaintext = bytes(self._active_connection().decrypt(body))
            if len(plaintext) > MAX_PLAINTEXT_RECORD_BYTES:
                raise ValueError
            return plaintext
        except Exception:
            raise self._fail("transport_failed") from None

    def mark_admitted(self) -> None:
        self._require_open()
        if not self.handshake_finished:
            raise SecureChannelError("handshake_not_finished")
        if self.admitted:
            raise SecureChannelError("channel_already_admitted")
        self.admitted = True

    def mark_transport_bound(self) -> None:
        self._require_open()
        if not self.handshake_finished or not self.admitted:
            raise SecureChannelError("channel_not_admitted")
        if self.transport_bound:
            raise SecureChannelError("channel_transport_bound")
        self.transport_bound = True

    def close(self) -> None:
        self.closed = True
        self._connection = None


def _deterministic_channel_for_test(
    *,
    initiator: bool,
    static_private_key: bytes,
    ephemeral_private_key: bytes,
    installation_id: bytes,
    remote_static_public_key: bytes | None = None,
) -> NoiseChannel:
    """Private vector-only constructor; production callers cannot inject ephemerals."""

    return NoiseChannel(
        initiator=initiator,
        static_private_key=static_private_key,
        installation_id=installation_id,
        remote_static_public_key=remote_static_public_key,
        _ephemeral_private_key=ephemeral_private_key,
        _test_token=_TEST_CONSTRUCTOR_TOKEN,
    )
