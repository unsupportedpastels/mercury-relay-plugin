from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = PLUGIN_ROOT
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from mercury_relay_plugin.secure_channel import (  # noqa: E402
    MAX_CIPHERTEXT_RECORD_BYTES,
    MAX_PLAINTEXT_RECORD_BYTES,
    NoiseChannel,
    SecureChannelError,
    _deterministic_channel_for_test,
    public_key,
)

NOISE_NEGATIVE_CASES = {
    "wrong-responder-identity",
    "wrong-prologue",
    "tampered-handshake",
    "truncated-handshake",
    "tampered-ciphertext",
    "truncated-ciphertext",
    "wrong-direction",
    "duplicate-replay",
}


def _vector(identifier: str) -> dict:
    corpus = json.loads(
        (REPOSITORY_ROOT / "protocol/vectors/secure-channel/corpus.json").read_text(
            encoding="utf-8"
        )
    )
    return next(vector for vector in corpus["vectors"] if vector["id"] == identifier)


def _vector_pair(vector: dict):
    keys = vector["keys"]
    installation = bytes.fromhex(keys["installation_id"])
    mobile = _deterministic_channel_for_test(
        initiator=True,
        static_private_key=bytes.fromhex(keys["initiator_static_private"]),
        ephemeral_private_key=bytes.fromhex(keys["initiator_ephemeral_private"]),
        installation_id=installation,
        remote_static_public_key=bytes.fromhex(keys["responder_static_public"]),
    )
    host = _deterministic_channel_for_test(
        initiator=False,
        static_private_key=bytes.fromhex(keys["responder_static_private"]),
        ephemeral_private_key=bytes.fromhex(keys["responder_ephemeral_private"]),
        installation_id=installation,
    )
    return mobile, host


def _complete(mobile: NoiseChannel, host: NoiseChannel, final_payload: bytes) -> list[bytes]:
    first = mobile.write_handshake()
    assert host.read_handshake(first) == b""
    second = host.write_handshake()
    assert mobile.read_handshake(second) == b""
    third = mobile.write_handshake(final_payload)
    assert host.read_handshake(third) == final_payload
    return [first, second, third]


@pytest.mark.parametrize("identifier", ["pairing-xk-capability", "reconnect-xk"])
def test_noise_vectors_reproduce_exact_handshake_and_transport_bytes(identifier: str) -> None:
    vector = _vector(identifier)
    mobile, host = _vector_pair(vector)
    payload = bytes.fromhex(vector["handshake_payloads"][2])
    assert [value.hex() for value in _complete(mobile, host, payload)] == vector[
        "handshake_messages"
    ]
    assert mobile.channel_binding.hex() == vector["channel_binding"]
    assert host.channel_binding == mobile.channel_binding
    assert host.remote_static_public == bytes.fromhex(vector["keys"]["initiator_static_public"])

    outbound = bytes.fromhex(vector["transport_messages"][0]["plaintext_hex"])
    ciphertext = mobile.encrypt(outbound)
    assert ciphertext.hex() == vector["transport_messages"][0]["ciphertext_hex"]
    assert host.decrypt(ciphertext) == outbound

    reply = bytes.fromhex(vector["transport_messages"][1]["plaintext_hex"])
    reply_ciphertext = host.encrypt(reply)
    assert reply_ciphertext.hex() == vector["transport_messages"][1]["ciphertext_hex"]
    assert mobile.decrypt(reply_ciphertext) == reply


def test_public_channels_use_fresh_ephemerals_and_hide_test_injection() -> None:
    assert "ephemeral_private_key" not in inspect.signature(NoiseChannel.initiator).parameters
    assert "ephemeral_private_key" not in inspect.signature(NoiseChannel.responder).parameters
    installation = bytes(range(32))
    mobile_private = bytes(range(32, 64))
    host_private = bytes(range(64, 96))

    def first_message() -> bytes:
        channel = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=installation,
            remote_static_public_key=public_key(host_private),
        )
        return channel.write_handshake()

    assert first_message() != first_message()


def test_tampering_wrong_identity_and_replay_close_the_channel() -> None:
    vector = _vector("reconnect-xk")
    mobile, host = _vector_pair(vector)
    first = mobile.write_handshake()
    host.read_handshake(first)
    second = bytearray(host.write_handshake())
    second[-1] ^= 1
    with pytest.raises(SecureChannelError, match="authentication_failed"):
        mobile.read_handshake(bytes(second))
    assert mobile.closed

    mobile, host = _vector_pair(vector)
    _complete(mobile, host, b"")
    plaintext = b"bounded record"
    ciphertext = mobile.encrypt(plaintext)
    assert len(ciphertext) == len(plaintext) + 16
    assert host.decrypt(ciphertext) == plaintext
    with pytest.raises(SecureChannelError, match="transport_failed"):
        host.decrypt(ciphertext)
    assert host.closed

    keys = vector["keys"]
    wrong_mobile = NoiseChannel.initiator(
        static_private_key=bytes.fromhex(keys["initiator_static_private"]),
        installation_id=bytes.fromhex(keys["installation_id"]),
        remote_static_public_key=public_key(bytes(range(1, 33))),
    )
    real_host = NoiseChannel.responder(
        static_private_key=bytes.fromhex(keys["responder_static_private"]),
        installation_id=bytes.fromhex(keys["installation_id"]),
    )
    with pytest.raises(SecureChannelError, match="authentication_failed"):
        real_host.read_handshake(wrong_mobile.write_handshake())
    assert real_host.closed


@pytest.mark.parametrize(
    "case_id",
    [
        "wrong-prologue",
        "truncated-handshake",
        "tampered-ciphertext",
        "truncated-ciphertext",
        "wrong-direction",
    ],
)
def test_remaining_noise_negative_cases_close_the_channel(case_id: str) -> None:
    vector = _vector("reconnect-xk")
    keys = vector["keys"]
    if case_id == "wrong-prologue":
        installation = bytearray.fromhex(keys["installation_id"])
        installation[-1] ^= 1
        mobile = NoiseChannel.initiator(
            static_private_key=bytes.fromhex(keys["initiator_static_private"]),
            installation_id=bytes(installation),
            remote_static_public_key=bytes.fromhex(keys["responder_static_public"]),
        )
        host = NoiseChannel.responder(
            static_private_key=bytes.fromhex(keys["responder_static_private"]),
            installation_id=bytes.fromhex(keys["installation_id"]),
        )
        with pytest.raises(SecureChannelError, match="authentication_failed"):
            host.read_handshake(mobile.write_handshake())
        assert host.closed
        return

    mobile, host = _vector_pair(vector)
    if case_id == "truncated-handshake":
        host.read_handshake(mobile.write_handshake())
        second = host.write_handshake()
        with pytest.raises(SecureChannelError, match="authentication_failed"):
            mobile.read_handshake(second[:-1])
        assert mobile.closed
        return

    _complete(mobile, host, b"")
    ciphertext = mobile.encrypt(b"negative case")
    if case_id == "tampered-ciphertext":
        changed = bytearray(ciphertext)
        changed[-1] ^= 1
        candidate = bytes(changed)
        receiver = host
    elif case_id == "truncated-ciphertext":
        candidate = ciphertext[:-1]
        receiver = host
    else:
        candidate = ciphertext
        receiver = mobile
    with pytest.raises(SecureChannelError, match="transport_failed"):
        receiver.decrypt(candidate)
    assert receiver.closed


def test_canonical_negative_matrix_has_executable_coverage() -> None:
    corpus = json.loads(
        (REPOSITORY_ROOT / "protocol/vectors/secure-channel/corpus.json").read_text(
            encoding="utf-8"
        )
    )
    case_ids = {
        case["id"]
        for vector in corpus["vectors"]
        for case in vector["negative_cases"]
        if case["applicable"]
    }
    assert case_ids == NOISE_NEGATIVE_CASES | {"wrong-pairing-capability"}


def test_transport_record_bounds_are_enforced_before_noise() -> None:
    vector = _vector("reconnect-xk")
    mobile, host = _vector_pair(vector)
    _complete(mobile, host, b"")
    with pytest.raises(SecureChannelError, match="plaintext_limit"):
        mobile.encrypt(b"x" * (MAX_PLAINTEXT_RECORD_BYTES + 1))
    assert not mobile.closed
    with pytest.raises(SecureChannelError, match="ciphertext_limit"):
        host.decrypt(b"x" * (MAX_CIPHERTEXT_RECORD_BYTES + 1))
    assert not host.closed
