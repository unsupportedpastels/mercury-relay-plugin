from __future__ import annotations

import asyncio
import json
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.controller_transport import (  # noqa: E402
    ControllerTransportError,
    EncryptedControllerTransport,
)
from mercury_relay_plugin.framing import Reassembler, encode_message  # noqa: E402
from mercury_relay_plugin.method_policy import ALLOWED_V1_METHODS, MethodPolicy  # noqa: E402
from mercury_relay_plugin.secure_channel import NoiseChannel, public_key  # noqa: E402
from mercury_relay_plugin.session_lease import LeaseLimits, SessionLease  # noqa: E402
from mercury_relay_plugin.virtual_ws import VirtualWebSocket  # noqa: E402


def _channels() -> tuple[NoiseChannel, NoiseChannel]:
    installation = secrets.token_bytes(32)
    mobile_private = secrets.token_bytes(32)
    host_private = secrets.token_bytes(32)
    mobile = NoiseChannel.initiator(
        static_private_key=mobile_private,
        installation_id=installation,
        remote_static_public_key=public_key(host_private),
    )
    host = NoiseChannel.responder(
        static_private_key=host_private,
        installation_id=installation,
    )
    assert host.read_handshake(mobile.write_handshake()) == b""
    assert mobile.read_handshake(host.write_handshake()) == b""
    assert host.read_handshake(mobile.write_handshake()) == b""
    host.mark_admitted()
    return mobile, host


def _lease(
    websocket: VirtualWebSocket,
    closed: list[str],
    *,
    limits: LeaseLimits | None = None,
) -> SessionLease:
    async def close_controller(controller_id: str) -> bool:
        closed.append(controller_id)
        return True

    lease = SessionLease(
        device_id="device-test",
        profile="default",
        controller_id="controller-test",
        websocket=websocket,
        close_controller=close_controller,
        limits=limits,
    )
    lease.start()
    return lease


async def _drain_attach_status(transport, mobile, channel_id: bytes) -> None:
    """Consume the encrypted relay.lease.attached control frame (BR-03)."""

    reassembler = Reassembler(channel_id=channel_id)
    recovered = None
    for ciphertext in await transport.next_ciphertexts(timeout=0.5):
        recovered = reassembler.push(mobile.decrypt(ciphertext))
    assert recovered is not None
    status = json.loads(recovered.decode())
    assert status["method"] == "relay.lease.attached"
    assert status["params"]["replay_gap"] is False


def test_transport_round_trips_fragmented_exact_utf8() -> None:
    async def exercise() -> None:
        mobile, host = _channels()
        websocket = VirtualWebSocket()
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        channel_id = bytes.fromhex("22" * 16)
        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=channel_id,
            message_id_factory=lambda: bytes.fromhex("33" * 16),
        )
        await _drain_attach_status(transport, mobile, channel_id)
        inbound = "  " + ("héllo 🌙" * 10_000) + "  "
        records = encode_message(channel_id, bytes.fromhex("11" * 16), inbound.encode())
        completions = [
            await transport.feed_ciphertext(mobile.encrypt(record)) for record in records
        ]
        assert completions == [False] * (len(records) - 1) + [True]
        assert await websocket.receive_text() == inbound

        outbound = " leading " + ("response " * 9_000)
        await websocket.send_text(outbound)
        ciphertexts = await transport.next_ciphertexts(timeout=0.5)
        reassembler = Reassembler(channel_id=channel_id)
        recovered = None
        for ciphertext in ciphertexts:
            recovered = reassembler.push(mobile.decrypt(ciphertext))
        assert recovered is not None
        assert recovered.decode() == outbound

        # Outer close is only a detach: the inner controller stays leased.
        transport.close()
        assert closed == []
        assert not websocket.closed
        assert not lease.released
        assert await lease.release("test_finished")
        assert closed == ["controller-test"]

    asyncio.run(exercise())


def test_encrypted_path_preserves_allowed_requests_and_stream_events() -> None:
    async def exercise() -> None:
        mobile, host = _channels()
        websocket = VirtualWebSocket(
            inbound_validator=MethodPolicy(
                profile="default",
                profile_authorizer=lambda profile: profile in {"default", "researcher"},
            ).validate_text
        )
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        channel_id = bytes.fromhex("c1" * 16)
        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=channel_id,
        )
        await _drain_attach_status(transport, mobile, channel_id)
        for index, method in enumerate(sorted(ALLOWED_V1_METHODS), start=1):
            raw = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": f"request-{index}",
                    "method": method,
                    "params": {"profile": "researcher"},
                },
                separators=(",", ":"),
            )
            records = encode_message(channel_id, bytes([index]) * 16, raw.encode())
            for record in records:
                await transport.feed_ciphertext(mobile.encrypt(record))
            assert await websocket.receive_text() == raw

        event = '  {"jsonrpc":"2.0","method":"event","params":{"text":" leading"}}  '
        await websocket.send_text(event)
        reassembler = Reassembler(channel_id=channel_id)
        recovered = None
        for ciphertext in await transport.next_ciphertexts(timeout=0.5):
            recovered = reassembler.push(mobile.decrypt(ciphertext))
        assert recovered is not None
        assert recovered.decode() == event
        transport.close()
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_transport_replay_fails_closed_but_preserves_the_lease() -> None:
    async def exercise() -> None:
        mobile, host = _channels()
        websocket = VirtualWebSocket()
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        channel_id = bytes.fromhex("44" * 16)
        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=channel_id,
        )
        record = encode_message(channel_id, bytes.fromhex("55" * 16), b"payload")[0]
        ciphertext = mobile.encrypt(record)
        assert await transport.feed_ciphertext(ciphertext) is True
        with pytest.raises(ControllerTransportError, match="protocol_violation") as caught:
            await transport.feed_ciphertext(ciphertext)
        assert caught.value.reason == "protocol_violation"
        # The outer channel fails closed; the inner controller survives.
        assert host.closed
        assert transport.closed
        assert not websocket.closed
        assert not lease.released
        assert closed == []
        await lease.release("test_finished")
        assert closed == ["controller-test"]

    asyncio.run(exercise())


def test_transport_rejects_malformed_utf8_and_backpressure_without_detail() -> None:
    async def exercise(payload: bytes, *, max_queue_bytes: int) -> ControllerTransportError:
        mobile, host = _channels()
        websocket = VirtualWebSocket(max_queue_bytes=max_queue_bytes)
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        channel_id = bytes.fromhex("66" * 16)
        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=channel_id,
        )
        record = encode_message(channel_id, bytes.fromhex("77" * 16), payload)[0]
        with pytest.raises(ControllerTransportError) as caught:
            await transport.feed_ciphertext(mobile.encrypt(record))
        assert transport.closed
        await lease.release("test_finished")
        return caught.value

    malformed = asyncio.run(exercise(b"\xff", max_queue_bytes=8))
    assert malformed.reason == "malformed_frame"
    assert "utf" not in str(malformed).lower()
    backpressure = asyncio.run(exercise(b"123456", max_queue_bytes=5))
    assert backpressure.reason == "backpressure"


def test_transport_close_wakes_blocked_outbound_reader() -> None:
    async def exercise() -> None:
        _mobile, host = _channels()
        websocket = VirtualWebSocket()
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=bytes.fromhex("88" * 16),
        )
        await _drain_attach_status(transport, _mobile, bytes.fromhex("88" * 16))
        reader = asyncio.create_task(transport.next_ciphertexts())
        await asyncio.sleep(0)
        transport.close()
        with pytest.raises(ControllerTransportError, match="channel_closed"):
            await reader
        # Detach never releases the retained controller.
        assert closed == []
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_attachment_backpressure_detaches_but_keeps_the_controller() -> None:
    async def exercise() -> None:
        _mobile, host = _channels()
        websocket = VirtualWebSocket()
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(
            websocket,
            closed,
            limits=LeaseLimits(max_events=1, max_event_bytes=4),
        )

        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=bytes.fromhex("89" * 16),
        )
        await _drain_attach_status(transport, _mobile, bytes.fromhex("89" * 16))
        await websocket.send_text("abc")
        await websocket.send_text("def")
        await asyncio.sleep(0.01)
        first = await transport.next_ciphertexts(timeout=0.5)
        assert first
        with pytest.raises(ControllerTransportError, match="backpressure"):
            await transport.next_ciphertexts(timeout=0.5)
        assert transport.closed
        assert host.closed
        assert not websocket.closed
        assert closed == []
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_transport_rejects_duplicate_binding_of_one_noise_channel() -> None:
    async def exercise() -> None:
        _mobile, host = _channels()
        websocket = VirtualWebSocket()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        attachment = lease.attach(0)
        EncryptedControllerTransport(
            channel=host,
            attachment=attachment,
            channel_id=bytes.fromhex("99" * 16),
        )
        with pytest.raises(ValueError, match="already bound"):
            EncryptedControllerTransport(
                channel=host,
                attachment=attachment,
                channel_id=bytes.fromhex("99" * 16),
            )
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_natural_inner_close_releases_lease_and_controller_once() -> None:
    async def exercise() -> None:
        _mobile, host = _channels()
        websocket = VirtualWebSocket()
        await websocket.accept()
        closed: list[str] = []
        lease = _lease(websocket, closed)

        transport = EncryptedControllerTransport(
            channel=host,
            attachment=lease.attach(0),
            channel_id=bytes.fromhex("aa" * 16),
        )
        await _drain_attach_status(transport, _mobile, bytes.fromhex("aa" * 16))
        await websocket.close()
        with pytest.raises(ControllerTransportError, match="lease_released"):
            await transport.next_ciphertexts(timeout=0.5)
        assert transport.closed
        assert host.closed
        assert lease.released
        assert lease.release_reason == "controller_closed"
        assert not await lease.release("again")
        assert closed == ["controller-test"]

    asyncio.run(exercise())
