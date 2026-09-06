"""Official recovery status read must not kill the admitted controller."""

import asyncio
import json

from test_controller_transport import _channels, _lease

from mercury_relay_plugin.controller_transport import EncryptedControllerTransport
from mercury_relay_plugin.framing import encode_message
from mercury_relay_plugin.method_policy import MethodPolicy
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


def test_recovery_delegation_status_then_second_send_preserves_channel():
    async def exercise():
        mobile, host = _channels()
        websocket = VirtualWebSocket(
            inbound_validator=MethodPolicy(profile="default").validate_text
        )
        lease = _lease(websocket, [])
        channel_id = b"a" * 16
        transport = EncryptedControllerTransport(
            channel=host, attachment=lease.attach(recovery=True), channel_id=channel_id
        )
        try:
            # Exact client loadDelegationStatus wire shape, followed by explicit Send.
            frames = [
                {"jsonrpc": "2.0", "id": "recovery-1", "method": "delegation.status", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": "recovery-2",
                    "method": "prompt.submit",
                    "params": {
                        "session_id": "runtime",
                        "text": "second",
                        "submission_id": "second-once",
                    },
                },
            ]
            for index, frame in enumerate(frames):
                raw = json.dumps(frame)
                for record in encode_message(channel_id, bytes([index]) * 16, raw.encode()):
                    await transport.feed_ciphertext(mobile.encrypt(record))
                assert await websocket.receive_text() == raw
            # An explicit duplicate ID is deduplicated, not fed to Hermes twice.
            for record in encode_message(channel_id, b"z" * 16, json.dumps(frames[-1]).encode()):
                await transport.feed_ciphertext(mobile.encrypt(record))
            assert websocket._inbound.empty()
            assert not transport.closed
        finally:
            transport.close()
            await lease.release("test_finished")

    asyncio.run(exercise())
