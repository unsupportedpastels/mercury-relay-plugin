"""Post-admission failures identify a safe boundary, never peer content."""

import asyncio
import logging

import pytest
from test_controller_transport import _channels, _lease

from mercury_relay_plugin.controller_transport import (
    ControllerTransportError,
    EncryptedControllerTransport,
)
from mercury_relay_plugin.framing import encode_message
from mercury_relay_plugin.method_policy import MethodPolicy
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


def test_policy_failure_diagnostic_has_type_reason_not_payload(caplog):
    async def exercise():
        mobile, host = _channels()
        websocket = VirtualWebSocket(
            inbound_validator=MethodPolicy(profile="default").validate_text
        )
        lease = _lease(websocket, [])
        channel_id = b"a" * 16
        transport = EncryptedControllerTransport(
            channel=host, attachment=lease.attach(), channel_id=channel_id
        )
        try:
            for record in encode_message(
                channel_id,
                b"b" * 16,
                b'{"jsonrpc":"2.0","id":1,"method":"PRIVATE_PAYLOAD","params":{}}',
            ):
                with pytest.raises(ControllerTransportError, match="protocol_violation"):
                    await transport.feed_ciphertext(mobile.encrypt(record))
            assert "stage=inbound" in caplog.text
            assert "type=MethodPolicyRejected" in caplog.text
            assert "reason=method_not_allowed" in caplog.text
            assert "PRIVATE_PAYLOAD" not in caplog.text
        finally:
            transport.close()
            await lease.release("test_finished")

    with caplog.at_level(logging.WARNING):
        asyncio.run(exercise())
