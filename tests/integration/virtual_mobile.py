"""Synthetic Mercury mobile endpoint for vertical-slice integration tests.

Speaks exactly what a phone would: Noise XK over an outer message-oriented
connection, the encrypted admission envelope, and canonical framed Hermes
JSON-RPC text — using only the plugin's own protocol modules plus the
retained canonical vectors' constructions.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from mercury_relay_plugin.admission import controller_auth_payload  # noqa: E402
from mercury_relay_plugin.framing import (  # noqa: E402
    CHANNEL_ID_SIZE,
    MESSAGE_ID_SIZE,
    Reassembler,
    encode_message,
)
from mercury_relay_plugin.secure_channel import NoiseChannel  # noqa: E402


class VirtualMobile:
    """One synthetic paired-device identity across reconnects."""

    def __init__(self, *, installation_id: bytes, host_public_key: bytes) -> None:
        self.installation_id = installation_id
        self.host_public_key = host_public_key
        self.static_private_key = secrets.token_bytes(32)
        self.device_id: str | None = None
        self.pairing_channel_binding: bytes | None = None

    def _new_channel(self) -> NoiseChannel:
        return NoiseChannel.initiator(
            static_private_key=self.static_private_key,
            installation_id=self.installation_id,
            remote_static_public_key=self.host_public_key,
        )

    async def pair(self, connection, capability: bytes) -> None:
        """Run the pairing handshake; the host records a pending device."""

        channel = self._new_channel()
        await connection.send(channel.write_handshake())
        assert channel.read_handshake(await self._recv(connection)) == b""
        await connection.send(channel.write_handshake(capability))
        self.pairing_channel_binding = channel.channel_binding
        channel.close()
        await connection.close()

    async def open_controller(
        self,
        connection,
        *,
        profile: str,
        resume_cursor: int | None = None,
    ) -> MobileSession:
        """Fresh handshake plus admission envelope on one outer connection."""

        assert self.device_id is not None, "pair and approve first"
        channel = self._new_channel()
        await connection.send(channel.write_handshake())
        assert channel.read_handshake(await self._recv(connection)) == b""
        await connection.send(channel.write_handshake())
        envelope = controller_auth_payload(
            device_id=self.device_id,
            profile=profile,
            resume_cursor=resume_cursor,
        )
        await connection.send(channel.encrypt(envelope))
        return MobileSession(connection, channel)

    @staticmethod
    async def _recv(connection) -> bytes:
        data = await asyncio.wait_for(connection.receive(), timeout=5.0)
        assert data is not None, "host closed the connection"
        return data


class MobileSession:
    """One admitted encrypted controller attachment."""

    def __init__(self, connection, channel: NoiseChannel) -> None:
        self.connection = connection
        self.channel = channel
        self.channel_id = channel.channel_binding[:CHANNEL_ID_SIZE]
        self._reassembler = Reassembler(channel_id=self.channel_id)

    async def send_json(self, value: dict[str, Any]) -> None:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        message_id = secrets.token_bytes(MESSAGE_ID_SIZE)
        for record in encode_message(self.channel_id, message_id, raw):
            await self.connection.send(self.channel.encrypt(record))

    async def next_json(self) -> dict[str, Any]:
        while True:
            data = await asyncio.wait_for(self.connection.receive(), timeout=5.0)
            assert data is not None, "host closed the connection"
            message = self._reassembler.push(self.channel.decrypt(data))
            if message is not None:
                return json.loads(message.decode("utf-8"))

    async def next_matching(self, predicate, *, attempts: int = 50) -> dict[str, Any]:
        for _ in range(attempts):
            frame = await self.next_json()
            if predicate(frame):
                return frame
        raise AssertionError("expected frame was not received")

    async def detach(self) -> None:
        """Simulate outer transport loss without any protocol goodbye."""

        await self.connection.close()
        self.channel.close()
