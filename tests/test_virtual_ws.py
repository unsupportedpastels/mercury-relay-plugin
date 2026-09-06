from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from conftest import contract_import

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.virtual_ws import (  # noqa: E402
    VirtualWebSocket,
    VirtualWebSocketBackpressure,
    VirtualWebSocketFrameTooLarge,
)


def test_virtual_websocket_preserves_text_exactly() -> None:
    async def exercise() -> None:
        ws = VirtualWebSocket(max_queue_items=2, max_frame_bytes=32)
        await ws.accept()
        await ws.feed_text("  leading and trailing  ")
        assert await ws.receive_text() == "  leading and trailing  "
        await ws.send_text(" outbound ")
        assert await ws.next_text(timeout=0.1) == " outbound "

    asyncio.run(exercise())


def test_virtual_websocket_rejects_oversized_frames() -> None:
    async def exercise() -> None:
        ws = VirtualWebSocket(max_queue_items=2, max_frame_bytes=4)
        await ws.accept()
        with pytest.raises(VirtualWebSocketFrameTooLarge):
            await ws.feed_text("12345")
        with pytest.raises(VirtualWebSocketFrameTooLarge):
            await ws.send_text("12345")

    asyncio.run(exercise())


def test_virtual_websocket_enforces_aggregate_byte_budgets() -> None:
    async def exercise() -> None:
        inbound = VirtualWebSocket(
            max_queue_items=4,
            max_frame_bytes=4,
            max_queue_bytes=5,
        )
        await inbound.accept()
        await inbound.feed_text("abc")
        with pytest.raises(VirtualWebSocketBackpressure, match="byte budget"):
            await inbound.feed_text("def")
        assert inbound.closed

        outbound = VirtualWebSocket(
            max_queue_items=4,
            max_frame_bytes=4,
            max_queue_bytes=5,
        )
        await outbound.accept()
        await outbound.send_text("abc")
        assert await outbound.next_text(timeout=0.1) == "abc"
        await outbound.send_text("def")
        assert await outbound.next_text(timeout=0.1) == "def"

        saturated = VirtualWebSocket(
            max_queue_items=4,
            max_frame_bytes=4,
            max_queue_bytes=5,
        )
        await saturated.accept()
        await saturated.send_text("abc")
        with pytest.raises(VirtualWebSocketBackpressure, match="byte budget"):
            await saturated.send_text("def")
        assert saturated.closed

    asyncio.run(exercise())


def test_virtual_websocket_fails_closed_on_backpressure() -> None:
    contract_import("starlette.websockets")

    async def exercise() -> None:
        ws = VirtualWebSocket(max_queue_items=1, max_frame_bytes=32)
        await ws.accept()
        await ws.feed_text("one")
        with pytest.raises(VirtualWebSocketBackpressure):
            await ws.feed_text("two")
        assert ws.closed
        with pytest.raises(Exception) as caught:
            await ws.receive_text()
        assert type(caught.value).__name__ == "WebSocketDisconnect"

    asyncio.run(exercise())


def test_close_wakes_a_blocked_receiver() -> None:
    contract_import("starlette.websockets")

    async def exercise() -> None:
        ws = VirtualWebSocket(max_queue_items=1, max_frame_bytes=32)
        await ws.accept()
        receiver = asyncio.create_task(ws.receive_text())
        await asyncio.sleep(0)
        await ws.close(code=1000)
        with pytest.raises(Exception) as caught:
            await receiver
        assert type(caught.value).__name__ == "WebSocketDisconnect"

    asyncio.run(exercise())


def test_close_wakes_a_blocked_outbound_reader() -> None:
    async def exercise() -> None:
        ws = VirtualWebSocket(max_queue_items=1, max_frame_bytes=32)
        await ws.accept()
        reader = asyncio.create_task(ws.next_text())
        await asyncio.sleep(0)
        await ws.close(code=1000)
        with pytest.raises(Exception, match="closed"):
            await reader

    asyncio.run(exercise())
