"""A runnable lease pump must not be starved by a buffered controller batch."""

import asyncio
import json

import pytest
from conftest import contract_import
from test_session_lease import Controllers

from mercury_relay_plugin.session_lease import SessionLease
from mercury_relay_plugin.virtual_ws import VirtualWebSocket, VirtualWebSocketBackpressure


@pytest.mark.parametrize("real_writer", [False, True])
def test_controller_burst_crosses_retention_without_releasing_v1_lease(real_writer):
    async def run():
        ws = VirtualWebSocket()
        controllers = Controllers()
        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="c",
            websocket=ws,
            close_controller=controllers.close,
        )
        await ws.accept()
        lease.start()
        attachment = lease.attach(recovery=True)
        attachment.detach()
        identity = lease.lease_id
        count = max(ws.max_queue_items, lease.limits.max_events) * 3
        try:
            frames = [json.dumps({"jsonrpc": "2.0", "id": i, "result": {}}) for i in range(count)]
            if real_writer:
                writer_type = contract_import("tui_gateway.ws").WSTransport
                writer = writer_type(ws, asyncio.get_running_loop())
                await writer._safe_send_many(frames)
                assert not writer.closed
            else:
                # Same producer shape as WSTransport: no producer-side sleeps.
                for frame in frames:
                    await ws.send_text(frame)
            await asyncio.sleep(0)
            assert not ws.closed
            assert not lease.released
            assert lease.last_seq == count
            assert len(lease._ring) <= lease.limits.max_events
            assert lease._ring_bytes <= lease.limits.max_event_bytes
            restored = lease.attach(cursor=0, recovery=True)
            status = json.loads(await restored.next_text())
            assert status["params"]["replay_gap"] is True
            assert status["params"]["lease_id"] == identity
            replayed = []
            while True:
                frame = json.loads(await restored.next_text())
                if frame["method"] == "relay.lease.replay_complete":
                    break
                replayed.append(frame["params"]["seq"])
            assert replayed == list(range(lease.trimmed_through + 1, count + 1))
            await restored.feed_text('{"jsonrpc":"2.0","id":"next","method":"ping"}')
            assert json.loads(await ws.receive_text())["id"] == "next"
        finally:
            await lease.release()

    asyncio.run(run())


def test_outbound_without_a_consumer_still_fails_closed_at_original_bound():
    async def run():
        ws = VirtualWebSocket(max_queue_items=2)
        await ws.send_text("one")
        await ws.send_text("two")
        with pytest.raises(VirtualWebSocketBackpressure):
            await ws.send_text("three")
        assert ws.closed
        assert ws.close_code == 1013
        assert ws.close_reason == "outbound_backpressure"

    asyncio.run(run())
