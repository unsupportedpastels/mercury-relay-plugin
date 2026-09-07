"""A retry identity must not retain every obsolete outer attachment."""

import asyncio
import json

from mercury_relay_plugin.session_lease import SessionLease
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


def test_pending_folder_retry_keeps_only_current_attachment() -> None:
    async def exercise() -> None:
        started = asyncio.Event()
        finish = asyncio.Event()
        calls = 0

        async def dispatch(_method, _params):
            nonlocal calls
            calls += 1
            started.set()
            await finish.wait()
            return {"path": "/workspace/new", "entries": []}

        websocket = VirtualWebSocket()
        await websocket.accept()

        async def close_controller(_controller: str) -> bool:
            return True

        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=websocket,
            close_controller=close_controller,
            read_dispatcher=dispatch,
        )
        lease.start()
        request = json.dumps({
            "jsonrpc": "2.0", "id": "socket-namespace:1",
            "method": "relay.folders.create",
            "params": {"profile": "default", "parent_path": "/workspace", "name": "new"},
        })
        try:
            current = lease.attach(0)
            await current.next_text(timeout=0.5)
            await current.feed_text(request)
            await asyncio.wait_for(started.wait(), timeout=0.5)
            for _ in range(20):
                current.detach()
                current = lease.attach(0)
                await current.next_text(timeout=0.5)
                await current.feed_text(request)
            record = next(iter(lease._mutations.values()))
            assert len(record.waiters) == 1
            assert record.waiters[0][1] is current
            finish.set()
            response = json.loads(await current.next_text(timeout=0.5))
            assert response["result"]["path"] == "/workspace/new"
            assert calls == 1
        finally:
            await lease.release("test_finished")

    asyncio.run(exercise())
