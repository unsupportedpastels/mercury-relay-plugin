"""Synthetic queue/backpressure regressions: no live push services."""

import asyncio
import json

import httpx
import pytest
from test_push_preview import PARAMS, preview_bridge

from mercury_relay_plugin.push import QUEUE_SIZE


@pytest.mark.parametrize("elapsed", [115, 120, 121])
def test_backlogged_preview_is_dropped_before_expiry_budget(tmp_path, elapsed):
    async def run():
        now = [2_000_000_000]
        calls = []
        entered, release = asyncio.Event(), asyncio.Event()

        async def peer(request):
            calls.append(request)
            if request.url.path.endswith("/wake") and not entered.is_set():
                entered.set()
                await release.wait()
            return httpx.Response(200)

        bridge = preview_bridge(tmp_path, calls, wall_clock=lambda: now[0])
        await bridge._client.aclose()
        bridge._client = httpx.AsyncClient(transport=httpx.MockTransport(peer))
        try:
            handle = (await bridge.dispatch("device", 4, "relay.push.preview.register", PARAMS))[
                "wake_handle"
            ]
            data = {"kind": "completion", "response_text": "Synthetic private answer"}
            route = {"durable_session_id": "synthetic-session", "profile": "default"}
            bridge.wake("device", 4, b"blocking", route, data)
            await asyncio.wait_for(entered.wait(), 2)
            bridge.wake("device", 4, b"queued", route, data)
            queued_id = bridge.pending_routes[handle]["event_id"]
            now[0] += elapsed
            release.set()
            await asyncio.wait_for(bridge.drain(), 2)
            wakes = [r for r in calls if r.url.path.endswith("/wake")]
            assert len(wakes) == 1
            assert await bridge.dispatch("device", 4, "relay.push.inspect", {
                "wake_handle": handle, "event_id": queued_id,
            }) == {"resolved": False}
            assert handle not in bridge.pending_routes
            # A stale job must not stop the worker or expose local expiry metadata.
            bridge.wake("device", 4, b"fresh", route, data)
            await bridge.drain()
            assert len(calls) == 3
            assert set(json.loads(calls[-1].content)) == {"wake_handle", "event_id", "preview"}
            assert b"Synthetic private answer" not in calls[-1].content
        finally:
            release.set()
            await bridge.close()

    asyncio.run(run())


def test_failed_enqueue_preserves_last_accepted_generic_route(tmp_path):
    async def run():
        calls = []
        bridge = preview_bridge(tmp_path, calls)
        try:
            handle = (await bridge.dispatch("device", 4, "relay.push.register", {
                "device_token": "ab" * 32, "environment": "sandbox",
            }))["wake_handle"]
            route = {"durable_session_id": "accepted-session", "profile": "default"}
            bridge.wake("device", 4, b"accepted", route)
            await bridge.drain()
            event_id = json.loads(calls[-1].content)["event_id"]
            # No await: fill the real queue before its consumer can run.
            for index in range(QUEUE_SIZE):
                assert bridge._enqueue("wake", handle, {"event_id": f"filler-{index}"})
            bridge.wake("device", 4, b"rejected", {
                "durable_session_id": "never-accepted", "profile": "default",
            })
            assert await bridge.dispatch("device", 4, "relay.push.resolve", {
                "wake_handle": handle,
            }) == {"resolved": True, **route}
            assert await bridge.dispatch("device", 4, "relay.push.inspect", {
                "wake_handle": handle, "event_id": event_id,
            }) == {"resolved": True, **route}
        finally:
            await bridge.close()

    asyncio.run(run())
