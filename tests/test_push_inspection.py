"""Non-consuming event-scoped arrival reads; provider sees random IDs only."""

import asyncio
import json

import httpx
from test_push import admitted_peer, emit_and_drain, event
from test_push_resolution import REGISTER, bind_runtime

from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.push import PENDING_ROUTE_TTL, PushBridge


def test_inspection_over_noise_preserves_tap_and_exact_older_event(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, _, _ = await admitted_peer(tmp_path)
        try:
            handle = (await rpc("relay.push.register", REGISTER))["result"]["wake_handle"]
            await bind_runtime(rpc, admitted.lease.websocket)
            await emit_and_drain(
                admitted,
                service.push,
                event("message.complete", {"text": "test"}, session_id="runtime-private"),
            )
            first = json.loads(requests[-1].content)["event_id"]
            params = {"wake_handle": handle, "event_id": first}
            expected = {
                "resolved": True,
                "durable_session_id": "durable-private",
                "profile": "researcher",
            }
            assert (await rpc("relay.push.inspect", params))["result"] == expected
            assert (await rpc("relay.push.inspect", params))["result"] == expected
            assert (await rpc("relay.push.resolve", {"wake_handle": handle}))["result"] == expected
            assert (await rpc("relay.push.resolve", {"wake_handle": handle}))["result"] == {
                "resolved": False
            }
            await emit_and_drain(
                admitted,
                service.push,
                event("approval.request", {"request_id": "next"}, session_id="runtime-private"),
            )
            assert (await rpc("relay.push.inspect", params))["result"] == expected
            assert (await rpc("relay.push.inspect", {"wake_handle": handle, "event_id": "x" * 43}))[
                "result"
            ] == {"resolved": False}
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_inspection_bounds_expiry_revocation_and_owner(tmp_path):
    async def run():
        now = [100.0]
        requests = []

        def peer(request):
            requests.append(json.loads(request.content))
            return httpx.Response(200)

        bridge = PushBridge(
            paths=profile_paths(explicit_path=tmp_path),
            relay_origin="https://relay.example",
            installation_id=b"a" * 32,
            token_provider=lambda: "test",
            authorized=lambda d, e: d == "owner" and e == 7,
            transport=httpx.MockTransport(peer),
            clock=lambda: now[0],
        )
        try:
            handle = (await bridge.dispatch("owner", 7, "relay.push.register", REGISTER))[
                "wake_handle"
            ]
            bridge.wake("owner", 7, b"first", {"durable_session_id": "first", "profile": "default"})
            await bridge.drain()
            params = {"wake_handle": handle, "event_id": requests[-1]["event_id"]}
            for d, e in [("other", 7), ("owner", 8)]:
                assert await bridge.dispatch(d, e, "relay.push.inspect", params) == {
                    "resolved": False
                }
            for n in range(70):
                bridge.wake(
                    "owner",
                    7,
                    str(n).encode(),
                    {"durable_session_id": "other", "profile": "default"},
                )
                await bridge.drain()
            assert len(bridge.arrival_routes) <= 64
            assert await bridge.dispatch("owner", 7, "relay.push.inspect", params) == {
                "resolved": False
            }
            params["event_id"] = requests[-1]["event_id"]
            assert (await bridge.dispatch("owner", 7, "relay.push.inspect", params))["resolved"]
            now[0] += PENDING_ROUTE_TTL
            assert await bridge.dispatch("owner", 7, "relay.push.inspect", params) == {
                "resolved": False
            }
            bridge.wake("owner", 7, b"last", {"durable_session_id": "last", "profile": "default"})
            await bridge.drain()
            params["event_id"] = requests[-1]["event_id"]
            bridge.revoke("owner", 7)
            assert await bridge.dispatch("owner", 7, "relay.push.inspect", params) == {
                "resolved": False
            }
            assert not bridge.arrival_routes
        finally:
            await bridge.close()

    asyncio.run(run())
