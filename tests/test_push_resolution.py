"""Privacy boundaries for one-time push wake session resolution."""

import asyncio
import json

import httpx
import pytest
from test_push import admitted_peer, emit_and_drain, event

from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.push import PENDING_ROUTE_TTL, PushBridge
from mercury_relay_plugin.session_reads import SessionReadsError

REGISTER = {"device_token": "ab" * 32, "environment": "sandbox"}


async def bind_runtime(rpc, websocket, *, profile="researcher"):
    create = asyncio.create_task(rpc("session.create", {"profile": profile}))
    request = json.loads(await asyncio.wait_for(websocket.receive_text(), 2))
    await websocket.send_text(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "session_id": "runtime-private",
                    "stored_session_id": "durable-private",
                    "info": {"profile_name": profile},
                },
            }
        )
    )
    assert (await create)["result"]["session_id"] == "runtime-private"


def test_bound_completion_and_input_resolve_once_over_encrypted_channel(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, attached, _ = await admitted_peer(tmp_path)
        try:
            assert attached["params"]["capabilities"] == {
                "push_notifications_v1": True,
                "push_notifications_v2": True,
                "push_notification_routes": {"version": 1, "inspect_method": "relay.push.inspect"},
            }
            handle = (await rpc("relay.push.register", REGISTER))["result"]["wake_handle"]
            await bind_runtime(rpc, admitted.lease.websocket)

            for notification in (
                event(
                    "message.complete",
                    {"text": "PRIVATE answer", "status": "complete"},
                    session_id="runtime-private",
                ),
                event(
                    "approval.request",
                    {"request_id": "private-approval", "command": "PRIVATE command"},
                    session_id="runtime-private",
                ),
            ):
                await emit_and_drain(admitted, service.push, notification)
                wake = json.loads(requests[-1].content)
                assert set(wake) == {"wake_handle", "event_id"}
                assert wake["wake_handle"] == handle
                assert "durable-private" not in requests[-1].content.decode()
                assert "researcher" not in requests[-1].content.decode()

                resolved = await rpc("relay.push.resolve", {"wake_handle": handle})
                assert resolved["result"] == {
                    "resolved": True,
                    "durable_session_id": "durable-private",
                    "profile": "researcher",
                }
                assert (await rpc("relay.push.resolve", {"wake_handle": handle}))["result"] == {
                    "resolved": False
                }

            status = (await rpc("relay.status", {}))["result"]
            assert status["capabilities"]["push_notifications_v1"] is True
            assert status["capabilities"]["push_notifications_v2"] is True
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_unbound_event_still_wakes_but_resolves_false(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, _, _ = await admitted_peer(tmp_path)
        try:
            handle = (await rpc("relay.push.register", REGISTER))["result"]["wake_handle"]
            await bind_runtime(rpc, admitted.lease.websocket)
            await emit_and_drain(
                admitted,
                service.push,
                event(
                    "message.complete",
                    {"text": "bound first", "status": "complete"},
                    session_id="runtime-private",
                ),
            )
            assert handle in service.push.pending_routes
            await emit_and_drain(
                admitted,
                service.push,
                event("clarify.request", {"request_id": "private"}),
            )
            assert requests[-1].url.path.endswith("/wake")
            assert (await rpc("relay.push.resolve", {"wake_handle": handle}))["result"] == {
                "resolved": False
            }
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_resolve_fences_wrong_owner_expiry_and_revocation(tmp_path):
    async def run():
        now = [100.0]

        def peer(_request):
            return httpx.Response(200)

        bridge = PushBridge(
            paths=profile_paths(explicit_path=tmp_path),
            relay_origin="https://relay.example",
            installation_id=b"a" * 32,
            token_provider=lambda: "token",
            authorized=lambda device, epoch: device == "owner" and epoch == 7,
            transport=httpx.MockTransport(peer),
            clock=lambda: now[0],
        )
        try:
            handle = (await bridge.dispatch("owner", 7, "relay.push.register", REGISTER))[
                "wake_handle"
            ]
            route = {"durable_session_id": "durable", "profile": "default"}
            bridge.wake("owner", 7, b"bound", route)
            await bridge.drain()

            assert await bridge.dispatch(
                "other", 7, "relay.push.resolve", {"wake_handle": handle}
            ) == {"resolved": False}
            assert await bridge.dispatch(
                "owner", 8, "relay.push.resolve", {"wake_handle": handle}
            ) == {"resolved": False}
            assert await bridge.dispatch(
                "owner", 7, "relay.push.resolve", {"wake_handle": "x" * 43}
            ) == {"resolved": False}
            assert await bridge.dispatch(
                "owner", 7, "relay.push.resolve", {"wake_handle": handle}
            ) == {
                "resolved": True,
                "durable_session_id": "durable",
                "profile": "default",
            }

            bridge.wake("owner", 7, b"expires", route)
            await bridge.drain()
            now[0] += PENDING_ROUTE_TTL
            assert await bridge.dispatch(
                "owner", 7, "relay.push.resolve", {"wake_handle": handle}
            ) == {"resolved": False}

            bridge.wake("owner", 7, b"revoked", route)
            await bridge.drain()
            assert handle in bridge.pending_routes
            bridge.revoke("owner", 7)
            assert handle not in bridge.pending_routes
            assert await bridge.dispatch(
                "owner", 7, "relay.push.resolve", {"wake_handle": handle}
            ) == {"resolved": False}
            await bridge.drain()

            handle = (await bridge.dispatch("owner", 7, "relay.push.register", REGISTER))[
                "wake_handle"
            ]
            bridge.wake("owner", 7, b"unregistered", route)
            await bridge.drain()
            assert handle in bridge.pending_routes
            assert await bridge.dispatch("owner", 7, "relay.push.unregister", {}) == {
                "registered": False
            }
            assert handle not in bridge.pending_routes
            assert await bridge.dispatch(
                "owner", 7, "relay.push.resolve", {"wake_handle": handle}
            ) == {"resolved": False}
            await bridge.drain()
        finally:
            await bridge.close()

    asyncio.run(run())


@pytest.mark.parametrize("params", [{}, {"wake_handle": True}, {"wake_handle": "x" * 43, "x": 1}])
def test_resolve_rejects_malformed_params(tmp_path, params):
    async def run():
        bridge = PushBridge(
            paths=profile_paths(explicit_path=tmp_path),
            relay_origin="https://relay.example",
            installation_id=b"a" * 32,
            token_provider=lambda: "token",
            authorized=lambda _device, _epoch: True,
            transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
        )
        try:
            with pytest.raises(SessionReadsError, match="invalid_params"):
                await bridge.dispatch("owner", 7, "relay.push.resolve", params)
        finally:
            await bridge.close()

    asyncio.run(run())