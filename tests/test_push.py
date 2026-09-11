"""Offline APNs bridge harness: real Noise admission, fake Hermes + HTTPS peer."""

import asyncio
import base64
import hashlib
import json
import re
import secrets

import httpx
import pytest
from test_admission import _handshake, _runtime

from mercury_relay_plugin.admission import DeviceAdmissionService, controller_auth_payload
from mercury_relay_plugin.authorization import AuthorizationRepository
from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.framing import Reassembler, encode_message
from mercury_relay_plugin.secure_channel import NoiseChannel


async def admitted_peer(tmp_path, *, enabled=True, handler=None):
    from mercury_relay_plugin.push import PushBridge
    from mercury_relay_plugin.routing_auth import RoutingIssuerStore

    repository = AuthorizationRepository(profile_paths(explicit_path=tmp_path))
    runtime = _runtime()
    await runtime.start()
    service = DeviceAdmissionService(repository, runtime, profile="default")
    offer = repository.create_offer()
    private = secrets.token_bytes(32)

    def channels():
        return NoiseChannel.initiator(
            static_private_key=private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        ), service.new_host_channel()

    mobile, host = channels()
    service.complete_pairing(host, _handshake(mobile, host, final_payload=offer.capability))
    device = repository.list_devices()[0].device_id
    repository.approve(device, hashlib.sha256(host.channel_binding).digest())
    requests = []

    async def peer(request):
        requests.append(request)
        if handler:
            return await handler(request)
        return httpx.Response(200, json={"ok": True})

    if enabled:
        issuer = RoutingIssuerStore(repository.store).load_or_create()
        service.push = PushBridge(
            paths=repository.paths,
            relay_origin="https://relay.example",
            installation_id=offer.installation_id,
            token_provider=lambda: issuer.mint_host_token(offer.installation_id),
            authorized=lambda d, e: service._epoch(d) == e,
            transport=httpx.MockTransport(peer),
        )
    mobile, host = channels()
    _handshake(mobile, host, final_payload=b"")
    admitted = await service.open_controller(
        host,
        mobile.encrypt(
            controller_auth_payload(
                device_id=device,
                profile="default",  # deliberately older, non-recovery client
            )
        ),
    )
    channel_id = host.channel_binding[:16]
    transport = service.bind_controller(admitted, channel_id=channel_id)
    reassembler = Reassembler(channel_id=channel_id)
    counter = 0

    async def read():
        for ciphertext in await transport.next_ciphertexts():
            complete = reassembler.push(mobile.decrypt(ciphertext))
            if complete is not None:
                return json.loads(complete)

    async def rpc(method, params):
        nonlocal counter
        counter += 1
        text = json.dumps({"jsonrpc": "2.0", "id": counter, "method": method, "params": params})
        for frame in encode_message(channel_id, counter.to_bytes(16, "big"), text.encode()):
            await transport.feed_ciphertext(mobile.encrypt(frame))
        return await asyncio.wait_for(read(), 2)

    status = await asyncio.wait_for(read(), 2)
    return service, runtime, admitted, rpc, requests, status, offer


def event(kind, payload=None, **params):
    return {
        "jsonrpc": "2.0",
        "method": "event",
        "params": {
            "type": kind,
            "session_id": "private-session",
            "payload": payload or {},
            **params,
        },
    }


def test_admitted_registration_and_detached_generic_wake(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, status, offer = await admitted_peer(tmp_path)
        try:
            assert status["params"]["capabilities"]["push_notifications_v1"] is True
            result = (
                await rpc(
                    "relay.push.register",
                    {
                        "device_token": "ab" * 32,
                        "environment": "sandbox",
                    },
                )
            )["result"]
            assert result["registered"] is True
            handle = result["wake_handle"]
            assert re.fullmatch(r"[A-Za-z0-9_-]{43}", handle)
            route = base64.urlsafe_b64encode(offer.installation_id).decode().rstrip("=")
            assert requests[0].url.path == f"/v1/push/{route}/register"
            assert json.loads(requests[0].content) == {
                "wake_handle": handle,
                "device_token": "ab" * 32,
                "environment": "sandbox",
            }
            # The retained reader runs whether TCP appears attached or is detached.
            ws = admitted.lease.websocket
            await ws.send_text(json.dumps(event("message.start", seq=1)))
            complete = event(
                "message.complete", {"text": "PRIVATE answer", "status": "complete"}, seq=2
            )
            await ws.send_text(json.dumps(complete))
            await ws.send_text(json.dumps(complete))
            await asyncio.wait_for(service.push.drain(), 2)
            # Pump scheduling barrier: next outgoing frame proves retention observed it.
            while admitted.lease.last_seq < 3:
                await asyncio.sleep(0)
            await service.push.drain()
            assert len(requests) == 2
            admitted.attachment.detach()
            await ws.send_text(
                json.dumps(
                    event(
                        "approval.request",
                        {"request_id": "private-approval", "command": "PRIVATE command"},
                        seq=3,
                    )
                )
            )
            while admitted.lease.last_seq < 4:
                await asyncio.sleep(0)
            await service.push.drain()
            assert len(requests) == 3
            from mercury_relay_plugin.routing_auth import RoutingIssuerStore, verify_routing_token

            issuer = RoutingIssuerStore(service.repository.store).load_or_create()
            tokens = set()
            for request in requests[1:]:
                assert request.url.path == f"/v1/push/{route}/wake"
                body = json.loads(request.content)
                assert set(body) == {"wake_handle", "event_id"}
                assert body["wake_handle"] == handle
                assert re.fullmatch(r"[A-Za-z0-9_-]{43}", body["event_id"])
                assert "PRIVATE" not in request.content.decode()
                token = request.headers["authorization"].removeprefix("Bearer ")
                claims = verify_routing_token(
                    token, public_key=issuer.public_key, installation=route
                )
                assert claims["role"] == "host"
                tokens.add(token)
            assert len(tokens) == len(requests) - 1
            await service.revoke_device(admitted.device_id)
            await service.push.drain()
            assert requests[-1].url.path.endswith("/unregister")
            assert json.loads(requests[-1].content) == {"wake_handle": handle}
            assert "ab" * 32 not in (tmp_path / "mercury-relay" / "push.json").read_text()
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


async def emit_and_drain(admitted, bridge, *events):
    target = admitted.lease.last_seq + len(events)
    for frame in events:
        await admitted.lease.websocket.send_text(json.dumps(frame))

    async def retained():
        while admitted.lease.last_seq < target:
            await asyncio.sleep(0)

    await asyncio.wait_for(retained(), 2)
    await asyncio.wait_for(bridge.drain(), 2)


def test_input_completion_filter_turn_dedup_and_unregister(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, _, _ = await admitted_peer(tmp_path)
        try:
            await rpc("relay.push.register", {"device_token": "cd" * 16, "environment": "sandbox"})
            assert (await rpc("relay.status", {}))["result"]["capabilities"][
                "push_notifications_v1"
            ]
            good = event("message.complete", {"text": "answer", "status": "complete"})
            rejected = [
                event("tool.complete", {"text": "tool"}),
                event("message.interim", {"text": "interim"}),
                event("message.complete", {"text": "user", "role": "user"}),
                event("message.complete", {"text": "tool", "role": "tool"}),
                event("message.complete", {"text": "stop", "status": "interrupted"}),
                event(
                    "message.complete",
                    {"text": "Operation interrupted: waiting for model response"},
                ),
                event("message.complete", {"text": "interim", "interim": True}),
                event("message.complete", {"text": "history"}, replay=True),
                {"jsonrpc": "2.0", "id": 99, "result": {"events": [good]}},
                {
                    "method": "relay.lease.frame",
                    "params": {"replay": True, "frame": json.dumps(good)},
                },
                event("clarify.request", {"question": "missing identifier"}),
                event("approval.request", {"request_id": "nonblocking", "blocking": False}),
            ]
            await emit_and_drain(admitted, service.push, *rejected)
            assert len(requests) == 1
            await emit_and_drain(admitted, service.push, event("message.start"), good, good)
            assert len(requests) == 2
            # Same answer next turn still wakes (not time-window/content dedup).
            await emit_and_drain(admitted, service.push, event("message.start"), good, good)
            assert len(requests) == 3
            from mercury_relay_plugin.push import INPUT_EVENTS

            for kind in INPUT_EVENTS:
                frame = event(kind, {"request_id": "same-private-request", "text": "PRIVATE"})
                await emit_and_drain(admitted, service.push, frame, frame)
            assert len(requests) == 3 + len(INPUT_EVENTS)
            before_replay = len(requests)
            admitted.attachment.detach()
            attachment = admitted.lease.attach(0)
            # Replaying existing ring must not notify again.
            for _ in range(admitted.lease.last_seq + 1):
                await attachment.next_text(timeout=2)
            await service.push.drain()
            assert len(requests) == before_replay
            # New attachment: exercise the existing authorized local dispatcher.
            response_id = "unregister"
            await attachment.feed_text(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": response_id,
                        "method": "relay.push.unregister",
                        "params": {},
                    }
                )
            )
            result = json.loads(await attachment.next_text(timeout=2))
            assert result["result"] == {"registered": False}
            await service.push.drain()
            assert requests[-1].url.path.endswith("/unregister")
            before = len(requests)
            await emit_and_drain(admitted, service.push, event("message.start"), good)
            assert len(requests) == before
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "params",
    [
        {"device_token": "ab" * 15, "environment": "sandbox"},
        {"device_token": "ab" * 101, "environment": "sandbox"},
        {"device_token": "a" * 33, "environment": "sandbox"},
        {"device_token": "AB" * 32, "environment": "sandbox"},
        {"device_token": "ag" * 32, "environment": "sandbox"},
        {"device_token": "ab" * 32, "environment": "production"},
        {"device_token": "ab" * 32, "environment": "sandbox", "device_id": "other"},
        {"device_token": True, "environment": "sandbox"},
        {},
    ],
)
def test_admitted_register_rejects_noncanonical_or_caller_identity(tmp_path, params):
    async def run():
        service, runtime, admitted, rpc, requests, _, _ = await admitted_peer(tmp_path)
        try:
            assert (await rpc("relay.push.register", params))["error"][
                "message"
            ] == "invalid_params"
            assert requests == []
            assert admitted.lease.last_seq == 0  # no forwarded Hermes unknown-method response
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_disabled_older_client_has_no_push_capability_and_no_forwarding(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, attached, _ = await admitted_peer(
            tmp_path, enabled=False
        )
        try:
            assert "push_notifications_v1" not in attached["params"].get("capabilities", {})
            result = await rpc("relay.status", {})
            assert "push_notifications_v1" not in result["result"].get("capabilities", {})
            assert (
                await rpc(
                    "relay.push.register", {"device_token": "ab" * 32, "environment": "sandbox"}
                )
            )["error"]["message"] == "push_unavailable"
            assert (await rpc("relay.push.unregister", {}))["error"][
                "message"
            ] == "push_unavailable"
            assert requests == []
            assert admitted.lease.last_seq == 0
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_revoke_cancels_inflight_and_queued_wakes_even_if_delete_fails(tmp_path):
    async def run():
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def handler(request):
            if request.url.path.endswith("/wake"):
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()
            return httpx.Response(503 if request.url.path.endswith("/unregister") else 200)

        service, runtime, admitted, rpc, requests, _, offer = await admitted_peer(
            tmp_path, handler=handler
        )
        bridge = service.push
        try:
            registered = (
                await rpc(
                    "relay.push.register", {"device_token": "ab" * 32, "environment": "sandbox"}
                )
            )["result"]
            handle = registered["wake_handle"]
            epoch = admitted.lease.authorization_epoch
            bridge.wake(admitted.device_id, epoch, b"first")
            await asyncio.wait_for(entered.wait(), 2)
            for n in range(200):
                bridge.wake(admitted.device_id, epoch, str(n).encode())
            assert bridge.queue.qsize() <= 64
            # Reader is not blocked behind the stalled HTTP operation.
            await admitted.lease.websocket.send_text(
                json.dumps(event("message.delta", {"text": "still streaming"}))
            )

            async def retained():
                while admitted.lease.last_seq < 1:
                    await asyncio.sleep(0)

            await asyncio.wait_for(retained(), 2)
            await service.revoke_device(admitted.device_id)
            await asyncio.wait_for(cancelled.wait(), 2)
            await asyncio.wait_for(bridge.drain(), 2)
            bridge.wake(admitted.device_id, epoch, b"after revoke")
            await bridge.drain()
            assert sum(r.url.path.endswith("/wake") for r in requests) == 1
            assert any(r.url.path.endswith("/unregister") for r in requests)
            assert bridge.rows[handle]["active"] is False
            assert (bridge.path.stat().st_mode & 0o777) == 0o600
            # Cleanup debt survives failure and retries on next lifecycle.
            from mercury_relay_plugin.push import PushBridge

            await service.close()
            retry = PushBridge(
                paths=service.repository.paths,
                relay_origin="https://relay.example",
                installation_id=offer.installation_id,
                token_provider=bridge.token_provider,
                authorized=lambda d, e: False,
                transport=httpx.MockTransport(lambda request: httpx.Response(200)),
            )
            await retry.drain()
            assert retry.rows == {}
            await retry.close()
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())
