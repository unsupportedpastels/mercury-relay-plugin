"""Push lifecycle failure boundaries; all network peers are local fakes."""

import asyncio
import json

import httpx
import pytest
from conftest import contract_import
from test_push import admitted_peer

from mercury_relay_plugin.push import PushBridge
from mercury_relay_plugin.session_reads import SessionReadsError


def test_failed_push_setup_does_not_disable_ciphertext_connector(tmp_path, monkeypatch):
    async def run():
        service, runtime, _, _, _, _, _ = await admitted_peer(tmp_path, enabled=False)
        try:
            api = contract_import("dashboard.plugin_api")

            monkeypatch.setenv("MERCURY_RELAY_PUSH_ENABLED", "1")

            def unavailable(**kwargs):
                raise ValueError("private corrupted state")

            monkeypatch.setattr("mercury_relay_plugin.push.PushBridge", unavailable)
            connector = api._default_connector_provider(service)
            assert connector is not None
            assert service.push is None
            await connector.close()
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_missing_httpx_import_keeps_ciphertext_connector(tmp_path, monkeypatch):
    async def run():
        import builtins
        import sys

        service, runtime, _, _, _, _, _ = await admitted_peer(tmp_path, enabled=False)
        try:
            api = contract_import("dashboard.plugin_api")
            monkeypatch.setenv("MERCURY_RELAY_PUSH_ENABLED", "1")
            original = builtins.__import__
            missing = []

            def without_httpx(name, globals=None, locals=None, fromlist=(), level=0):
                if name == "httpx" and (globals or {}).get("__name__") == (
                    "mercury_relay_plugin.push"
                ):
                    missing.append(name)
                    raise ModuleNotFoundError("No module named 'httpx'")
                return original(name, globals, locals, fromlist, level)

            monkeypatch.delitem(sys.modules, "mercury_relay_plugin.push")
            monkeypatch.setattr(builtins, "__import__", without_httpx)
            connector = api._default_connector_provider(service)
            assert missing == ["httpx"]
            assert connector is not None
            assert service.push is None
            await connector.close()
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


@pytest.mark.parametrize("enabled", [None, "0", "true", "1"])
def test_production_opt_in_reuses_origin_and_host_issuer(tmp_path, monkeypatch, enabled):
    async def run():
        service, runtime, _, _, _, _, offer = await admitted_peer(tmp_path, enabled=False)
        try:
            api = contract_import("dashboard.plugin_api")

            if enabled is None:
                monkeypatch.delenv("MERCURY_RELAY_PUSH_ENABLED", raising=False)
            else:
                monkeypatch.setenv("MERCURY_RELAY_PUSH_ENABLED", enabled)
            connector = api._default_connector_provider(service)
            assert (service.push is not None) == (enabled == "1")
            if service.push is not None:
                from mercury_relay_plugin.config import load_public_config
                from mercury_relay_plugin.relay_client import host_socket_url

                origin = load_public_config(service.repository.paths)["relay_origin"]
                route = (
                    host_socket_url(origin, offer.installation_id)
                    .split("/v1/host/")[1]
                    .split("?")[0]
                )
                assert service.push.url == origin + "/v1/push/" + route
                assert service.push._task is not None
            await connector.close()
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_preview_capability_requires_sender_flag_and_public_config(tmp_path, monkeypatch):
    async def run():
        service, runtime, _, _, _, _, _ = await admitted_peer(tmp_path, enabled=False)
        try:
            api = contract_import("dashboard.plugin_api")
            from mercury_relay_plugin.config import load_public_config, save_public_config

            monkeypatch.setenv("MERCURY_RELAY_PUSH_ENABLED", "1")
            monkeypatch.setenv("MERCURY_RELAY_PUSH_PREVIEW_ENABLED", "1")
            config = load_public_config(service.repository.paths)
            config["push_previews"] = True
            save_public_config(service.repository.paths, config)
            connector = api._default_connector_provider(service)
            assert service.push is not None and service.push.preview_available
            assert service.push.capabilities["push_previews"]["version"] == 1
            await connector.close()
            await service.push.close()
            service.push = None

            monkeypatch.delenv("MERCURY_RELAY_PUSH_PREVIEW_ENABLED")
            connector = api._default_connector_provider(service)
            assert service.push is not None and not service.push.preview_available
            assert "push_previews" not in service.push.capabilities
            await connector.close()
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_timeout_redirect_and_unauthorized_epoch_fail_closed(tmp_path):
    async def run():
        service, runtime, admitted, _, _, _, offer = await admitted_peer(tmp_path, enabled=False)
        calls = []
        mint_calls = []
        epoch = admitted.lease.authorization_epoch
        mode = "redirect"

        async def peer(request):
            calls.append(request)
            if mode == "timeout" and request.url.path.endswith("/register"):
                await asyncio.Event().wait()
            if request.url.path.endswith("/register"):
                return httpx.Response(307, headers={"Location": "https://other.example/leak"})
            return httpx.Response(200)

        def token():
            mint_calls.append(True)
            return "synthetic-offline-host-token"

        bridge = PushBridge(
            paths=service.repository.paths,
            relay_origin="wss://relay.example",
            installation_id=offer.installation_id,
            token_provider=token,
            authorized=lambda d, e: d == admitted.device_id and e == epoch,
            transport=httpx.MockTransport(peer),
            timeout=0.02,
        )
        try:
            with pytest.raises(SessionReadsError):
                await bridge.dispatch(
                    admitted.device_id,
                    epoch,
                    "relay.push.register",
                    {"device_token": "ab" * 32, "environment": "sandbox"},
                )
            await bridge.drain()
            assert all(r.url.host == "relay.example" for r in calls)
            assert all(r.url.scheme == "https" for r in calls)
            assert bridge.rows == {}
            mode = "timeout"
            with pytest.raises(SessionReadsError):
                await asyncio.wait_for(
                    bridge.dispatch(
                        admitted.device_id,
                        epoch,
                        "relay.push.register",
                        {"device_token": "ab" * 100, "environment": "sandbox"},
                    ),
                    2,
                )
            await bridge.drain()
            assert bridge.rows == {}
            assert len(mint_calls) == len(calls) == 4
            before = len(calls)
            for device, old_epoch in [(admitted.device_id, epoch + 1), ("another-device", epoch)]:
                with pytest.raises(SessionReadsError):
                    await bridge.dispatch(
                        device,
                        old_epoch,
                        "relay.push.register",
                        {"device_token": "ab" * 32, "environment": "sandbox"},
                    )
            assert len(calls) == before
            assert all(
                set(json.loads(r.content)) <= {"wake_handle", "device_token", "environment"}
                for r in calls
            )
        finally:
            await bridge.close()
            assert bridge._task.done()
            assert bridge.queue.empty()
            await service.close()
            await runtime.close()

    asyncio.run(run())
