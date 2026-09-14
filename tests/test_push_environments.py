"""Versioned generic APNs environment contract; all peers are local fakes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path

import httpx
import pytest
from test_push import admitted_peer

from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.push import PushBridge
from mercury_relay_plugin.session_reads import SessionReadsError

CORPUS_PATH = (
    Path(__file__).parents[1] / "protocol" / "vectors" / "push-environments" / "corpus.json"
)
CAPABILITY = {
    "version": 1,
    "environments": ["sandbox", "production"],
    "generic_register_version": 2,
}


def bridge_at(tmp_path, calls, *, production_enabled=False):
    tmp_path.mkdir(parents=True, exist_ok=True)

    def peer(request):
        calls.append(request)
        return httpx.Response(200)

    return PushBridge(
        paths=profile_paths(explicit_path=tmp_path),
        relay_origin="https://relay.example",
        installation_id=b"i" * 32,
        token_provider=lambda: "host-token",
        authorized=lambda _device, _epoch: True,
        transport=httpx.MockTransport(peer),
        production_enabled=production_enabled,
    )


def test_shared_generic_contract_corpus_is_enforced(tmp_path):
    corpus_bytes = CORPUS_PATH.read_bytes()
    shared_path = os.environ.get("MERCURY_SHARED_PUSH_ENVIRONMENTS_CORPUS")
    if shared_path:
        assert corpus_bytes == Path(shared_path).read_bytes()
    manifest = json.loads(CORPUS_PATH.with_name("manifest.json").read_text(encoding="utf-8"))
    artifact = manifest["artifacts"]["corpus.json"]
    assert artifact == {
        "bytes": len(corpus_bytes),
        "sha256": hashlib.sha256(corpus_bytes).hexdigest(),
    }
    assert manifest["synthetic"] is True
    assert manifest["contains_secrets"] is False
    assert manifest["contains_live_hosts"] is False
    corpus = json.loads(corpus_bytes)
    assert type(corpus["version"]) is int and corpus["version"] == 1
    assert corpus["capability"] == CAPABILITY

    async def run():
        for index, case in enumerate(corpus["cases"]):
            calls = []
            bridge = bridge_at(
                tmp_path / str(index), calls, production_enabled=case["production_enabled"]
            )
            try:
                if case["accepted"]:
                    result = await bridge.dispatch(
                        "device", 4, "relay.push.register", case["params"]
                    )
                    assert result["registered"] is True, case["name"]
                    assert len(calls) == 1, case["name"]
                    body = json.loads(calls[0].content)
                    assert body["environment"] == case["params"]["environment"]
                    if case["forwarded_version"] is None:
                        assert "version" not in body, case["name"]
                    else:
                        assert body["version"] == case["forwarded_version"], case["name"]
                else:
                    with pytest.raises(SessionReadsError, match=case["error"]):
                        await bridge.dispatch(
                            "device", 4, "relay.push.register", case["params"]
                        )
                    assert calls == [], case["name"]
            finally:
                await bridge.close()

    asyncio.run(run())


def test_capability_is_strictly_additive_and_flag_gated(tmp_path):
    disabled = bridge_at(tmp_path / "disabled", [])
    enabled = bridge_at(tmp_path / "enabled", [], production_enabled=True)
    try:
        baseline = {
            "push_notifications_v1": True,
            "push_notifications_v2": True,
            "push_notification_routes": {
                "version": 1,
                "inspect_method": "relay.push.inspect",
            },
        }
        assert disabled.capabilities == baseline
        assert enabled.capabilities == {**baseline, "push_environments": CAPABILITY}
    finally:
        asyncio.run(disabled.close())
        asyncio.run(enabled.close())


def test_production_capability_and_version2_registration_cross_authenticated_channel(tmp_path):
    async def run():
        service, runtime, _, rpc, requests, attached, _ = await admitted_peer(
            tmp_path, production_enabled=True
        )
        try:
            assert attached is not None
            assert attached["params"]["capabilities"]["push_environments"] == CAPABILITY
            status = await rpc("relay.status", {})
            assert status is not None
            assert status["result"]["capabilities"]["push_environments"] == CAPABILITY
            response = await rpc(
                "relay.push.register",
                {
                    "version": 2,
                    "device_token": "cd" * 32,
                    "environment": "production",
                },
            )
            assert response is not None
            assert response["result"]["registered"] is True
            assert json.loads(requests[0].content)["version"] == 2
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_production_generic_state_roundtrip_and_flag_disable_cleanup_debt(tmp_path):
    async def run():
        calls = []
        enabled = bridge_at(tmp_path, calls, production_enabled=True)
        params = {"version": 2, "device_token": "cd" * 32, "environment": "production"}
        handle = (await enabled.dispatch("device", 9, "relay.push.register", params))[
            "wake_handle"
        ]
        await enabled.close()
        persisted = json.loads(enabled.path.read_text())
        assert persisted["rows"][handle]["environment"] == "production"
        assert persisted["rows"][handle]["status"] == "active"

        calls.clear()
        restarted = bridge_at(tmp_path, calls, production_enabled=True)
        try:
            restarted.wake("device", 9, b"same-binding")
            await restarted.drain()
            assert len(calls) == 1 and calls[0].url.path.endswith("/wake")
            assert restarted.rows[handle]["environment"] == "production"
        finally:
            await restarted.close()

        calls.clear()
        disabled = bridge_at(tmp_path, calls)
        try:
            assert disabled.rows[handle]["status"] == "debt"
            assert disabled.rows[handle]["environment"] == "production"
            disabled.wake("device", 9, b"must-not-wake")
            await disabled.drain()
            assert len(calls) == 1 and calls[0].url.path.endswith("/unregister")
            assert json.loads(calls[0].content) == {"wake_handle": handle}
            assert disabled.rows == {}
        finally:
            await disabled.close()

    asyncio.run(run())
