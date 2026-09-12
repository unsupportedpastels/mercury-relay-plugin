"""Offline persistence boundaries: registry identities must never be rebound."""

import asyncio
import base64
import json

import httpx
import pytest

from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.push import MAX_ROWS, PushBridge
from mercury_relay_plugin.session_reads import SessionReadsError

PARAMS = {"device_token": "ab" * 32, "environment": "sandbox"}


def bridge_at(tmp_path, calls, origin="https://relay.example", installation=b"a" * 32):
    def peer(request):
        calls.append(request)
        return httpx.Response(200)

    return PushBridge(
        paths=profile_paths(explicit_path=tmp_path),
        relay_origin=origin,
        installation_id=installation,
        token_provider=lambda: "offline-current-scope-token",
        authorized=lambda d, e: True,
        transport=httpx.MockTransport(peer),
    )


@pytest.mark.parametrize(
    "origin,installation",
    [
        ("https://other.example", b"a" * 32),
        ("https://relay.example", b"b" * 32),
    ],
)
def test_changed_registry_blocks_debt_and_never_revives_on_return(tmp_path, origin, installation):
    async def run():
        calls = []
        old = bridge_at(tmp_path, calls)
        handle = (await old.dispatch("device", 0, "relay.push.register", PARAMS))["wake_handle"]
        await old.close()
        calls.clear()
        new = bridge_at(tmp_path, calls, origin, installation)
        try:
            new.wake("device", 0, b"changed")
            await new.drain()
            assert calls == []
            assert new.rows[handle]["status"] == "debt"
            fresh = await new.dispatch("device", 0, "relay.push.register", PARAMS)
            new.wake("device", 0, b"fresh")
            await new.drain()
            assert all(json.loads(r.content)["wake_handle"] == fresh["wake_handle"] for r in calls)
            assert handle in new.rows  # explicit blocked cleanup debt
        finally:
            await new.close()
        calls.clear()
        restored = bridge_at(tmp_path, calls)
        try:
            restored.wake("device", 0, b"restored")
            await restored.drain()
            assert len(calls) == 1
            assert calls[0].url.host == "relay.example"
            route = base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")
            assert calls[0].url.path == f"/v1/push/{route}/unregister"
            assert json.loads(calls[0].content) == {"wake_handle": handle}
            assert handle not in restored.rows
            assert fresh["wake_handle"] in restored.rows
        finally:
            await restored.close()

    asyncio.run(run())


def test_same_canonical_registry_restart_retains_registration(tmp_path):
    async def run():
        calls = []
        old = bridge_at(tmp_path, calls, "wss://RELAY.example:443/")
        handle = (await old.dispatch("device", 0, "relay.push.register", PARAMS))["wake_handle"]
        await old.close()
        calls.clear()
        new = bridge_at(tmp_path, calls)
        try:
            new.wake("device", 0, b"restart")
            await new.drain()
            assert len(calls) == 1 and calls[0].url.path.endswith("/wake")
            row = json.loads(new.path.read_text())["rows"][handle]
            assert row["origin"] == "https://relay.example"
            assert row["route"] == base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")
        finally:
            await new.close()

    asyncio.run(run())


def test_legacy_unbound_is_permanent_blocked_debt_but_new_registration_works(tmp_path):
    async def run():
        paths = profile_paths(explicit_path=tmp_path).ensure()
        handle = "x" * 43
        (paths.agent_dir / "push.json").write_text(
            json.dumps(
                {"version": 1, "rows": {handle: {"device": "device", "epoch": 0, "active": True}}}
            )
        )
        (paths.agent_dir / "push.json").chmod(0o600)
        calls = []
        for _ in range(2):
            bridge = bridge_at(tmp_path, calls)
            try:
                bridge.wake("device", 0, b"legacy")
                await bridge.drain()
                assert not any(json.loads(r.content)["wake_handle"] == handle for r in calls)
                fresh = await asyncio.wait_for(
                    bridge.dispatch("device", 0, "relay.push.register", PARAMS), 2
                )
                assert fresh["registered"]
                assert bridge.rows[handle]["status"] == "debt"
                assert bridge.rows[handle]["origin"] is None
                assert bridge.rows[handle]["route"] is None
            finally:
                await bridge.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "binding",
    [
        {"origin": "https://relay.example/path", "route": "A" * 43},
        {"origin": "https://user@relay.example", "route": "A" * 43},
        {"origin": "https://RELAY.example", "route": "A" * 43},
        {"origin": "https://relay.example", "route": "../other"},
        {"origin": "https://relay.example", "route": "a" * 43},  # noncanonical base64
        {"origin": None, "route": "a" * 43},
        {"origin": None, "route": None},  # unbound cannot be active
    ],
)
def test_invalid_persisted_binding_rejected_before_network(tmp_path, binding):
    paths = profile_paths(explicit_path=tmp_path).ensure()
    path = paths.agent_dir / "push.json"
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "rows": {"x" * 43: {"device": "device", "epoch": 0, "active": True, **binding}},
            }
        )
    )
    path.chmod(0o600)
    calls = []
    with pytest.raises(ValueError):
        bridge_at(tmp_path, calls)
    assert calls == []


def test_full_v2_state_roundtrip_and_blocked_debt_never_mints(tmp_path):
    async def run():
        paths = profile_paths(explicit_path=tmp_path).ensure()
        route = base64.urlsafe_b64encode(b"a" * 32).decode().rstrip("=")
        rows = {
            base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("="): {
                "device": "\U0001f600" * 128,
                "epoch": 2**31 - 1,
                "active": True,
                "origin": "https://" + "a" * 240 + ".example",
                "route": route,
            }
            for i in range(MAX_ROWS)
        }
        path = paths.agent_dir / "push.json"
        path.write_text(json.dumps({"version": 2, "rows": rows}))
        path.chmod(0o600)
        calls, mints = [], []
        for _ in range(2):
            bridge = bridge_at(tmp_path, calls)
            bridge.token_provider = lambda: mints.append(True) or "offline-token"
            try:
                # Construction alone durably fences before start/close.
                assert all(
                    r["status"] == "debt" for r in json.loads(path.read_text())["rows"].values()
                )
                await bridge.drain()
                assert len(bridge.rows) == MAX_ROWS
                assert not calls and not mints
            finally:
                await bridge.close()

    asyncio.run(run())


def test_matching_debt_without_auth_remains_blocked(tmp_path):
    async def run():
        calls = []
        bridge = bridge_at(tmp_path, calls)
        handle = (await bridge.dispatch("device", 0, "relay.push.register", PARAMS))["wake_handle"]
        await bridge.close()
        calls.clear()
        bridge = bridge_at(tmp_path, calls)

        def unavailable():
            raise ValueError("no valid routing credentials")

        bridge.token_provider = unavailable
        try:
            bridge.revoke("device")
            await bridge.drain()
            assert not calls
            assert bridge.rows[handle]["status"] == "debt"
        finally:
            await bridge.close()

    asyncio.run(run())


def test_blocked_debt_is_bounded_and_not_silently_evicted(tmp_path):
    async def run():
        calls = []
        paths = profile_paths(explicit_path=tmp_path).ensure()
        rows = {
            base64.urlsafe_b64encode(i.to_bytes(32, "big")).decode().rstrip("="): {
                "device": "device",
                "epoch": 0,
                "active": True,
            }
            for i in range(MAX_ROWS)
        }
        (paths.agent_dir / "push.json").write_text(json.dumps({"version": 1, "rows": rows}))
        (paths.agent_dir / "push.json").chmod(0o600)
        bridge = bridge_at(tmp_path, calls)
        try:
            await bridge.drain()
            with pytest.raises(SessionReadsError, match="rate_limited"):
                await bridge.dispatch("device", 0, "relay.push.register", PARAMS)
            assert len(bridge.rows) == MAX_ROWS
            assert bridge.queue.qsize() <= 64
            assert calls == []
        finally:
            await bridge.close()

    asyncio.run(run())
