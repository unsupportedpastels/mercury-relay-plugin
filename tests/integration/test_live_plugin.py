"""Phase 1 vertical slice: real Hermes gateway, real plugin lifespan, fake host.

Everything between the synthetic mobile endpoint and the real in-process
Hermes session dispatcher is the actual production code path: the plugin
lifespan builds the admission service and connector, the connector runs the
session loops, admission runs Noise + authorization, and the leases carry the
turn across an outer disconnect.  Only the hosted Cloudflare path is the
deterministic in-memory fake (replaced in the hosted-staging phase), and the
`hermes serve` process boundary itself remains the manual phase-promotion
gate.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
sys.path.insert(0, str(Path(__file__).parents[2] / "src"))

from conftest import contract_import  # noqa: E402

contract_import("tui_gateway.ws")

from virtual_mobile import VirtualMobile  # noqa: E402

from mercury_relay_plugin.connector import (  # noqa: E402
    InMemoryHostedConnector,
    RelayConnectorService,
)

PLUGIN_ROOT = Path(__file__).parents[2]


def _load_plugin_api():
    path = PLUGIN_ROOT / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("mercury_relay_live_plugin_api", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _wait_for(predicate, *, timeout: float = 5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition was not reached in time")
        await asyncio.sleep(0.01)


def test_vertical_slice_pairs_streams_survives_detach_and_revokes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        home = tmp_path / "hermes"
        (home / "profiles" / "researcher").mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(home))

        # Durable transcript rows are written by the real agent loop, which
        # this slice replaces with a counted fake; seed the researcher DB so
        # the in-process read path reads real SessionDB rows.
        from hermes_state import SessionDB

        seeded = SessionDB(home / "profiles" / "researcher" / "state.db")
        try:
            seeded.create_session("seeded-session-001", source="mercury")
            seeded.append_message("seeded-session-001", "user", content="seeded prompt")
            seeded.append_message("seeded-session-001", "assistant", content="seeded answer")
        finally:
            seeded.close()

        module = _load_plugin_api()
        module._runtime = module.RelayRuntime(max_controllers=4)
        connector = InMemoryHostedConnector()
        module._connector_provider = lambda admission: RelayConnectorService(
            admission, connector
        )

        submit_calls: list[str] = []

        async with module._lifespan(None):
            management = module._management
            assert management is not None
            assert module._connector is not None

            # -- pair and approve through the management plane ---------------
            offer = management.create_pairing_offer({})
            mobile = VirtualMobile(
                installation_id=base64.b64decode(offer["installation_id"]),
                host_public_key=base64.b64decode(offer["host_public_key"]),
            )
            await mobile.pair(
                await connector.connect(), base64.b64decode(offer["capability"])
            )
            pending = await _wait_for(
                lambda: management.pending_devices()["devices"]
            )
            device_id = pending[0]["device_id"]
            assert pending[0]["status"] == "pending"
            digest = hashlib.sha256(mobile.pairing_channel_binding).digest()
            approved = management.approve_device(
                device_id,
                {"channel_binding_digest": base64.b64encode(digest).decode()},
            )
            assert approved["status"] == "authorized"
            mobile.device_id = device_id

            # -- real Hermes session over the encrypted path -----------------
            session = await mobile.open_controller(
                await connector.connect(), profile="researcher"
            )
            ready = await session.next_matching(
                lambda frame: frame.get("params", {}).get("type") == "gateway.ready"
            )
            assert ready["params"]["payload"]["change_events"] is True

            await session.send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "create-1",
                    "method": "session.create",
                    "params": {
                        "profile": "researcher",
                        "source": "mercury",
                        "close_on_disconnect": False,
                    },
                }
            )
            created = await session.next_matching(lambda frame: frame.get("id") == "create-1")
            session_id = created["result"]["session_id"]
            assert created["result"]["info"]["profile_name"] == "researcher"

            from tui_gateway import server

            def counted_submit(request_id, params):
                submit_calls.append(params.get("submission_id", ""))
                server._emit(
                    "message.delta", params["session_id"], {"text": " streaming delta"}
                )
                return server._ok(request_id, {"accepted": True, "turn": 1})

            monkeypatch.setitem(server._methods, "prompt.submit", counted_submit)

            submission_id = secrets.token_hex(16)
            await session.send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "submit-1",
                    "method": "prompt.submit",
                    "params": {
                        "session_id": session_id,
                        "text": "fixture prompt sentinel",
                        "submission_id": submission_id,
                    },
                }
            )
            delta = await session.next_matching(
                lambda frame: frame.get("params", {}).get("type") == "message.delta"
            )
            assert delta["params"]["payload"]["text"] == " streaming delta"

            # -- outer transport loss during the running turn ----------------
            # The device has processed 3 lease events (ready, create response,
            # delta); the acceptance may still be retained on the host.
            await session.detach()
            await asyncio.sleep(0.05)

            resumed = await mobile.open_controller(
                await connector.connect(), profile="researcher", resume_cursor=3
            )
            accepted = await resumed.next_matching(
                lambda frame: frame.get("id") == "submit-1"
            )
            assert accepted["result"] == {"accepted": True, "turn": 1}

            # Retrying the same logical submission never reaches Hermes again.
            await resumed.send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "submit-retry",
                    "method": "prompt.submit",
                    "params": {
                        "session_id": session_id,
                        "text": "fixture prompt sentinel",
                        "submission_id": submission_id,
                    },
                }
            )
            synthesized = await resumed.next_matching(
                lambda frame: frame.get("id") == "submit-retry"
            )
            assert synthesized["result"] == {"accepted": True, "turn": 1}
            assert submit_calls == [submission_id]

            # -- bounded in-process reads over the same channel --------------
            await resumed.send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "read-1",
                    "method": "relay.sessions.list",
                    "params": {"profile": "researcher"},
                }
            )
            listed = await resumed.next_matching(lambda frame: frame.get("id") == "read-1")
            assert listed["result"]["total"] >= 1
            assert any(
                row["id"] == "seeded-session-001" for row in listed["result"]["sessions"]
            )
            await resumed.send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "read-2",
                    "method": "relay.session.transcript",
                    "params": {"profile": "researcher", "session_id": "seeded-session-001"},
                }
            )
            transcript = await resumed.next_matching(
                lambda frame: frame.get("id") == "read-2"
            )
            contents = [m.get("content") for m in transcript["result"]["messages"]]
            assert contents == ["seeded prompt", "seeded answer"]

            # -- immediate revoke tears down the live lease ------------------
            revoked = await management.revoke_device(device_id)
            assert revoked["status"] == "revoked"
            with pytest.raises((AssertionError, TimeoutError, ConnectionError)):
                await resumed.next_matching(lambda frame: False, attempts=3)

            rejected = await mobile.open_controller(
                await connector.connect(), profile="researcher"
            )
            with pytest.raises((AssertionError, TimeoutError, ConnectionError)):
                await rejected.next_json()

        # -- persisted state carries no forbidden material -------------------
        state_files = list(home.rglob("state.json"))
        assert state_files, "owner-private state was persisted"
        for state_file in state_files:
            text = state_file.read_text()
            assert offer["capability"] not in text
            assert "fixture prompt sentinel" not in text
            assert "streaming delta" not in text
            assert submission_id not in text

    asyncio.run(exercise())
