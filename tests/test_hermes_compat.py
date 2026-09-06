from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from conftest import contract_import

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.hermes_compat import (  # noqa: E402
    HermesContractUnavailable,
    HermesSessionBridge,
    probe_hermes_contract,
)
from mercury_relay_plugin.virtual_ws import VirtualWebSocket  # noqa: E402


async def _next_json(ws: VirtualWebSocket, *, predicate) -> dict:
    for _ in range(20):
        frame = json.loads(await ws.next_text(timeout=2.0))
        if predicate(frame):
            return frame
    raise AssertionError("expected Hermes frame was not received")


def test_real_handle_ws_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    contract_import("tui_gateway.ws")

    async def exercise() -> None:
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
        ws = VirtualWebSocket(max_queue_items=64, max_frame_bytes=1_048_576)
        bridge = HermesSessionBridge(ws)
        await bridge.start()
        try:
            ready = await _next_json(
                ws, predicate=lambda frame: frame.get("params", {}).get("type") == "gateway.ready"
            )
            assert ready["params"]["payload"]["change_events"] is True

            await ws.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "create-id",
                    "method": "session.create",
                    "params": {"source": "mercury", "close_on_disconnect": False},
                }
            )
            created = await _next_json(ws, predicate=lambda frame: frame.get("id") == "create-id")
            runtime_id = created["result"]["session_id"]
            stored_id = created["result"]["stored_session_id"]
            assert runtime_id
            assert stored_id
            assert runtime_id != stored_id

            await ws.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "history-id",
                    "method": "session.history",
                    "params": {"session_id": runtime_id},
                }
            )
            history = await _next_json(ws, predicate=lambda frame: frame.get("id") == "history-id")
            assert history["result"]["messages"] == []

            from tui_gateway import server

            def emit_leading_space(request_id, params):
                server._emit(
                    "message.delta",
                    params["session_id"],
                    {"text": " leading whitespace"},
                )
                return server._ok(request_id, {"emitted": True})

            monkeypatch.setitem(server._methods, "mercury.test.emit", emit_leading_space)
            await ws.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "emit-id",
                    "method": "mercury.test.emit",
                    "params": {"session_id": runtime_id},
                }
            )
            delta = await _next_json(
                ws,
                predicate=lambda frame: frame.get("params", {}).get("type") == "message.delta",
            )
            assert delta["params"]["payload"]["text"] == " leading whitespace"
            emitted = await _next_json(ws, predicate=lambda frame: frame.get("id") == "emit-id")
            assert emitted["result"]["emitted"] is True

            await ws.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "browser-id",
                    "method": "browser.controller.register",
                    "params": {
                        "session_id": runtime_id,
                        "protocol_version": 1,
                        "controller_id": "fixture-controller",
                        "browser_profile_id": "fixture-profile",
                        "capabilities": ["navigate"],
                    },
                }
            )
            forbidden = await _next_json(
                ws, predicate=lambda frame: frame.get("id") == "browser-id"
            )
            assert forbidden["error"]["code"] == 4403

            await ws.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "close-id",
                    "method": "session.close",
                    "params": {"session_id": runtime_id},
                }
            )
            closed = await _next_json(ws, predicate=lambda frame: frame.get("id") == "close-id")
            assert closed["result"]["closed"] is True
        finally:
            await bridge.close()
        assert bridge.status == "stopped"
        assert ws.closed

    asyncio.run(exercise())


def test_immediate_normal_return_fails_start_and_closes_socket() -> None:
    """BR-02: a handler that returns during startup is not a successful start."""

    async def returns_immediately(ws, *, auth_identity=None) -> None:
        del ws, auth_identity

    async def exercise() -> None:
        ws = VirtualWebSocket()
        bridge = HermesSessionBridge(ws, loader=lambda: returns_immediately)
        with pytest.raises(RuntimeError, match="hermes_session_bridge_failed"):
            await bridge.start()
        assert not bridge.running
        assert bridge.status == "failed"
        assert ws.closed

    asyncio.run(exercise())


def test_immediate_crash_fails_start_and_closes_socket() -> None:
    async def crashes_immediately(ws, *, auth_identity=None) -> None:
        del ws, auth_identity
        raise RuntimeError("sensitive handler detail")

    async def exercise() -> None:
        ws = VirtualWebSocket()
        bridge = HermesSessionBridge(ws, loader=lambda: crashes_immediately)
        with pytest.raises(RuntimeError, match="hermes_session_bridge_failed"):
            await bridge.start()
        assert bridge.status == "failed"
        assert ws.closed

    asyncio.run(exercise())


@pytest.mark.parametrize(("fail", "expected_status"), [(True, "failed"), (False, "stopped")])
def test_post_start_exit_closes_socket(fail: bool, expected_status: str) -> None:
    """BR-02: after start, both a crash and a normal return close the socket."""

    async def handler(ws, *, auth_identity=None) -> None:
        del auth_identity
        await ws.receive_text()
        if fail:
            raise RuntimeError("sensitive handler detail")

    async def exercise() -> None:
        ws = VirtualWebSocket()
        bridge = HermesSessionBridge(ws, loader=lambda: handler)
        await bridge.start()
        assert bridge.running
        assert bridge.status == "running"
        await ws.feed_json({"jsonrpc": "2.0", "id": "x", "method": "noop"})
        for _ in range(200):
            if ws.closed:
                break
            await asyncio.sleep(0.01)
        assert ws.closed
        assert bridge.status == expected_status
        await bridge.close()

    asyncio.run(exercise())


def test_missing_contract_is_sanitized() -> None:
    def missing():
        raise ImportError("sensitive local import detail")

    result = probe_hermes_contract(loader=missing)
    assert result == {"status": "unsupported_hermes_contract", "supported": False}

    def invalid_handler(_ws, *, auth_identity=None):
        del auth_identity

    assert probe_hermes_contract(loader=lambda: invalid_handler) == {
        "status": "unsupported_hermes_contract",
        "supported": False,
    }

    async def exercise() -> None:
        bridge = HermesSessionBridge(VirtualWebSocket(), loader=missing)
        with pytest.raises(HermesContractUnavailable, match="unsupported_hermes_contract"):
            await bridge.start()
        assert bridge.status == "unsupported_hermes_contract"
        assert "sensitive" not in bridge.status

    asyncio.run(exercise())
