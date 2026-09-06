from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from conftest import contract_import

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.method_policy import MethodPolicyRejected  # noqa: E402
from mercury_relay_plugin.runtime import (  # noqa: E402
    ControllerLimitReached,
    ProfileNotAvailable,
    RelayRuntime,
    RuntimeUnavailable,
)


async def compatible_handle_ws(ws, *, auth_identity=None) -> None:
    del ws, auth_identity


class FakeBridge:
    def __init__(self, websocket) -> None:
        self.websocket = websocket
        self.start_calls = 0
        self.close_calls = 0

    async def start(self) -> None:
        self.start_calls += 1

    async def close(self) -> None:
        self.close_calls += 1


def test_runtime_owns_and_closes_bounded_controllers() -> None:
    async def exercise() -> None:
        bridges: list[FakeBridge] = []

        def factory(websocket):
            bridge = FakeBridge(websocket)
            bridges.append(bridge)
            return bridge

        runtime = RelayRuntime(
            loader=lambda: compatible_handle_ws,
            bridge_factory=factory,
            max_controllers=2,
            id_factory=iter(["controller-a", "controller-b"]).__next__,
        )
        await runtime.start()
        await runtime.start()
        assert runtime.snapshot() == {
            "installed": True,
            "runtime": "ready",
            "hermes_contract": {"status": "ready", "supported": True},
            "active_controllers": 0,
            "max_controllers": 2,
        }

        first = await runtime.open_controller(profile="default")
        second = await runtime.open_controller(profile="default")
        assert first.controller_id == "controller-a"
        assert second.controller_id == "controller-b"
        assert first.websocket is bridges[0].websocket
        assert [bridge.start_calls for bridge in bridges] == [1, 1]

        with pytest.raises(ControllerLimitReached, match="controller_limit_reached"):
            await runtime.open_controller(profile="default")

        with pytest.raises(MethodPolicyRejected, match="method_not_allowed"):
            await first.websocket.feed_text(
                json.dumps({"jsonrpc": "2.0", "id": "x", "method": "config.get", "params": {}})
            )

        assert await runtime.close_controller("controller-a") is True
        assert await runtime.close_controller("controller-a") is False
        assert bridges[0].close_calls == 1

        await runtime.close()
        await runtime.close()
        assert bridges[1].close_calls == 1
        assert runtime.snapshot()["runtime"] == "stopped"
        assert runtime.snapshot()["active_controllers"] == 0

    asyncio.run(exercise())


def test_runtime_fails_closed_when_contract_is_missing() -> None:
    def missing():
        raise ImportError("private import detail")

    async def exercise() -> None:
        runtime = RelayRuntime(loader=missing)
        with pytest.raises(RuntimeUnavailable, match="runtime_not_ready"):
            await runtime.open_controller(profile="default")
        await runtime.start()
        assert runtime.snapshot()["runtime"] == "unsupported_hermes_contract"
        assert "private" not in str(runtime.snapshot())
        with pytest.raises(RuntimeUnavailable, match="runtime_not_ready"):
            await runtime.open_controller(profile="default")
        await runtime.close()

    asyncio.run(exercise())


def test_runtime_allows_existing_profiles_and_rechecks_each_request() -> None:
    async def exercise() -> None:
        profiles = {"default", "researcher"}
        runtime = RelayRuntime(
            loader=lambda: compatible_handle_ws,
            bridge_factory=lambda websocket: FakeBridge(websocket),
            id_factory=lambda: "multi-profile-controller",
            profile_authorizer=lambda profile: profile in profiles,
        )
        await runtime.start()
        controller = await runtime.open_controller(profile="researcher")

        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "default-session",
                "method": "session.create",
                "params": {"profile": "default"},
            }
        )
        await controller.websocket.feed_text(raw)
        assert await controller.websocket.receive_text() == raw

        profiles.remove("default")
        with pytest.raises(MethodPolicyRejected, match="profile_not_available"):
            await controller.websocket.feed_text(raw)
        with pytest.raises(ProfileNotAvailable, match="profile_not_available"):
            await runtime.open_controller(profile="missing")
        await runtime.close()

    asyncio.run(exercise())


def test_cancelled_open_closes_unpublished_candidate() -> None:
    async def exercise() -> None:
        started = asyncio.Event()
        candidate: FakeBridge | None = None

        class BlockingBridge(FakeBridge):
            async def start(self) -> None:
                self.start_calls += 1
                started.set()
                await asyncio.Future()

        def factory(websocket):
            nonlocal candidate
            candidate = BlockingBridge(websocket)
            return candidate

        runtime = RelayRuntime(loader=lambda: compatible_handle_ws, bridge_factory=factory)
        await runtime.start()
        opening = asyncio.create_task(runtime.open_controller(profile="default"))
        await started.wait()
        opening.cancel()
        with pytest.raises(asyncio.CancelledError):
            await opening
        assert candidate is not None
        assert candidate.close_calls == 1
        assert runtime.snapshot()["active_controllers"] == 0
        await runtime.close()

    asyncio.run(exercise())


def test_cancelled_runtime_close_finishes_resource_cleanup() -> None:
    async def exercise() -> None:
        close_started = asyncio.Event()
        release_close = asyncio.Event()

        class SlowCloseBridge(FakeBridge):
            async def close(self) -> None:
                self.close_calls += 1
                close_started.set()
                await release_close.wait()

        bridges: list[SlowCloseBridge] = []

        def factory(websocket):
            bridge = SlowCloseBridge(websocket)
            bridges.append(bridge)
            return bridge

        runtime = RelayRuntime(loader=lambda: compatible_handle_ws, bridge_factory=factory)
        await runtime.start()
        await runtime.open_controller(profile="default")
        closing = asyncio.create_task(runtime.close())
        await close_started.wait()
        closing.cancel()
        await asyncio.sleep(0)
        assert not closing.done()
        release_close.set()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert bridges[0].close_calls == 1
        assert runtime.snapshot()["runtime"] == "stopped"
        assert runtime.snapshot()["active_controllers"] == 0

    asyncio.run(exercise())


def test_real_runtime_routes_one_controller_to_an_existing_bot_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_import("tui_gateway.ws")

    async def next_json(websocket, request_id: str) -> dict:
        for _ in range(20):
            frame = json.loads(await websocket.next_text(timeout=2.0))
            if frame.get("id") == request_id:
                return frame
        raise AssertionError("expected response not received")

    async def exercise() -> None:
        root = tmp_path / "hermes"
        (root / "profiles" / "researcher").mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(root))
        runtime = RelayRuntime(max_controllers=1, id_factory=lambda: "controller-real")
        await runtime.start()
        controller = await runtime.open_controller(profile="default")
        try:
            ready = json.loads(await controller.websocket.next_text(timeout=2.0))
            assert ready["params"]["type"] == "gateway.ready"
            await controller.websocket.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "create-real",
                    "method": "session.create",
                    "params": {"profile": "researcher", "source": "mercury"},
                }
            )
            created = await next_json(controller.websocket, "create-real")
            assert created["result"]["info"]["profile_name"] == "researcher"
            runtime_id = created["result"]["session_id"]
            await controller.websocket.feed_json(
                {
                    "jsonrpc": "2.0",
                    "id": "close-real",
                    "method": "session.close",
                    "params": {"session_id": runtime_id, "profile": "default"},
                }
            )
            assert (await next_json(controller.websocket, "close-real"))["result"]["closed"]
        finally:
            await runtime.close()
        assert runtime.snapshot()["active_controllers"] == 0

    asyncio.run(exercise())
