from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.session_lease import (  # noqa: E402
    LeaseAttachRejected,
    LeaseLimits,
    LeaseReleased,
    SessionLease,
    SessionLeaseError,
    SessionLeaseManager,
)
from mercury_relay_plugin.virtual_ws import VirtualWebSocket  # noqa: E402


class Controllers:
    def __init__(self) -> None:
        self.closed: list[str] = []

    async def close(self, controller_id: str) -> bool:
        self.closed.append(controller_id)
        return True


def _lease(
    websocket: VirtualWebSocket,
    controllers: Controllers,
    *,
    limits: LeaseLimits | None = None,
    clock=None,
) -> SessionLease:
    lease = SessionLease(
        device_id="device-1",
        profile="default",
        controller_id="controller-1",
        websocket=websocket,
        close_controller=controllers.close,
        limits=limits,
        clock=clock,
    )
    lease.start()
    return lease


async def _attached(lease: SessionLease, cursor: int = 0, *, expect_gap: bool = False):
    """Attach and consume the ordered attach-status control frame (BR-03)."""

    attachment = lease.attach(cursor)
    status = json.loads(await attachment.next_text(timeout=0.5))
    assert status["method"] == "relay.lease.attached"
    assert status["params"]["replay_gap"] is expect_gap
    assert status["params"]["resume_cursor"] == cursor
    return attachment


def _submit(request_id: str, submission_id: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "prompt.submit",
            "params": {"submission_id": submission_id, "text": "fixture"},
        },
        separators=(",", ":"),
    )


def test_outer_detach_during_running_turn_keeps_the_controller_alive() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers)
        attachment = await _attached(lease)

        await attachment.feed_text(_submit("r1", "s1"))
        assert await websocket.receive_text() == _submit("r1", "s1")

        # The outer transport drops mid-turn; the inner transport survives.
        attachment.detach()
        assert not websocket.closed
        assert not lease.released
        assert controllers.closed == []

        # The turn keeps streaming into the retained ring while detached.
        await websocket.send_text('{"jsonrpc":"2.0","method":"event","params":{"n":1}}')
        await asyncio.sleep(0.01)
        assert lease.last_seq == 1
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_every_retained_event_gets_a_monotonic_lease_sequence() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers)
        attachment = await _attached(lease)
        for index in range(5):
            await websocket.send_text(json.dumps({"jsonrpc": "2.0", "seq_probe": index}))
        await asyncio.sleep(0.01)
        assert lease.last_seq == 5
        for index in range(5):
            frame = json.loads(await attachment.next_text(timeout=0.5))
            assert frame["seq_probe"] == index
        attachment.detach()
        replayed = await _attached(lease, 2)
        first = json.loads(await replayed.next_text(timeout=0.5))
        assert first["seq_probe"] == 2
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_duplicate_submission_id_returns_original_outcome_without_resubmit() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers)
        attachment = await _attached(lease)

        await attachment.feed_text(_submit("r1", "s1"))
        assert await websocket.receive_text() == _submit("r1", "s1")
        outcome = '{"jsonrpc":"2.0","id":"r1","result":{"accepted":true,"turn":7}}'
        await websocket.send_text(outcome)
        assert await attachment.next_text(timeout=0.5) == outcome

        # A retry after reconnect must not reach Hermes a second time.
        attachment.detach()
        retry = await _attached(lease, 1)
        await retry.feed_text(_submit("r2", "s1"))
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
        synthesized = json.loads(await retry.next_text(timeout=0.5))
        assert synthesized == {
            "jsonrpc": "2.0",
            "id": "r2",
            "result": {"accepted": True, "turn": 7},
        }
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_duplicate_before_outcome_waits_and_never_resubmits() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers)
        attachment = await _attached(lease)

        await attachment.feed_text(_submit("a1", "s2"))
        assert await websocket.receive_text() == _submit("a1", "s2")
        await attachment.feed_text(_submit("a2", "s2"))
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(websocket.receive_text(), timeout=0.05)

        await websocket.send_text('{"jsonrpc":"2.0","id":"a1","result":{"accepted":true}}')
        frames = [
            json.loads(await attachment.next_text(timeout=0.5)),
            json.loads(await attachment.next_text(timeout=0.5)),
        ]
        assert {frame["id"] for frame in frames} == {"a1", "a2"}
        assert all(frame["result"] == {"accepted": True} for frame in frames)
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_detached_retention_cap_releases_the_lease() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers, limits=LeaseLimits(max_events=2))
        attachment = lease.attach(0)
        attachment.detach()
        for index in range(3):
            await websocket.send_text(json.dumps({"jsonrpc": "2.0", "n": index}))
        await asyncio.sleep(0.05)
        assert lease.released
        assert lease.release_reason == "retention_cap"
        assert controllers.closed == ["controller-1"]

    asyncio.run(exercise())


def test_aged_out_events_flag_a_replay_gap_for_transcript_reconciliation() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        now = [0.0]
        lease = _lease(websocket, controllers, clock=lambda: now[0])
        attachment = lease.attach(0)
        await websocket.send_text('{"jsonrpc":"2.0","n":1}')
        await asyncio.sleep(0.01)
        now[0] = 700.0
        await websocket.send_text('{"jsonrpc":"2.0","n":2}')
        await asyncio.sleep(0.01)
        assert lease.trimmed_through == 1
        assert not lease.released
        attachment.detach()

        stale = await _attached(lease, 0, expect_gap=True)
        assert stale.replay_gap is True
        assert json.loads(await stale.next_text(timeout=0.5))["n"] == 2
        stale.detach()
        fresh = lease.attach(2)
        assert fresh.replay_gap is False
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_one_attachment_with_observer_safe_replay_after_cursor() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers)
        attachment = lease.attach(0)
        with pytest.raises(LeaseAttachRejected, match="already_attached"):
            lease.attach(0)
        texts = [json.dumps({"jsonrpc": "2.0", "n": index}) for index in range(4)]
        for text in texts:
            await websocket.send_text(text)
        await asyncio.sleep(0.01)
        attachment.detach()

        with pytest.raises(LeaseAttachRejected, match="cursor_ahead"):
            lease.attach(9)
        replayed = await _attached(lease, 1)
        assert [await replayed.next_text(timeout=0.5) for _ in range(3)] == texts[1:]
        replayed.detach()
        again = await _attached(lease, 1)
        assert [await again.next_text(timeout=0.5) for _ in range(3)] == texts[1:]
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_detach_ttl_expiry_releases_exactly_once() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(
            websocket,
            controllers,
            limits=LeaseLimits(detach_ttl_seconds=0.05),
        )
        attachment = lease.attach(0)
        attachment.detach()
        await asyncio.sleep(0.15)
        assert lease.released
        assert lease.release_reason == "expired"
        assert not await lease.release("sync")
        assert controllers.closed == ["controller-1"]
        assert not await lease.release("again")
        assert controllers.closed == ["controller-1"]
        with pytest.raises(LeaseReleased):
            lease.attach(0)

    asyncio.run(exercise())


def test_terminal_inner_close_releases_and_detaches_the_attachment() -> None:
    async def exercise() -> None:
        websocket = VirtualWebSocket()
        await websocket.accept()
        controllers = Controllers()
        lease = _lease(websocket, controllers)
        attachment = await _attached(lease)
        await websocket.close()
        with pytest.raises(LeaseReleased):
            await attachment.next_text(timeout=0.5)
        assert lease.released
        assert lease.release_reason == "controller_closed"
        assert not await lease.release("sync")
        assert controllers.closed == ["controller-1"]

    asyncio.run(exercise())


def test_release_notifies_lifecycle_observer_exactly_once() -> None:
    async def exercise() -> None:
        controllers = Controllers()
        notifications: list[str] = []
        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=VirtualWebSocket(),
            close_controller=controllers.close,
            on_release=lambda: notifications.append("released"),
        )
        lease.start()

        assert await lease.release("expired")
        assert not await lease.release("duplicate")
        assert notifications == ["released"]

    asyncio.run(exercise())


def test_manager_maps_one_device_to_one_lease_and_releases_on_close() -> None:
    async def exercise() -> None:
        controllers = Controllers()
        manager = SessionLeaseManager(max_leases=2)
        first_ws = VirtualWebSocket()
        first = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=first_ws,
            close_controller=controllers.close,
        )
        manager.register(first)
        duplicate = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-dup",
            websocket=VirtualWebSocket(),
            close_controller=controllers.close,
        )
        with pytest.raises(SessionLeaseError, match="device_already_leased"):
            manager.register(duplicate)
        assert manager.get("device-1") is first

        assert await manager.release_device("device-1", reason="revoked")
        assert first.release_reason == "revoked"
        assert controllers.closed == ["controller-1"]
        assert manager.get("device-1") is None
        assert not await manager.release_device("device-1")

        second = SessionLease(
            device_id="device-2",
            profile="default",
            controller_id="controller-2",
            websocket=VirtualWebSocket(),
            close_controller=controllers.close,
        )
        manager.register(second)
        await manager.close()
        assert second.released
        assert second.release_reason == "plugin_shutdown"
        assert controllers.closed == ["controller-1", "controller-2"]
        with pytest.raises(SessionLeaseError, match="manager_closed"):
            manager.register(duplicate)
        await duplicate.release("cleanup")

    asyncio.run(exercise())
