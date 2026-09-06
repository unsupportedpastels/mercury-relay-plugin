"""Opt-in recovery preserves legacy frames and exposes lease cursors."""

import asyncio
import json

from test_session_lease import Controllers, _lease

from mercury_relay_plugin.virtual_ws import VirtualWebSocket


def test_recovery_frames_carry_actual_lease_sequence_and_replay_marker():
    async def run():
        ws = VirtualWebSocket()
        await ws.accept()
        lease = _lease(ws, Controllers())
        first = lease.attach(0, recovery=True)
        status = json.loads(await first.next_text(timeout=0.5))["params"]
        assert status["recovery_version"] == 1
        assert status["lease_id"]
        assert (
            json.loads(await first.next_text(timeout=0.5))["method"]
            == "relay.lease.replay_complete"
        )
        frame = '{"jsonrpc":"2.0","id":1,"result":{"accepted":true}}'
        await ws.send_text(frame)
        live = json.loads(await first.next_text(timeout=0.5))
        assert live["method"] == "relay.lease.frame"
        assert live["params"] == {
            "lease_id": status["lease_id"],
            "seq": 1,
            "replay": False,
            "frame": frame,
        }
        first.detach()
        second = lease.attach(0, recovery=True)
        assert (
            json.loads(await second.next_text(timeout=0.5))["params"]["lease_id"]
            == status["lease_id"]
        )
        replay = json.loads(await second.next_text(timeout=0.5))
        assert replay["params"] == dict(live["params"], replay=True)
        second.detach()
        legacy = lease.attach(0)
        await legacy.next_text(timeout=0.5)
        assert await legacy.next_text(timeout=0.5) == frame
        await lease.release("test")

    asyncio.run(run())


def test_gap_snapshot_preserves_explicit_child_terminal_not_parent_completion():
    async def run():
        ws = VirtualWebSocket()
        await ws.accept()
        now = [0.0]
        lease = _lease(ws, Controllers(), clock=lambda: now[0])
        first = lease.attach(0, recovery=True)
        await first.next_text(timeout=0.5)
        await first.next_text(timeout=0.5)  # empty replay-complete watermark
        for kind, payload in [
            ("subagent.start", {"subagent_id": "child", "goal": "test"}),
            ("subagent.progress", {"subagent_id": "child", "action": "working"}),
            ("subagent.complete", {"subagent_id": "child", "status": "completed"}),
        ]:
            await ws.send_text(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "method": "event",
                        "params": {"session_id": "runtime", "type": kind, "payload": payload},
                    }
                )
            )
            await first.next_text(timeout=0.5)
        now[0] = 700.0
        await ws.send_text('{"jsonrpc":"2.0","id":2,"result":{}}')
        await first.next_text(timeout=0.5)
        first.detach()
        second = lease.attach(0, recovery=True)
        status = json.loads(await second.next_text(timeout=0.5))["params"]
        assert status["replay_gap"] is True
        tasks = status["task_snapshot"]
        assert len(tasks) == 1
        assert tasks[0]["params"]["payload"]["status"] == "completed"
        assert tasks[0]["params"]["payload"]["goal"] == "test"
        await lease.release("test")

    asyncio.run(run())
