import asyncio
import json

from conftest import posix_only
from test_session_lease import Controllers

from mercury_relay_plugin.lease_recovery import RecoveryProjection, RecoveryStore
from mercury_relay_plugin.session_lease import LeaseLimits, SessionLease, SessionLeaseManager
from mercury_relay_plugin.virtual_ws import VirtualWebSocket

SCOPE = ("installation", "device", 0)


def bind(projection, runtime="runtime", durable="durable", profile="default"):
    projection.request(
        {"id": 1, "method": "session.resume", "params": {"profile": profile, "session_id": durable}}
    )
    projection.observe(
        json.dumps({"id": 1, "result": {"session_id": runtime, "session_key": durable}})
    )


def event(child="child", status="completed", runtime="runtime", **fields):
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "method": "event",
            "params": {
                "session_id": runtime,
                "type": "subagent.complete" if status == "completed" else "subagent.start",
                "payload": {"subagent_id": child, "status": status, **fields},
            },
        }
    )


@posix_only
def test_store_recreated_scope_expiry_truncation_and_sticky_terminal(tmp_path):
    now = [100]
    path = tmp_path / "private" / "recovery.json"
    store = RecoveryStore(path, clock=lambda: now[0], max_rows=2, ttl_seconds=10)
    projection = RecoveryProjection("default", store=store, scope=SCOPE)
    bind(projection)
    projection.observe(event(goal="g" * 10000, summary="s" * 10000))
    projection.observe(event(status="running"))
    projection.observe(event(child="running", status="running"))
    recreated = RecoveryStore(path, clock=lambda: now[0], max_rows=2, ttl_seconds=10)
    historical = RecoveryProjection("default", store=recreated, scope=SCOPE).snapshot()
    rows = historical["task_snapshot"]
    assert len(rows) == 2
    assert rows[0]["params"]["payload"]["status"] == "completed"
    assert len(rows[0]["params"]["payload"]["goal"]) == 500
    assert rows[1]["params"]["payload"]["status"] == "unknown"
    assert all(not b["live"] for b in historical["bindings"])
    assert historical["snapshot_complete"] is False
    for scope in [
        ("installation", "other", 0),
        ("other", "device", 0),
        ("installation", "device", 1),
    ]:
        assert (
            RecoveryProjection("default", store=recreated, scope=scope).snapshot()["task_snapshot"]
            == []
        )
    assert (
        RecoveryProjection(
            "default", store=recreated, scope=SCOPE, profile_authorizer=lambda p: False
        ).snapshot()["task_snapshot"]
        == []
    )
    projection.observe(event(child="third"))
    assert RecoveryStore(path, clock=lambda: now[0], max_rows=2).truncated
    now[0] = 111
    assert (
        RecoveryProjection(
            "default", store=RecoveryStore(path, clock=lambda: now[0]), scope=SCOPE
        ).snapshot()["task_snapshot"]
        == []
    )
    assert path.stat().st_mode & 0o777 == 0o600


def test_manager_restart_projection_persisted_before_delivery_gap_keeps_controller(tmp_path):
    async def run():
        path = tmp_path / "private" / "recovery.json"
        ws = VirtualWebSocket()
        await ws.accept()
        controllers = Controllers()
        projection = RecoveryProjection("default", store=RecoveryStore(path), scope=SCOPE)
        manager = SessionLeaseManager()
        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="controller",
            websocket=ws,
            close_controller=controllers.close,
            recovery_projection=projection,
            limits=LeaseLimits(max_events=2),
        )
        manager.register(lease)
        attachment = lease.attach(recovery=True)
        await attachment.next_text()
        await attachment.next_text()
        request = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "session.resume",
                "params": {"session_id": "durable", "profile": "default"},
            }
        )
        await attachment.feed_text(request)
        await ws.send_text(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"session_id": "runtime", "session_key": "durable"},
                }
            )
        )
        await attachment.next_text(timeout=1)
        attachment.detach()
        for n in range(10):
            await ws.send_text(
                event(status="running", goal="g") if n == 0 else json.dumps({"id": n, "result": {}})
            )
        await ws.send_text(event(summary="done"))
        # Await pump deterministically through the last emitted sequence.
        for _ in range(1000):
            if lease.last_seq == 12:
                break
            await asyncio.sleep(0.001)
        assert lease.last_seq == 12
        assert not lease.released
        snapshot = RecoveryProjection("default", store=RecoveryStore(path), scope=SCOPE).snapshot()
        assert snapshot["task_snapshot"][0]["params"]["payload"]["status"] == "completed"
        reattach = lease.attach(0, recovery=True)
        preamble = json.loads(await reattach.next_text())["params"]
        assert preamble["replay_gap"]
        assert preamble["bindings"][0]["live"]
        assert preamble["snapshot_through"] == 12
        await manager.close()
        fresh = SessionLeaseManager()
        fresh_ws = VirtualWebSocket()
        await fresh_ws.accept()
        fresh_lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="new",
            websocket=fresh_ws,
            close_controller=controllers.close,
            recovery_projection=RecoveryProjection(
                "default", store=RecoveryStore(path), scope=SCOPE
            ),
        )
        fresh.register(fresh_lease)
        status = json.loads(
            await fresh_lease.attach(recovery=True, recovery_reset=True).next_text()
        )["params"]
        assert status["lease_id"] != preamble["lease_id"]
        assert status["recovery_reset"]
        assert status["task_snapshot"][0]["params"]["payload"]["summary"] == "done"
        assert status["bindings"][0]["live"] is False
        await fresh.close()

    asyncio.run(run())


def test_late_read_and_cancelled_read_cannot_cross_attachment():
    async def run():
        started, done = asyncio.Event(), asyncio.Event()

        async def dispatcher(method, params):
            started.set()
            await done.wait()
            return {"old": True}

        ws = VirtualWebSocket()
        await ws.accept()
        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="c",
            websocket=ws,
            close_controller=Controllers().close,
            read_dispatcher=dispatcher,
        )
        lease.start()
        first = lease.attach()
        await first.next_text()
        await first.feed_text(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "relay.sessions.list",
                    "params": {"profile": "default"},
                }
            )
        )
        await asyncio.wait_for(started.wait(), 1)
        first.detach()
        second = lease.attach()
        await second.next_text()
        done.set()
        await asyncio.gather(*lease._read_tasks)
        await ws.send_text('{"id":1,"result":{"new":true}}')
        assert json.loads(await second.next_text(timeout=1))["result"] == {"new": True}
        done.clear()
        await second.feed_text(
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "relay.sessions.list", "params": {}})
        )
        tasks = list(lease._read_tasks)
        await asyncio.sleep(0)
        await lease.release()
        assert all(t.cancelled() for t in tasks)

    asyncio.run(run())
