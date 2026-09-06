import json

import pytest
from test_recovery_store import SCOPE, bind, event

from mercury_relay_plugin.lease_recovery import (
    MAX_SNAPSHOT_BYTES,
    RecoveryProjection,
    RecoveryStore,
)


def test_terminal_stays_authoritative_after_memory_eviction(tmp_path):
    store = RecoveryStore(tmp_path / "private" / "recovery.json")
    projection = RecoveryProjection("default", store=store, scope=SCOPE)
    bind(projection)
    projection.observe(event(summary="original terminal"))
    for n in range(65):
        projection.observe(event(child=f"other{n}", status="running"))
    projection.observe(event(status="failed", summary="stale terminal"))
    tasks = projection.snapshot()["task_snapshot"]
    child = next(e for e in tasks if e["params"]["payload"]["subagent_id"] == "child")
    assert child["params"]["payload"]["status"] == "completed"
    assert child["params"]["payload"]["summary"] == "original terminal"


def test_observation_bounds_identity_profile_and_failed_write(tmp_path, monkeypatch):
    path = tmp_path / "private" / "recovery.json"
    store = RecoveryStore(path)
    projection = RecoveryProjection("default", store=store, scope=SCOPE)
    bind(projection)
    projection.observe(event(child="x" * 129))
    assert projection.snapshot()["task_snapshot"] == []
    for n in range(70):
        projection.observe(
            event(child=f"child{n}", goal="🙂" * 500, summary="🙂" * 500, action="🙂" * 500)
        )
    snapshot = projection.snapshot()
    assert len(snapshot["task_snapshot"]) <= 64
    assert (
        len(json.dumps(snapshot["task_snapshot"], ensure_ascii=True).encode()) <= MAX_SNAPSHOT_BYTES
    )
    assert snapshot["snapshot_truncated"]
    unbound = RecoveryProjection("default", store=store, scope=("other", "device", 0))
    unbound.request({"id": 2, "method": "session.create", "params": {}})
    unbound.observe('{"id":2,"result":{"session_id":"foreign","stored_session_id":"foreign"}}')
    assert not unbound.bindings
    unbound.request({"id": 3, "method": "session.create", "params": {"profile": "default"}})
    unbound.observe(
        '{"id":3,"result":{"session_id":"foreign","stored_session_id":"foreign","info":{"profile_name":"researcher"}}}'
    )
    assert not unbound.bindings
    before = path.read_bytes()
    monkeypatch.setattr(
        "mercury_relay_plugin.lease_recovery._atomic_write",
        lambda *args: (_ for _ in ()).throw(OSError("disk unavailable")),
    )
    with pytest.raises(OSError):
        projection.observe(event(child="failed-write"))
    assert path.read_bytes() == before
    assert all(
        e["params"]["payload"]["subagent_id"] != "failed-write"
        for e in projection.snapshot()["task_snapshot"]
    )
