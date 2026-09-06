from __future__ import annotations

import json
from pathlib import Path

import pytest

from mercury_relay_plugin.admission import DeviceAdmissionService
from mercury_relay_plugin.authorization import AuthorizationRepository
from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.operational_metrics import OperationalMetrics, OperationalMetricsError
from mercury_relay_plugin.runtime import RelayRuntime


def test_metrics_persist_only_fixed_aggregate_counters(tmp_path: Path) -> None:
    metrics = OperationalMetrics(profile_paths(explicit_path=tmp_path), clock=lambda: 1_000)
    assert metrics.path.parent.name == "operations"
    metrics.update_registered_devices(2)
    metrics.record_pairing(active_leases=0)
    metrics.record_controller_open(active_leases=1)
    metrics.record_reattachment(active_leases=1)

    assert metrics.snapshot() == {
        "schema_version": 2,
        "started_at": 1_000,
        "updated_at": 1_000,
        "total_pairings": 1,
        "total_controller_opens": 1,
        "total_reattachments": 1,
        "active_leases": 1,
        "registered_devices": 2,
    }
    raw = metrics.path.read_text(encoding="utf-8")
    assert "device_id" not in raw
    assert "installation" not in raw
    assert "profile" not in raw
    assert metrics.path.stat().st_mode & 0o777 == 0o600


def test_metrics_upgrade_v1_without_exposing_device_records(tmp_path: Path) -> None:
    paths = profile_paths(explicit_path=tmp_path).ensure()
    path = paths.agent_dir / "ops-metrics.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "started_at": 1_000,
                "updated_at": 1_001,
                "total_pairings": 3,
                "total_controller_opens": 4,
                "total_reattachments": 5,
                "active_leases": 1,
            }
        ),
        encoding="ascii",
    )
    path.chmod(0o600)

    metrics = OperationalMetrics(paths, clock=lambda: 2_000)

    assert metrics.snapshot()["schema_version"] == 2
    assert metrics.snapshot()["registered_devices"] == 0
    assert json.loads(metrics.path.read_text(encoding="ascii"))["schema_version"] == 2


def test_metrics_survive_restart_and_reject_corruption(tmp_path: Path) -> None:
    paths = profile_paths(explicit_path=tmp_path)
    first = OperationalMetrics(paths, clock=lambda: 1_000)
    first.record_controller_open(active_leases=1)
    second = OperationalMetrics(paths, clock=lambda: 2_000)
    assert second.snapshot()["total_controller_opens"] == 1
    assert second.snapshot()["started_at"] == 1_000

    second.path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
    second.path.chmod(0o600)
    with pytest.raises(OperationalMetricsError):
        OperationalMetrics(paths, clock=lambda: 3_000)


def test_admission_start_resets_stale_process_local_active_lease_count(tmp_path: Path) -> None:
    class Bridge:
        async def start(self) -> None: ...

        async def close(self) -> None: ...

    paths = profile_paths(explicit_path=tmp_path)
    persisted = OperationalMetrics(paths, clock=lambda: 1_000)
    persisted.update_active_leases(3)
    repository = AuthorizationRepository(paths)
    runtime = RelayRuntime(
        loader=lambda: None,
        bridge_factory=lambda websocket: Bridge(),
        profile_authorizer=lambda profile: profile == "default",
    )

    admission = DeviceAdmissionService(repository, runtime, profile="default")

    assert admission.metrics is not None
    assert admission.metrics.snapshot()["active_leases"] == 0
    assert admission.metrics.snapshot()["registered_devices"] == 0
