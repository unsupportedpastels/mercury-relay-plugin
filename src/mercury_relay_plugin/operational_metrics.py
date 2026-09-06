"""Owner-private aggregate operational counters for Mercury Relay.

The file intentionally contains no installation, device, profile, session, route,
or content identifiers. It is safe to mount read-only into the local operations
dashboard without exposing the plugin's cryptographic state file.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .config import ProfilePaths, _secure_directory
from .state_store import _atomic_write, _read_bounded

METRICS_FILE_NAME = "ops-metrics.json"
METRICS_DIR_NAME = "operations"
METRICS_SCHEMA_VERSION = 2
MAX_METRICS_BYTES = 4_096
_COUNTERS = (
    "total_pairings",
    "total_controller_opens",
    "total_reattachments",
)
_KEYS = frozenset(
    {
        "schema_version",
        "started_at",
        "updated_at",
        "active_leases",
        "registered_devices",
        *_COUNTERS,
    }
)


class OperationalMetricsError(RuntimeError):
    """Stable failure for invalid or unavailable aggregate metrics."""


def _validate(value: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(value, Mapping) or set(value) != _KEYS:
        raise OperationalMetricsError("invalid_operational_metrics")
    result: dict[str, int] = {}
    for key in _KEYS:
        candidate = value[key]
        if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate < 0:
            raise OperationalMetricsError("invalid_operational_metrics")
        result[key] = candidate
    if result["schema_version"] != METRICS_SCHEMA_VERSION:
        raise OperationalMetricsError("invalid_operational_metrics")
    if result["updated_at"] < result["started_at"]:
        raise OperationalMetricsError("invalid_operational_metrics")
    return result


def _encode(value: Mapping[str, Any]) -> bytes:
    validated = _validate(value)
    encoded = json.dumps(validated, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(encoded) > MAX_METRICS_BYTES:
        raise OperationalMetricsError("invalid_operational_metrics")
    return encoded


class OperationalMetrics:
    """Persist bounded aggregate counters through atomic owner-only writes."""

    def __init__(
        self,
        paths: ProfilePaths,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(paths, ProfilePaths):
            raise TypeError("paths must be ProfilePaths")
        paths.ensure()
        self.path = Path(paths.agent_dir) / METRICS_DIR_NAME / METRICS_FILE_NAME
        self.legacy_path = Path(paths.agent_dir) / METRICS_FILE_NAME
        _secure_directory(self.path.parent)
        self._clock = clock or time.time
        self._lock = threading.Lock()
        with self._lock:
            try:
                self._value = self._load()
            except FileNotFoundError:
                try:
                    self._value = self._load(self.legacy_path)
                except FileNotFoundError:
                    now = self._now()
                    self._value = {
                        "schema_version": METRICS_SCHEMA_VERSION,
                        "started_at": now,
                        "updated_at": now,
                        "total_pairings": 0,
                        "total_controller_opens": 0,
                        "total_reattachments": 0,
                        "active_leases": 0,
                        "registered_devices": 0,
                    }
                self._save()

    def _now(self) -> int:
        value = int(self._clock())
        if value < 0:
            raise OperationalMetricsError("invalid_operational_metrics")
        return value

    def _load(self, path: Path | None = None) -> dict[str, int]:
        try:
            raw = _read_bounded(path or self.path, MAX_METRICS_BYTES)
            value = json.loads(raw.decode("ascii"))
            if isinstance(value, dict) and value.get("schema_version") == 1:
                legacy_keys = _KEYS - {"registered_devices"}
                if set(value) != legacy_keys:
                    raise OperationalMetricsError("invalid_operational_metrics")
                value = dict(value)
                value["schema_version"] = METRICS_SCHEMA_VERSION
                value["registered_devices"] = 0
            return _validate(value)
        except FileNotFoundError:
            raise
        except Exception:
            raise OperationalMetricsError("invalid_operational_metrics") from None

    def _save(self) -> None:
        try:
            _atomic_write(self.path, _encode(self._value))
        except OperationalMetricsError:
            raise
        except Exception:
            raise OperationalMetricsError("operational_metrics_unavailable") from None

    def _record(self, counter: str | None, active_leases: int) -> None:
        if (
            isinstance(active_leases, bool)
            or not isinstance(active_leases, int)
            or active_leases < 0
        ):
            raise OperationalMetricsError("invalid_operational_metrics")
        if counter is not None and counter not in _COUNTERS:
            raise OperationalMetricsError("invalid_operational_metrics")
        with self._lock:
            if counter is not None:
                self._value[counter] += 1
            self._value["active_leases"] = active_leases
            self._value["updated_at"] = max(self._value["started_at"], self._now())
            self._save()

    def record_pairing(self, *, active_leases: int) -> None:
        self._record("total_pairings", active_leases)

    def record_controller_open(self, *, active_leases: int) -> None:
        self._record("total_controller_opens", active_leases)

    def record_reattachment(self, *, active_leases: int) -> None:
        self._record("total_reattachments", active_leases)

    def update_active_leases(self, active_leases: int) -> None:
        self._record(None, active_leases)

    def update_registered_devices(self, registered_devices: int) -> None:
        if (
            isinstance(registered_devices, bool)
            or not isinstance(registered_devices, int)
            or registered_devices < 0
        ):
            raise OperationalMetricsError("invalid_operational_metrics")
        with self._lock:
            self._value["registered_devices"] = registered_devices
            self._value["updated_at"] = max(self._value["started_at"], self._now())
            self._save()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._value)
