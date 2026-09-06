from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
from conftest import posix_only

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.connection_journal import (
    ConnectionJournal,
    sanitize_connection_event,
)


@posix_only
def test_journal_is_bounded_private_rotating_and_sanitized(tmp_path: Path) -> None:
    paths = profile_paths(explicit_path=tmp_path)
    journal = ConnectionJournal(paths, max_bytes=2_200, memory_limit=3)

    attempt = journal.new_attempt_id()
    connection = journal.new_connection_id()
    journal.record(
        "connection_attempt",
        attempt_id=attempt,
        connection_id=connection,
        reason="connect_started",
    )
    journal.record(
        "handshake_outcome",
        attempt_id=attempt,
        connection_id=connection,
        outcome="failed",
        reason="timeout",
        exception_category="timeout",
    )
    for _ in range(12):
        journal.record(
            "disconnect",
            attempt_id=attempt,
            connection_id=connection,
            reason="connection_failed",
            exception_category="connection",
            connection_age_ms=42,
        )

    journal.close()
    assert journal.path.stat().st_mode & 0o777 == 0o600
    assert journal.path.stat().st_size <= 2_200
    rotated = journal.path.with_name(journal.path.name + ".1")
    assert rotated.exists()
    assert rotated.stat().st_size <= 2_200
    assert len(journal.export()["events"]) <= 3
    raw = journal.path.read_text(encoding="utf-8") + rotated.read_text(encoding="utf-8")
    assert "https://" not in raw
    assert "Bearer" not in raw
    assert "secret" not in raw
    assert all(set(event) <= journal.event_keys for event in journal.export()["events"])


def test_journal_retains_sanitized_events_after_restart(tmp_path: Path) -> None:
    paths = profile_paths(explicit_path=tmp_path)
    first = ConnectionJournal(paths, memory_limit=8)
    first.record(
        "admission_outcome",
        connection_id=first.new_connection_id(),
        outcome="rejected",
        reason="device_not_authorized",
        exception_category="admission",
    )
    first.close()

    second = ConnectionJournal(paths, memory_limit=8)

    events = second.export()["events"]
    assert len(events) == 1
    assert events[0]["event"] == "admission_outcome"
    assert events[0]["reason"] == "device_not_authorized"
    assert "device_id" not in json.dumps(events)


def test_sanitizer_drops_unknown_fields_and_never_echoes_raw_values() -> None:
    event = sanitize_connection_event(
        {
            "schema_version": 1,
            "timestamp": "2026-09-05T00:00:00.000Z",
            "event": "disconnect",
            "attempt_id": "not-an-ephemeral-id",
            "connection_id": "also-not-an-id",
            "reason": "https://relay.example/private?token=secret",
            "exception_category": "Traceback with bearer secret",
            "route": "/v1/host/private",
        }
    )

    assert event is None


def test_telemetry_failures_are_best_effort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = ConnectionJournal(profile_paths(explicit_path=tmp_path))
    monkeypatch.setattr(journal, "_persist", lambda _line: (_ for _ in ()).throw(OSError("disk")))

    journal.record("connection_open", generation=1, outcome="success")
    journal.close()

    assert journal.export()["events"][0]["event"] == "connection_open"
    assert journal.snapshot()["persistence_available"] is False
    assert journal.snapshot()["write_failure_count"] >= 1


def test_journal_calls_do_not_block_or_raise_when_clock_fails(tmp_path: Path) -> None:
    journal = ConnectionJournal(profile_paths(explicit_path=tmp_path))
    journal._clock = lambda: (_ for _ in ()).throw(RuntimeError("clock"))

    journal.record("reconnect_attempt", attempt_number=1)
    assert journal.export()["events"] == []


def test_slow_storage_is_not_on_record_path_and_drops_are_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = ConnectionJournal(
        profile_paths(explicit_path=tmp_path), writer_queue_limit=1, memory_limit=8
    )

    def slow_persist(_line: bytes) -> None:
        time.sleep(0.2)

    monkeypatch.setattr(journal, "_persist", slow_persist)
    started = time.monotonic()
    for _ in range(40):
        journal.record("reconnect_attempt", attempt_number=1)
    elapsed = time.monotonic() - started

    assert elapsed < 0.1
    assert journal.snapshot()["dropped_event_count"] > 0
    assert journal.close(timeout=0.01) is False


def test_host_disconnect_keeps_generation_and_numeric_close_code_only(tmp_path: Path) -> None:
    journal = ConnectionJournal(profile_paths(explicit_path=tmp_path))
    attempt = journal.new_attempt_id()
    journal.host_open(attempt_id=attempt, generation=1_720_000_123)
    journal.host_disconnect(
        attempt_id=attempt,
        reason="socket_closed",
        exception_category_value="connection",
        close_code=1006,
    )
    journal.close()

    events = journal.export()["events"]
    assert any(
        event["event"] == "host_generation_change" and event["generation"] == 1_720_000_123
        for event in events
    )
    disconnect = [event for event in events if event["event"] == "disconnect"][-1]
    assert disconnect["close_code"] == 1006
    assert "reason_text" not in json.dumps(events)
