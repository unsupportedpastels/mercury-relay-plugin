"""Owner-private, bounded connection lifecycle diagnostics.

The journal is deliberately separate from operational metrics. It is a small
sanitized JSONL ring for the local owner only; it never receives URLs, routing
values, device/session identifiers, keys, tokens, or message content. A
telemetry failure is treated as a dropped diagnostic event and cannot affect the
relay transport.
"""

from __future__ import annotations

import datetime as _datetime
import json
import os
import re
import secrets
import stat
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Any

from . import secure_fs
from .config import ProfilePaths, _secure_directory
from .state_store import _read_bounded

JOURNAL_DIR_NAME = "operations"
JOURNAL_FILE_NAME = "connection-journal.jsonl"
JOURNAL_SCHEMA_VERSION = 1
DEFAULT_MAX_JOURNAL_BYTES = 64 * 1024
DEFAULT_MAX_ROTATED_FILES = 2
DEFAULT_MEMORY_EVENTS = 64
DEFAULT_WRITER_QUEUE = 64
MAX_EVENT_BYTES = 2 * 1024
MAX_EVENT_AGE_MS = 7 * 24 * 60 * 60 * 1000
MAX_GENERATION = 2**31 - 1
MAX_ATTEMPT_NUMBER = 2**31 - 1
MAX_CLOSE_CODE = 65_535

_EVENT_NAMES = frozenset(
    {
        "connection_attempt",
        "connection_open",
        "disconnect",
        "handshake_outcome",
        "admission_outcome",
        "reconnect_attempt",
        "reconnect_backoff",
        "reconnect_result",
        "host_generation_change",
    }
)
_OUTCOMES = frozenset({"unknown", "started", "success", "failed", "rejected", "timeout", "closed"})
_REASONS = frozenset(
    {
        "unknown",
        "connect_started",
        "connect_failed",
        "connection_closed",
        "connection_failed",
        "connection_limit",
        "handshake_failed",
        "handshake_timeout",
        "protocol_violation",
        "timeout",
        "pairing_pending",
        "pairing_rejected",
        "pairing_ack_failed",
        "device_not_authorized",
        "invalid_auth_envelope",
        "lease_not_available",
        "profile_not_available",
        "runtime_unavailable",
        "channel_already_admitted",
        "controller_transport",
        "backpressure",
        "socket_closed",
        "shutdown",
    }
)
_EXCEPTION_CATEGORIES = frozenset(
    {
        "timeout",
        "unauthorized",
        "connection",
        "protocol",
        "admission",
        "transport",
        "os_error",
        "value_error",
        "cancelled",
        "other",
        "unknown",
    }
)
_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "timestamp",
        "event",
        "attempt_id",
        "connection_id",
        "generation",
        "outcome",
        "reason",
        "exception_category",
        "backoff_ms",
        "attempt_number",
        "connection_age_ms",
        "last_send_age_ms",
        "last_receive_age_ms",
        "close_code",
    }
)
_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def upgrade_refused_status(error: BaseException | None) -> int | None:
    """HTTP status of a refused WebSocket upgrade, from the exception's typed
    attributes only (``websockets`` spells it ``status_code`` or
    ``response.status_code`` across releases); never from its text."""

    if error is None:
        return None
    status = getattr(error, "status_code", None)
    if status is None:
        status = getattr(getattr(error, "response", None), "status_code", None)
    if isinstance(status, bool) or not isinstance(status, int):
        return None
    return status if 100 <= status <= 599 else None


def exception_category(error: BaseException | None) -> str | None:
    """Return a closed exception category without inspecting exception text."""

    if error is None:
        return None
    if upgrade_refused_status(error) in (401, 403):
        return "unauthorized"
    if isinstance(error, (TimeoutError,)):  # asyncio.TimeoutError aliases this.
        return "timeout"
    if isinstance(error, ConnectionError):
        return "connection"
    if isinstance(error, (ValueError, TypeError)):
        return "value_error"
    if isinstance(error, OSError):
        return "os_error"
    if error.__class__.__name__ == "CancelledError":
        return "cancelled"
    name = error.__class__.__name__.casefold()
    if "securechannel" in name or "protocol" in name:
        return "protocol"
    if "admission" in name or "pairing" in name:
        return "admission"
    if "transport" in name:
        return "transport"
    return "other"


def _bounded_int(value: Any, *, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        return None
    return value


def _safe_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _ID_RE.fullmatch(value) else None


def _safe_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        return None
    try:
        _datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
    return value


def sanitize_connection_event(value: Mapping[str, Any]) -> dict[str, Any] | None:
    """Validate one event against the closed export schema.

    Unknown keys invalidate the whole event instead of being copied. All
    string-valued diagnostic fields are closed vocabularies or fixed-format
    ephemeral IDs; no caller-provided string is ever emitted.
    """

    if not isinstance(value, Mapping) or not set(value) <= _EVENT_KEYS:
        return None
    if value.get("schema_version") != JOURNAL_SCHEMA_VERSION:
        return None
    timestamp = _safe_timestamp(value.get("timestamp"))
    event = value.get("event")
    if timestamp is None or event not in _EVENT_NAMES:
        return None

    def safe_choice(candidate: Any, allowed: frozenset[str]) -> str | None:
        return candidate if candidate is None or candidate in allowed else "unknown"

    return {
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "timestamp": timestamp,
        "event": event,
        "attempt_id": _safe_id(value.get("attempt_id")),
        "connection_id": _safe_id(value.get("connection_id")),
        "generation": _bounded_int(value.get("generation"), maximum=MAX_GENERATION),
        "outcome": safe_choice(value.get("outcome"), _OUTCOMES),
        "reason": safe_choice(value.get("reason"), _REASONS),
        "exception_category": safe_choice(value.get("exception_category"), _EXCEPTION_CATEGORIES),
        "backoff_ms": _bounded_int(value.get("backoff_ms"), maximum=MAX_EVENT_AGE_MS),
        "attempt_number": _bounded_int(value.get("attempt_number"), maximum=MAX_ATTEMPT_NUMBER),
        "connection_age_ms": _bounded_int(value.get("connection_age_ms"), maximum=MAX_EVENT_AGE_MS),
        "last_send_age_ms": _bounded_int(value.get("last_send_age_ms"), maximum=MAX_EVENT_AGE_MS),
        "last_receive_age_ms": _bounded_int(
            value.get("last_receive_age_ms"), maximum=MAX_EVENT_AGE_MS
        ),
        "close_code": _bounded_int(value.get("close_code"), maximum=MAX_CLOSE_CODE),
    }


def sanitize_connection_events(values: Any) -> list[dict[str, Any]]:
    """Return only sanitized events, capped for safe diagnostics export."""

    if not isinstance(values, (list, tuple, deque)):
        return []
    result: deque[dict[str, Any]] = deque(maxlen=DEFAULT_MEMORY_EVENTS)
    for value in values:
        event = sanitize_connection_event(value)
        if event is not None:
            result.append(event)
    return list(result)


def _timestamp(clock: Callable[[], float]) -> str | None:
    try:
        value = clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        moment = _datetime.datetime.fromtimestamp(value, tz=_datetime.UTC)
        return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, TypeError, ValueError):
        return None


class ConnectionJournal:
    """A bounded memory snapshot plus an owner-private rotating JSONL journal."""

    event_keys = _EVENT_KEYS

    def __init__(
        self,
        paths: ProfilePaths,
        *,
        max_bytes: int = DEFAULT_MAX_JOURNAL_BYTES,
        max_files: int = DEFAULT_MAX_ROTATED_FILES,
        memory_limit: int = DEFAULT_MEMORY_EVENTS,
        writer_queue_limit: int = DEFAULT_WRITER_QUEUE,
        clock: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(paths, ProfilePaths):
            raise TypeError("paths must be ProfilePaths")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes <= 0
            or isinstance(max_files, bool)
            or not isinstance(max_files, int)
            or not 1 <= max_files <= 4
            or isinstance(memory_limit, bool)
            or not isinstance(memory_limit, int)
            or not 1 <= memory_limit <= 256
            or isinstance(writer_queue_limit, bool)
            or not isinstance(writer_queue_limit, int)
            or not 1 <= writer_queue_limit <= 256
        ):
            raise ValueError("invalid connection journal bounds")
        self.paths = paths
        self.path = Path(paths.agent_dir) / JOURNAL_DIR_NAME / JOURNAL_FILE_NAME
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.memory_limit = memory_limit
        self.writer_queue_limit = writer_queue_limit
        self._clock = clock or time.time
        self._monotonic = monotonic or time.monotonic
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=memory_limit)
        self._write_queue: Queue[bytes] = Queue(maxsize=writer_queue_limit)
        self._writer: threading.Thread | None = None
        self._writer_stop = threading.Event()
        self._writer_closed = False
        self._dropped_events = 0
        self._storage_available = False
        self._write_failure_count = 0
        self._host_generation: int | None = None
        self._host_connected = False
        self._host_opened_at: float | None = None
        self._host_last_send: float | None = None
        self._host_last_receive: float | None = None
        self._connections: dict[str, tuple[float, float | None, float | None]] = {}
        self._storage_ready = False
        try:
            paths.ensure()
            _secure_directory(self.path.parent)
            self._storage_ready = True
            self._storage_available = True
            self._load_persisted()
        except Exception:
            # Diagnostics must be optional, including when its directory is
            # unavailable or contains a malformed old file.
            self._storage_ready = False

    @property
    def rotated_path(self) -> Path:
        return self.path.with_name(self.path.name + ".1")

    def new_attempt_id(self) -> str:
        try:
            return secrets.token_hex(8)
        except Exception:
            return "0" * 16

    def new_connection_id(self) -> str:
        try:
            return secrets.token_hex(8)
        except Exception:
            return "f" * 16

    def _now_monotonic(self) -> float | None:
        try:
            value = self._monotonic()
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None
            return value
        except Exception:
            return None

    def _age_ms(self, start: float | None, now: float | None = None) -> int | None:
        if start is None:
            return None
        current = self._now_monotonic() if now is None else now
        if current is None:
            return None
        try:
            return max(0, min(MAX_EVENT_AGE_MS, int((current - start) * 1000)))
        except (OverflowError, TypeError, ValueError):
            return None

    def _normalize_event(self, event: str, fields: Mapping[str, Any]) -> dict[str, Any] | None:
        value = {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "timestamp": _timestamp(self._clock),
            "event": event,
            "attempt_id": fields.get("attempt_id"),
            "connection_id": fields.get("connection_id"),
            "generation": fields.get("generation"),
            "outcome": fields.get("outcome"),
            "reason": fields.get("reason"),
            "exception_category": fields.get("exception_category"),
            "backoff_ms": fields.get("backoff_ms"),
            "attempt_number": fields.get("attempt_number"),
            "connection_age_ms": fields.get("connection_age_ms"),
            "last_send_age_ms": fields.get("last_send_age_ms"),
            "last_receive_age_ms": fields.get("last_receive_age_ms"),
            "close_code": fields.get("close_code"),
        }
        if value["timestamp"] is None:
            return None
        return sanitize_connection_event(value)

    def record(self, event: str, **fields: Any) -> None:
        """Append one closed-schema event; all failures are swallowed."""

        try:
            normalized = self._normalize_event(event, fields)
            if normalized is None:
                return
            line = (
                json.dumps(
                    normalized, ensure_ascii=True, allow_nan=False, separators=(",", ":")
                ).encode("ascii")
                + b"\n"
            )
            if len(line) > min(MAX_EVENT_BYTES, self.max_bytes):
                return
            with self._lock:
                self._events.append(normalized)
            self._enqueue(line)
        except Exception:
            pass

    def _ensure_writer(self) -> None:
        if self._writer is not None or self._writer_closed:
            return
        try:
            writer = threading.Thread(
                target=self._writer_loop,
                name="mercury-relay-connection-journal",
                daemon=True,
            )
            self._writer = writer
            writer.start()
        except Exception:
            self._writer = None
            self._mark_write_failure()

    def _enqueue(self, line: bytes) -> None:
        with self._lock:
            if self._writer_closed:
                return
            self._ensure_writer()
            try:
                self._write_queue.put_nowait(line)
            except Full:
                self._dropped_events += 1

    def _writer_loop(self) -> None:
        while not self._writer_stop.is_set() or not self._write_queue.empty():
            try:
                line = self._write_queue.get(timeout=0.02)
            except Empty:
                continue
            try:
                try:
                    self._persist(line)
                except Exception:
                    self._mark_write_failure()
            finally:
                self._write_queue.task_done()

    def _mark_write_failure(self) -> None:
        self._storage_available = False
        self._write_failure_count += 1

    def flush(self, timeout: float = 0.25) -> bool:
        """Best-effort bounded flush; never waits indefinitely on storage."""

        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            return False
        deadline = time.monotonic() + float(timeout)
        while self._write_queue.unfinished_tasks:
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
        return True

    def close(self, timeout: float = 0.25) -> bool:
        """Stop the one bounded writer worker after a bounded drain attempt."""

        with self._lock:
            self._writer_closed = True
            writer = self._writer
            self._writer_stop.set()
        if writer is None:
            return True
        self.flush(timeout)
        writer.join(max(0.0, float(timeout)))
        return not writer.is_alive()

    def _persist(self, line: bytes) -> None:
        if not self._storage_ready:
            return
        try:
            _secure_directory(self.path.parent)
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size + len(line) > self.max_bytes:
                self._rotate()
                current_size = 0
            if current_size + len(line) > self.max_bytes:
                return
            fd = secure_fs.open_append_nofollow(self.path, 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    return
                secure_fs.fchmod_private(fd, 0o600)
                if info.st_size + len(line) > self.max_bytes:
                    return
                written = os.write(fd, line)
                if written != len(line):
                    return
            finally:
                with suppress(OSError):
                    os.close(fd)
        except (OSError, ValueError):
            self._mark_write_failure()
            return

    def _rotate(self) -> None:
        if self.max_files <= 1:
            with suppress(OSError):
                self.path.unlink()
            return
        for index in range(self.max_files - 1, 0, -1):
            source = self.path.with_name(self.path.name + f".{index}")
            destination = self.path.with_name(self.path.name + f".{index + 1}")
            if source.exists():
                if index + 1 > self.max_files:
                    with suppress(OSError):
                        source.unlink()
                else:
                    os.replace(source, destination)
        if self.path.exists():
            os.replace(self.path, self.rotated_path)

    def _load_persisted(self) -> None:
        for path in self._persisted_paths():
            try:
                raw = _read_bounded(path, self.max_bytes)
            except Exception:
                continue
            for line in raw.splitlines():
                if len(line) > MAX_EVENT_BYTES:
                    continue
                try:
                    candidate = json.loads(line.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                event = sanitize_connection_event(candidate)
                if event is not None:
                    self._events.append(event)

    def _persisted_paths(self) -> list[Path]:
        return [
            self.path.with_name(self.path.name + f".{index}")
            for index in range(self.max_files - 1, 0, -1)
        ] + [self.path]

    def _track_connection(self, connection_id: str) -> None:
        if len(self._connections) >= 64 and connection_id not in self._connections:
            self._connections.pop(next(iter(self._connections)))
        now = self._now_monotonic()
        if now is not None:
            self._connections[connection_id] = (now, None, None)

    def connection_attempt(self, connection_id: str, *, attempt_id: str | None = None) -> None:
        self.record(
            "connection_attempt",
            attempt_id=attempt_id,
            connection_id=connection_id,
            outcome="started",
            reason="connect_started",
        )

    def connection_open(
        self,
        connection_id: str,
        *,
        attempt_id: str | None = None,
        generation: int | None = None,
    ) -> None:
        self._track_connection(connection_id)
        self.record(
            "connection_open",
            attempt_id=attempt_id,
            connection_id=connection_id,
            generation=generation,
            outcome="success",
        )

    def connection_disconnect(
        self,
        connection_id: str,
        *,
        reason: str | None = None,
        exception_category_value: str | None = None,
        attempt_id: str | None = None,
        close_code: int | None = None,
    ) -> None:
        state = self._connections.pop(connection_id, None)
        now = self._now_monotonic()
        self.record(
            "disconnect",
            attempt_id=attempt_id,
            connection_id=connection_id,
            outcome="closed",
            reason=reason,
            exception_category=exception_category_value,
            connection_age_ms=self._age_ms(state[0], now) if state else None,
            last_send_age_ms=self._age_ms(state[1], now) if state else None,
            last_receive_age_ms=self._age_ms(state[2], now) if state else None,
            close_code=close_code,
        )

    def mark_send(self, connection_id: str | None = None) -> None:
        now = self._now_monotonic()
        if now is None:
            return
        if connection_id is None:
            self._host_last_send = now
            return
        state = self._connections.get(connection_id)
        if state is not None:
            self._connections[connection_id] = (state[0], now, state[2])

    def mark_receive(self, connection_id: str | None = None) -> None:
        now = self._now_monotonic()
        if now is None:
            return
        if connection_id is None:
            self._host_last_receive = now
            return
        state = self._connections.get(connection_id)
        if state is not None:
            self._connections[connection_id] = (state[0], state[1], now)

    def host_open(self, *, attempt_id: str | None, generation: int | None) -> None:
        self._host_connected = True
        self._host_generation = (
            max(0, min(MAX_GENERATION, generation))
            if isinstance(generation, int) and not isinstance(generation, bool)
            else None
        )
        self._host_opened_at = self._now_monotonic()
        self._host_last_send = None
        self._host_last_receive = None
        self.record(
            "connection_open",
            attempt_id=attempt_id,
            generation=generation,
            outcome="success",
        )
        self.record(
            "host_generation_change",
            attempt_id=attempt_id,
            generation=generation,
            outcome="success",
        )

    def host_disconnect(
        self,
        *,
        attempt_id: str | None,
        reason: str | None,
        exception_category_value: str | None = None,
        close_code: int | None = None,
    ) -> None:
        now = self._now_monotonic()
        self.record(
            "disconnect",
            attempt_id=attempt_id,
            generation=self._host_generation,
            outcome="closed",
            reason=reason,
            exception_category=exception_category_value,
            connection_age_ms=self._age_ms(self._host_opened_at, now),
            last_send_age_ms=self._age_ms(self._host_last_send, now),
            last_receive_age_ms=self._age_ms(self._host_last_receive, now),
            close_code=close_code,
        )
        self._host_connected = False
        self._host_opened_at = None
        self._host_last_send = None
        self._host_last_receive = None

    def handshake_outcome(
        self,
        connection_id: str,
        *,
        outcome: str,
        reason: str | None = None,
        exception_category_value: str | None = None,
    ) -> None:
        self.record(
            "handshake_outcome",
            connection_id=connection_id,
            outcome=outcome,
            reason=reason,
            exception_category=exception_category_value,
        )

    def admission_outcome(
        self,
        connection_id: str,
        *,
        outcome: str,
        reason: str | None = None,
        exception_category_value: str | None = None,
    ) -> None:
        self.record(
            "admission_outcome",
            connection_id=connection_id,
            outcome=outcome,
            reason=reason,
            exception_category=exception_category_value,
        )

    def reconnect_attempt(self, *, attempt_id: str, attempt_number: int) -> None:
        self.record(
            "reconnect_attempt",
            attempt_id=attempt_id,
            attempt_number=attempt_number,
            outcome="started",
            reason="connect_started",
        )

    def reconnect_backoff(self, *, attempt_id: str, backoff_ms: int) -> None:
        self.record(
            "reconnect_backoff",
            attempt_id=attempt_id,
            backoff_ms=backoff_ms,
            outcome="started",
        )

    def reconnect_result(
        self,
        *,
        attempt_id: str,
        outcome: str,
        reason: str | None = None,
        exception_category_value: str | None = None,
    ) -> None:
        self.record(
            "reconnect_result",
            attempt_id=attempt_id,
            outcome=outcome,
            reason=reason,
            exception_category=exception_category_value,
        )

    def snapshot(self) -> dict[str, Any]:
        now = self._now_monotonic()
        return {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "connected": self._host_connected,
            "host_generation": self._host_generation,
            "connection_age_ms": self._age_ms(self._host_opened_at, now),
            "last_send_age_ms": self._age_ms(self._host_last_send, now),
            "last_receive_age_ms": self._age_ms(self._host_last_receive, now),
            "active_connection_count": len(self._connections),
            "memory_event_limit": self.memory_limit,
            "dropped_event_count": self._dropped_events,
            "persistence_available": self._storage_available,
            "write_failure_count": self._write_failure_count,
        }

    def export(self) -> dict[str, Any]:
        with self._lock:
            events = [dict(event) for event in self._events]
        return {
            "schema_version": JOURNAL_SCHEMA_VERSION,
            "snapshot": self.snapshot(),
            "events": sanitize_connection_events(events)[-self.memory_limit :],
        }


__all__ = [
    "ConnectionJournal",
    "DEFAULT_MAX_JOURNAL_BYTES",
    "JOURNAL_FILE_NAME",
    "JOURNAL_SCHEMA_VERSION",
    "exception_category",
    "sanitize_connection_event",
    "sanitize_connection_events",
]
