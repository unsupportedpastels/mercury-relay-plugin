"""Bounded observation-only child recovery; never reads Hermes private state."""

from __future__ import annotations

import copy
import json
import math
import time
from collections import OrderedDict
from pathlib import Path

from .config import _secure_directory
from .state_store import _atomic_write, _read_bounded
from .strict_json import loads_strict

MAX_ROWS = 64
MAX_STORE_ROWS = 256
MAX_STORE_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024
TERMINAL = frozenset({"completed", "failed", "cancelled", "interrupted", "error", "timeout"})
TEXT_FIELDS = {
    "subagent_id": 128,
    "child_session_id": 128,
    "delegation_id": 128,
    "parent_id": 128,
    "goal": 500,
    "action": 500,
    "summary": 500,
    "status": 32,
    "model": 128,
    "tool": 128,
    "tool_name": 128,
    "text": 500,
}
IDENTITY_FIELDS = frozenset({"subagent_id", "child_session_id", "delegation_id", "parent_id"})


def identifier(value):
    return value if isinstance(value, str) and 0 < len(value) <= 128 else None


def child_key(payload):
    for name in ("subagent_id", "child_session_id"):
        if identifier(payload.get(name)):
            return name + ":" + payload[name]
    delegation = identifier(payload.get("delegation_id"))
    index = payload.get("task_index")
    if delegation and type(index) is int and 0 <= index <= 10000:
        return f"delegation:{delegation}:{index}"
    return None


class RecoveryStore:
    """Atomic fsync-before-delivery projection, independent of streaming ring.

    No raw frames/credentials are stored. One installation-owned writer (serve)
    owns this bounded file. A corrupt/unavailable store fails closed at admission.
    """

    def __init__(
        self, path: Path, *, clock=time.time, max_rows=MAX_STORE_ROWS, ttl_seconds=7 * 86400
    ):
        self.path = path
        self.clock = clock
        self.max_rows = min(MAX_STORE_ROWS, max(1, max_rows))
        self.ttl_seconds = ttl_seconds
        _secure_directory(path.parent)
        self.rows = []
        self.revision = 0
        self.truncated = False
        try:
            data = loads_strict(_read_bounded(path, MAX_STORE_BYTES).decode("utf-8"))
        except FileNotFoundError:
            return
        if (
            not isinstance(data, dict)
            or data.get("version") != 1
            or not isinstance(data.get("rows"), list)
        ):
            raise ValueError("invalid recovery store")
        self.rows = data["rows"]
        if (
            len(self.rows) > MAX_STORE_ROWS
            or type(data.get("revision")) is not int
            or not 0 <= data["revision"] <= 2**63 - 1
        ):
            raise ValueError("invalid recovery store")
        self.revision = data["revision"]
        for row in self.rows:
            self._validate_row(row)
        self.truncated = bool(data.get("truncated"))
        self._prune()

    @staticmethod
    def _validate_row(row):
        try:
            key, event, expiry = row["key"], row["event"], row["expires_at"]
            params = event["params"]
            binding, payload = params["recovery_binding"], params["payload"]
            valid = (
                isinstance(key, list)
                and len(key) == 6
                and all(identifier(key[i]) for i in (0, 1, 3, 4))
                and type(key[2]) is int
                and 0 <= key[2] <= 2**31 - 1
                and type(expiry) in (int, float)
                and math.isfinite(expiry)
                and event["method"] == "event"
                and event["jsonrpc"] == "2.0"
                and identifier(params["session_id"])
                and binding["runtime_session_id"] == params["session_id"]
                and binding["durable_session_id"] == key[4] == params["durable_session_id"]
                and binding["profile"] == key[3] == params["profile"]
                and child_key(payload) == key[5]
                and type(params["recovery_revision"]) is int
                and params["relay_event_id"] == f"projection:{params['recovery_revision']}"
                and all(
                    (k in TEXT_FIELDS and isinstance(v, str) and len(v) <= TEXT_FIELDS[k])
                    or (
                        k in {"task_index", "task_count", "depth", "tool_count"}
                        and type(v) is int
                        and 0 <= v <= 10000
                    )
                    for k, v in payload.items()
                )
                and len(json.dumps(event, ensure_ascii=True).encode()) <= 32768
            )
        except (KeyError, TypeError, AttributeError, ValueError):
            valid = False
        if not valid:
            raise ValueError("invalid recovery store")

    def _prune(self):
        now = self.clock()
        kept = [r for r in self.rows if r["expires_at"] > now]
        if len(kept) != len(self.rows) or len(kept) > self.max_rows:
            self.truncated = True
        self.rows = kept[-self.max_rows :]

    def _save(self):
        self._prune()

        def encode():
            return json.dumps(
                {
                    "version": 1,
                    "revision": self.revision,
                    "truncated": self.truncated,
                    "rows": self.rows,
                },
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode()

        raw = encode()
        while len(raw) > MAX_STORE_BYTES and self.rows:
            self.rows.pop(0)
            self.truncated = True
            raw = encode()
        _atomic_write(self.path, raw)

    def put(self, scope, event):
        before = (list(self.rows), self.revision, self.truncated)
        params = event["params"]
        binding = params["recovery_binding"]
        key = [
            *scope,
            binding["profile"],
            binding["durable_session_id"],
            child_key(params["payload"]),
        ]
        self._prune()
        prior = next((r for r in self.rows if r["key"] == key), None)
        if prior and prior["event"]["params"]["payload"].get("status") in TERMINAL:
            # Duplicate replay and stale starts cannot downgrade terminal evidence.
            params["payload"] = copy.deepcopy(prior["event"]["params"]["payload"])
            params["type"] = prior["event"]["params"]["type"]
            return prior["event"]["params"]["recovery_revision"]
        self.revision += 1
        stored = copy.deepcopy(event)
        stored["params"]["recovery_revision"] = self.revision
        stored["params"]["relay_event_id"] = f"projection:{self.revision}"
        self.rows = [r for r in self.rows if r["key"] != key]
        self.rows.append(
            {"key": key, "expires_at": self.clock() + self.ttl_seconds, "event": stored}
        )
        try:
            self._save()
        except Exception:
            self.rows, self.revision, self.truncated = before
            raise
        return self.revision

    def snapshot(self, scope, profile_authorizer):
        self._prune()
        result = []
        for row in self.rows:
            if row["key"][:3] != list(scope) or not profile_authorizer(row["key"][3]):
                continue
            event = copy.deepcopy(row["event"])
            params = event["params"]
            params["recovery_binding"]["live"] = False
            if params["payload"].get("status") not in TERMINAL:
                params["payload"]["status"] = "unknown"
            result.append(event)
        return result[-MAX_ROWS:], self.truncated or len(result) > MAX_ROWS

    def revoke(self, installation, device):
        # Channel-scoped leases store the device as "<device>/<channel>".
        prefix = device + "/"
        self.rows = [
            r
            for r in self.rows
            if not (
                r["key"][0] == installation
                and (r["key"][1] == device or str(r["key"][1]).startswith(prefix))
            )
        ]
        self._save()


def recovery_scope_device(device_id, channel=""):
    """Durable scope component for one (device, channel) lease.

    The default channel keeps the bare device id so existing lease-recovery
    rows stay readable; named channels append "/<channel>" (device ids are
    base64url and never contain "/").
    """

    return device_id if not channel else f"{device_id}/{channel}"


class RecoveryProjection:
    def __init__(self, profile, *, store=None, scope=None, profile_authorizer=lambda p: True):
        self.profile = profile
        self.store = store
        self.scope = scope
        self.profile_authorizer = profile_authorizer
        self.pending = OrderedDict()
        self.bindings = OrderedDict()
        self.tasks = OrderedDict()
        self.truncated = False
        self.revision = 0

    def request(self, value):
        if not isinstance(value, dict) or value.get("method") not in {
            "session.create",
            "session.resume",
        }:
            return
        rid = value.get("id")
        params = value.get("params", {})
        if not (
            identifier(rid) or (type(rid) is int and -(2**63) <= rid < 2**63)
        ) or not isinstance(params, dict):
            return
        # Admission profile is routing context, not proof of actual RPC profile.
        profile = params.get("profile")
        if not identifier(profile) or not self.profile_authorizer(profile):
            return
        self.pending[rid] = profile
        while len(self.pending) > MAX_ROWS:
            self.pending.popitem(last=False)
            self.truncated = True

    def observe(self, text):
        try:
            value = loads_strict(text)
        except Exception:
            return
        if not isinstance(value, dict):
            return
        if "method" not in value:
            rid = value.get("id")
            if type(rid) not in (str, int):
                return
            profile = self.pending.pop(rid, None)
            result = value.get("result")
            if profile and isinstance(result, dict):
                info = result.get("info")
                reported_profile = info.get("profile_name") if isinstance(info, dict) else None
                if reported_profile and reported_profile != profile:
                    self.truncated = True
                    return
                runtime = identifier(result.get("session_id"))
                durable = identifier(result.get("stored_session_id") or result.get("session_key"))
                if runtime and durable and self.profile_authorizer(profile):
                    self.bindings[runtime] = {
                        "runtime_session_id": runtime,
                        "durable_session_id": durable,
                        "profile": profile,
                        "live": True,
                    }
                    while len(self.bindings) > MAX_ROWS:
                        self.bindings.popitem(last=False)
                        self.truncated = True
                    # Some hosts emit child events before their create/resume reply.
                    for (sid, _), event in self.tasks.items():
                        if sid == runtime:
                            self._persist(event)
            return
        params = value.get("params")
        if value.get("method") != "event" or not isinstance(params, dict):
            return
        kind = params.get("type")
        runtime = identifier(params.get("session_id"))
        raw = params.get("payload")
        if (
            kind
            not in {"subagent.start", "subagent.progress", "subagent.tool", "subagent.complete"}
            or not runtime
            or not isinstance(raw, dict)
        ):
            return
        if any(k in raw and raw[k] and not identifier(raw[k]) for k in IDENTITY_FIELDS):
            self.truncated = True
            return
        payload = {
            k: v[: TEXT_FIELDS[k]]
            for k, v in raw.items()
            if k in TEXT_FIELDS and isinstance(v, str)
        }
        for k in ("task_index", "task_count", "depth", "tool_count"):
            if type(raw.get(k)) is int and 0 <= raw[k] <= 10000:
                payload[k] = raw[k]
        child = child_key(payload)
        if not child:
            return
        key = (runtime, child)
        previous = self.tasks.get(key)
        if previous and previous["params"]["payload"].get("status") in TERMINAL:
            return
        merged = dict(previous["params"]["payload"]) if previous else {}
        merged.update({k: v for k, v in payload.items() if v != ""})
        # Event name alone is not evidence of terminal success.
        self.revision += 1
        event = {
            "jsonrpc": "2.0",
            "method": "event",
            "params": {
                "session_id": runtime,
                "type": kind,
                "payload": merged,
                "recovery_revision": self.revision,
            },
        }
        self._persist(event)
        self.tasks[key] = event
        self.tasks.move_to_end(key)
        while len(self.tasks) > MAX_ROWS:
            self.tasks.popitem(last=False)
            self.truncated = True

    def _persist(self, event):
        binding = self.bindings.get(event["params"]["session_id"])
        if not binding or not self.profile_authorizer(binding["profile"]):
            return
        event["params"]["recovery_binding"] = dict(binding)
        event["params"]["durable_session_id"] = binding["durable_session_id"]
        event["params"]["profile"] = binding["profile"]
        if self.store is not None:
            event["params"]["recovery_revision"] = self.store.put(self.scope, event)
            event["params"]["relay_event_id"] = f"projection:{event['params']['recovery_revision']}"

    def snapshot(self):
        historical, truncated = (
            self.store.snapshot(self.scope, self.profile_authorizer) if self.store else ([], False)
        )
        rows = OrderedDict()

        def key(event):
            p = event["params"]
            b = p.get("recovery_binding", {})
            return (
                b.get("profile"),
                b.get("durable_session_id", p["session_id"]),
                child_key(p["payload"]),
            )

        for event in historical:
            rows[key(event)] = event
        for event in self.tasks.values():
            binding = event["params"].get("recovery_binding")
            if binding and not self.profile_authorizer(binding["profile"]):
                continue
            k = key(event)
            prior = rows.get(k)
            if (
                prior
                and prior["params"]["payload"].get("status") in TERMINAL
                and event["params"]["payload"].get("status") not in TERMINAL
            ):
                continue
            rows[k] = event
        tasks = list(rows.values())[-MAX_ROWS:]
        while len(json.dumps(tasks, ensure_ascii=True).encode()) > MAX_SNAPSHOT_BYTES:
            tasks.pop(0)
            truncated = True
        bindings = OrderedDict()
        for event in tasks:
            b = event["params"].get("recovery_binding")
            if b:
                bindings[(b["runtime_session_id"], b["durable_session_id"], b["profile"])] = b
        for b in self.bindings.values():
            if self.profile_authorizer(b["profile"]):
                bindings[(b["runtime_session_id"], b["durable_session_id"], b["profile"])] = b
        return {
            "task_snapshot": tasks,
            "bindings": list(bindings.values())[-MAX_ROWS:],
            "snapshot_complete": False,
            "snapshot_truncated": self.truncated or truncated or len(rows) > MAX_ROWS,
        }
