"""Opt-in generic and end-to-end encrypted push bridge.

The single asynchronous sender serializes registry changes and wakes. Preview
keys are scoped to the authenticated installation/device/authorization epoch,
persisted only in the private state file, and never leave this process after
provisioning over the existing Noise channel.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import time
from collections import OrderedDict

import httpx

from .config import canonicalize_relay_origin
from .push_preview import (
    MAX_ROUTE_PROFILE_BYTES,
    MAX_ROUTE_SESSION_BYTES,
    PREVIEW_CAPABILITY,
    PREVIEW_TTL_SECONDS,
    build_preview_plaintext,
    canonical_b64url,
    decode_canonical_b64url,
    encrypt_preview,
    normalize_title,
)
from .session_reads import SessionReadsError
from .state_store import _atomic_write, _read_bounded
from .strict_json import loads_strict

MAX_ROWS = 64
MAX_STATE_BYTES = 128 * 1024
MAX_PUSH_BODY_BYTES = 3072
QUEUE_SIZE = 64
TIMEOUT = 5.0
PENDING_ROUTE_TTL = 300.0
MAX_PENDING_ROUTES = MAX_ROWS
INPUT_EVENTS = frozenset(
    {
        "approval.request",
        "clarify.request",
        "secret.request",
        "sudo.request",
        "vault.unlock.request",
        "vault.save_login.request",
    }
)
_HANDLE = re.compile(r"[A-Za-z0-9_-]{43}")
_TOKEN = re.compile(r"[0-9a-f]{32,200}")
_PREVIEW_FIELDS = {
    "version",
    "key_id",
    "key",
    "completion",
    "attention",
    "include_title",
    "include_response_excerpt",
}
_ROW_V3_FIELDS = {
    "device",
    "epoch",
    "status",
    "origin",
    "route",
    "mode",
    "environment",
    "preview",
}


def _push_origin(value):
    origin = canonicalize_relay_origin(value)
    authority = origin.split("://", 1)[1]
    if authority.endswith(":443"):
        authority = authority[:-4]
    return "https://" + authority


def _binding_valid(row):
    origin, route = row["origin"], row["route"]
    if origin is None or route is None:
        return origin is None and route is None and row["status"] == "debt"
    if not isinstance(origin, str) or not isinstance(route, str) or not _HANDLE.fullmatch(route):
        return False
    try:
        canonical_route = canonical_b64url(decode_canonical_b64url(route, 32))
        canonical_origin = _push_origin(origin)
    except (TypeError, ValueError):
        return False
    return canonical_route == route and canonical_origin == origin


def _preview_record_valid(value):
    if not isinstance(value, dict) or set(value) != _PREVIEW_FIELDS:
        return False
    try:
        decode_canonical_b64url(value["key_id"], 16)
        decode_canonical_b64url(value["key"], 32)
    except ValueError:
        return False
    return (
        type(value["version"]) is int
        and value["version"] == 1
        and all(
            type(value[field]) is bool
            for field in (
                "completion",
                "attention",
                "include_title",
                "include_response_excerpt",
            )
        )
    )


def _row_v3_valid(row):
    if not isinstance(row, dict) or set(row) != _ROW_V3_FIELDS:
        return False
    if (
        not isinstance(row["device"], str)
        or not 1 <= len(row["device"]) <= 128
        or type(row["epoch"]) is not int
        or not 0 <= row["epoch"] <= 2**31 - 1
        or not isinstance(row["status"], str)
        or row["status"] not in {"active", "pending", "debt"}
        or not isinstance(row["mode"], str)
        or row["mode"] not in {"generic", "preview"}
        or not isinstance(row["environment"], str)
        or row["environment"] not in {"sandbox", "production"}
        or (row["mode"] == "generic" and row["environment"] != "sandbox")
    ):
        return False
    if row["mode"] == "generic":
        return row["preview"] is None
    if row["status"] == "debt":
        return row["preview"] is None
    return _preview_record_valid(row["preview"])


class PushBridge:
    def __init__(
        self,
        *,
        paths,
        relay_origin,
        installation_id,
        token_provider,
        authorized,
        transport=None,
        timeout=TIMEOUT,
        clock=time.monotonic,
        wall_clock=time.time,
        preview_enabled=False,
    ):
        if not isinstance(installation_id, bytes) or len(installation_id) != 32:
            raise ValueError("invalid installation")
        origin = _push_origin(relay_origin)
        route = canonical_b64url(installation_id)
        self.origin, self.route = origin, route
        self.url = origin + f"/v1/push/{route}"
        self.token_provider = token_provider
        self.authorized = authorized
        self.timeout = timeout
        self.clock = clock
        self.wall_clock = wall_clock
        self.preview_enabled = preview_enabled is True
        paths.ensure()
        self.path = paths.agent_dir / "push.json"
        self.rows = {}
        self.closed = False
        self.failed = False
        self.queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._task = None
        self._http_task = None
        self._http_handle = None
        self._seen = OrderedDict()
        self._generation = {}
        self._registration_lock = asyncio.Lock()
        self.pending_routes = OrderedDict()
        self.arrival_routes = OrderedDict()
        dirty = False
        try:
            data = loads_strict(_read_bounded(self.path, MAX_STATE_BYTES).decode("utf-8"))
        except FileNotFoundError:
            data = {"version": 3, "rows": {}}
        if (
            not isinstance(data, dict)
            or set(data) != {"version", "rows"}
            or type(data["version"]) is not int
            or data["version"] not in {1, 2, 3}
            or not isinstance(data["rows"], dict)
            or len(data["rows"]) > MAX_ROWS
        ):
            raise ValueError("invalid push state")
        version = data["version"]
        for handle, source in data["rows"].items():
            if (
                not isinstance(handle, str)
                or not _HANDLE.fullmatch(handle)
                or not isinstance(source, dict)
            ):
                raise ValueError("invalid push state")
            if version == 1:
                if (
                    set(source) != {"device", "epoch", "active"}
                    or type(source.get("active")) is not bool
                ):
                    raise ValueError("invalid push state")
                row = {
                    "device": source.get("device"),
                    "epoch": source.get("epoch"),
                    "status": "debt",
                    "origin": None,
                    "route": None,
                    "mode": "generic",
                    "environment": "sandbox",
                    "preview": None,
                }
            elif version == 2:
                if (
                    set(source) != {"device", "epoch", "active", "origin", "route"}
                    or type(source.get("active")) is not bool
                ):
                    raise ValueError("invalid push state")
                row = {
                    "device": source.get("device"),
                    "epoch": source.get("epoch"),
                    "status": "active" if source.get("active") is True else "debt",
                    "origin": source.get("origin"),
                    "route": source.get("route"),
                    "mode": "generic",
                    "environment": "sandbox",
                    "preview": None,
                }
            else:
                row = dict(source)
            if not _row_v3_valid(row) or not _binding_valid(row):
                raise ValueError("invalid push state")
            self.rows[handle] = row
            self._generation[handle] = 0
            if row["status"] in {"active", "pending"} and (
                not self._valid_scope(row)
                or (row["mode"] == "preview" and not self.preview_enabled)
                or (row["status"] == "pending" and row["mode"] == "generic")
            ):
                self._make_debt(handle)
                dirty = True
            dirty = dirty or version != 3
        if dirty:
            self._save()
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
        )

    @property
    def available(self):
        return not self.closed and not self.failed

    @property
    def preview_available(self):
        return self.available and self.preview_enabled

    @property
    def capabilities(self):
        value: dict[str, object] = {"push_notifications_v1": True, "push_notifications_v2": True}
        value["push_notification_routes"] = {"version": 1, "inspect_method": "relay.push.inspect"}
        if self.preview_available:
            value["push_previews"] = dict(PREVIEW_CAPABILITY)
        return value

    def _authorized(self, device, epoch):
        try:
            return self.available and self.authorized(device, epoch)
        except Exception:
            return False

    def _valid_scope(self, row):
        return self._bound(row) and self._authorized(row["device"], row["epoch"])

    def _valid(self, handle):
        row = self.rows.get(handle)
        return bool(row and row["status"] == "active" and self._valid_scope(row))

    def _bound(self, row):
        return row["origin"] == self.origin and row["route"] == self.route

    def _save(self):
        try:
            payload = json.dumps(
                {"version": 3, "rows": self.rows},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            if len(payload) > MAX_STATE_BYTES:
                raise ValueError("oversized push state")
            _atomic_write(self.path, payload)
        except Exception:
            self.failed = True
            raise SessionReadsError("push_unavailable") from None

    def _make_debt(self, handle):
        row = self.rows[handle]
        row["status"] = "debt"
        row["preview"] = None
        self._generation[handle] = self._generation.get(handle, 0) + 1
        self._clear_pending(handle)
        self._clear_arrival(handle)

    def start(self):
        if self._task is None and not self.closed:
            self._task = asyncio.create_task(self._run(), name="mercury-push-worker")
            for handle, row in self.rows.items():
                if row["status"] == "debt" and self._bound(row):
                    self._enqueue("unregister", handle, {})

    def _enqueue(self, action, handle, fields, future=None):
        self.start()
        try:
            generation = self._generation.get(handle, 0)
            self.queue.put_nowait((action, handle, fields, future, generation))
            return True
        except asyncio.QueueFull:
            return False

    def _drop_queued(self, handle):
        keep = []
        while not self.queue.empty():
            job = self.queue.get_nowait()
            self.queue.task_done()
            if job[1] == handle:
                job[2].clear()
                future = job[3]
                if future is not None and not future.done():
                    future.set_exception(SessionReadsError("push_unavailable"))
            else:
                keep.append(job)
        for job in keep:
            self.queue.put_nowait(job)

    def _clear_pending(self, handle, event_id=None):
        pending = self.pending_routes.get(handle)
        if pending is not None and (event_id is None or pending["event_id"] == event_id):
            del self.pending_routes[handle]

    def _prune_pending(self):
        now = self.clock()
        for handle, pending in list(self.pending_routes.items()):
            if pending["expires_at"] <= now:
                del self.pending_routes[handle]
        for key, pending in list(self.arrival_routes.items()):
            if pending["expires_at"] <= now:
                del self.arrival_routes[key]

    def _clear_arrival(self, handle, event_id=None):
        for key in list(self.arrival_routes):
            if key[0] == handle and (event_id is None or key[1] == event_id):
                del self.arrival_routes[key]

    def _inspect(self, device, epoch, handle, event_id):
        self._prune_pending()
        row = self.rows.get(handle)
        pending = self.arrival_routes.get((handle, event_id))
        if (not self._authorized(device, epoch) or not self._valid(handle)
                or not row or not pending or row["device"] != device or row["epoch"] != epoch
                or pending["device"] != device or pending["epoch"] != epoch):
            return {"resolved": False}
        # This independent event-indexed read never consumes the tap mapping.
        return {"resolved": True, "durable_session_id": pending["durable_session_id"],
                "profile": pending["profile"]}

    def _resolve(self, device, epoch, handle):
        self._prune_pending()
        if not self._authorized(device, epoch):
            return {"resolved": False}
        row = self.rows.get(handle)
        pending = self.pending_routes.get(handle)
        if (
            not row
            or not pending
            or not self._valid(handle)
            or row["device"] != device
            or row["epoch"] != epoch
            or pending["device"] != device
            or pending["epoch"] != epoch
        ):
            return {"resolved": False}
        del self.pending_routes[handle]
        return {
            "resolved": True,
            "durable_session_id": pending["durable_session_id"],
            "profile": pending["profile"],
        }

    def revoke(self, device, epoch=None):
        handles = []
        for handle, row in list(self.rows.items()):
            if row["device"] != device or (epoch is not None and row["epoch"] != epoch):
                continue
            self._drop_queued(handle)
            self._make_debt(handle)
            handles.append(handle)
            if self._http_handle == handle and self._http_task is not None:
                self._http_task.cancel()
        if handles:
            self._save()
            for handle in handles:
                self._enqueue("unregister", handle, {})

    @staticmethod
    def _validate_token(token):
        return isinstance(token, str) and bool(_TOKEN.fullmatch(token)) and len(token) % 2 == 0

    @staticmethod
    def _parse_preview(value):
        if not _preview_record_valid(value):
            raise SessionReadsError("invalid_params")
        return dict(value)

    def _find_idempotent_preview(self, device, epoch, preview, environment):
        for handle, row in self.rows.items():
            if (
                row["device"] == device
                and row["epoch"] == epoch
                and row["mode"] == "preview"
                and row["status"] in {"active", "pending"}
                and row["preview"]["key_id"] == preview["key_id"]
            ):
                if row["environment"] != environment or row["preview"]["key"] != preview["key"]:
                    raise SessionReadsError("invalid_params")
                # Keep the last known-good preferences until the Worker has
                # accepted the replacement registration.
                return handle
        return None

    async def dispatch(self, device, epoch, method, params):
        if method == "relay.push.inspect":
            if (set(params) != {"wake_handle", "event_id"}
                    or any(not isinstance(params[k], str) or not _HANDLE.fullmatch(params[k])
                           for k in ("wake_handle", "event_id"))):
                raise SessionReadsError("invalid_params")
            return self._inspect(device, epoch, params["wake_handle"], params["event_id"])
        if method == "relay.push.resolve":
            handle = params.get("wake_handle")
            if (
                set(params) != {"wake_handle"}
                or not isinstance(handle, str)
                or not _HANDLE.fullmatch(handle)
            ):
                raise SessionReadsError("invalid_params")
            return self._resolve(device, epoch, handle)
        if not self._authorized(device, epoch):
            raise SessionReadsError("push_unavailable")
        if method == "relay.push.unregister":
            if params:
                raise SessionReadsError("invalid_params")
            self.revoke(device, epoch)
            return {"registered": False}
        if method == "relay.push.preview.register":
            if not self.preview_available:
                raise SessionReadsError("push_unavailable")
            if set(params) != {"device_token", "environment", "preview"}:
                raise SessionReadsError("invalid_params")
            token, environment = params.get("device_token"), params.get("environment")
            if not self._validate_token(token) or environment not in {"sandbox", "production"}:
                raise SessionReadsError("invalid_params")
            preview = self._parse_preview(params.get("preview"))
            mode = "preview"
        elif method == "relay.push.register":
            if set(params) != {"device_token", "environment"}:
                raise SessionReadsError("invalid_params")
            token, environment = params.get("device_token"), params.get("environment")
            if not self._validate_token(token) or environment != "sandbox":
                raise SessionReadsError("invalid_params")
            preview, mode = None, "generic"
        else:
            raise SessionReadsError("invalid_params")

        async with self._registration_lock:
            self.start()
            handle = (
                self._find_idempotent_preview(device, epoch, preview, environment)
                if mode == "preview"
                else None
            )
            if handle is None:
                if self.queue.full() or len(self.rows) >= MAX_ROWS:
                    raise SessionReadsError("rate_limited")
                handle = secrets.token_urlsafe(32)
                self.rows[handle] = {
                    "device": device,
                    "epoch": epoch,
                    "status": "pending",
                    "origin": self.origin,
                    "route": self.route,
                    "mode": mode,
                    "environment": environment,
                    "preview": preview,
                }
                self._generation[handle] = 0
                self._save()
            row = self.rows[handle]
            fields = {"device_token": token, "environment": environment}
            if mode == "preview":
                fields["preview"] = {"version": 1, "key_id": preview["key_id"]}
            future = asyncio.get_running_loop().create_future()
            if not self._enqueue("register", handle, fields, future):
                if row["status"] == "pending":
                    self._make_debt(handle)
                    self._save()
                raise SessionReadsError("rate_limited")
            await future
            if not self._valid(handle):
                raise SessionReadsError("push_unavailable")
            if mode == "preview" and self.rows[handle]["preview"] != preview:
                self.rows[handle]["preview"] = preview
                self._save()
            result = {"registered": True, "wake_handle": handle}
            if mode == "preview":
                result["preview"] = {"version": 1, "key_id": preview["key_id"]}
            return result

    @staticmethod
    def _route_valid(route):
        return bool(
            isinstance(route, dict)
            and set(route) == {"durable_session_id", "profile"}
            and isinstance(route["durable_session_id"], str)
            and 1 <= len(route["durable_session_id"].encode("utf-8")) <= MAX_ROUTE_SESSION_BYTES
            and isinstance(route["profile"], str)
            and 1 <= len(route["profile"].encode("utf-8")) <= MAX_ROUTE_PROFILE_BYTES
            and not any(
                ord(character) < 32 or 127 <= ord(character) <= 159
                for character in route["durable_session_id"] + route["profile"]
            )
        )

    def wake(self, device, epoch, identity, route=None, preview_data=None):
        if not self._authorized(device, epoch):
            return
        handles = [
            h
            for h, r in self.rows.items()
            if r["device"] == device and r["epoch"] == epoch and self._valid(h)
        ]
        if not handles:
            return
        key = (device, epoch, identity)
        if key in self._seen:
            return
        self._seen[key] = None
        if len(self._seen) > 256:
            self._seen.popitem(last=False)
        if not self._route_valid(route):
            route = None
        for handle in handles:
            row = self.rows[handle]
            event_id = secrets.token_urlsafe(32)
            fields = {"event_id": event_id}
            if row["mode"] == "preview":
                if not isinstance(preview_data, dict):
                    continue
                kind = preview_data.get("kind")
                preference = "completion" if kind == "completion" else "attention"
                record = row["preview"]
                if kind not in {"completion", "attention"} or not record[preference]:
                    continue
                try:
                    issued_at = int(self.wall_clock())
                    plaintext = build_preview_plaintext(
                        kind=kind,
                        attention_kind=preview_data.get("attention_kind"),
                        response_text=preview_data.get("response_text"),
                        title=preview_data.get("title"),
                        include_title=record["include_title"],
                        include_response_excerpt=record["include_response_excerpt"],
                        route=route,
                        now=issued_at,
                    )
                    nonce = secrets.token_bytes(12)
                    ciphertext = encrypt_preview(
                        key=decode_canonical_b64url(record["key"], 32),
                        nonce=nonce,
                        plaintext=plaintext,
                        environment=row["environment"],
                        wake_handle=handle,
                        event_id=event_id,
                        key_id=record["key_id"],
                    )
                    fields["preview"] = {
                        "version": 1,
                        "alg": "C20P",
                        "key_id": record["key_id"],
                        "nonce": canonical_b64url(nonce),
                        "ciphertext": ciphertext,
                    }
                    fields["_preview_expires_at"] = issued_at + PREVIEW_TTL_SECONDS
                except (ValueError, TypeError):
                    fields.clear()
                    continue
            if not self._enqueue("wake", handle, fields):
                fields.clear()
                continue
            self._clear_pending(handle)
            if route is not None:
                self.pending_routes[handle] = {
                    "event_id": event_id,
                    "device": device,
                    "epoch": epoch,
                    "durable_session_id": route["durable_session_id"],
                    "profile": route["profile"],
                    "expires_at": self.clock() + PENDING_ROUTE_TTL,
                }
                self.pending_routes.move_to_end(handle)
                self._prune_pending()
                self.arrival_routes[(handle, event_id)] = dict(self.pending_routes[handle])
                while len(self.arrival_routes) > MAX_PENDING_ROUTES:
                    self.arrival_routes.popitem(last=False)
                while len(self.pending_routes) > MAX_PENDING_ROUTES:
                    self.pending_routes.popitem(last=False)

    async def _post(self, action, handle, fields):
        row = self.rows.get(handle)
        if row is None or not self._bound(row):
            raise SessionReadsError("push_unavailable")
        # Keep only ciphertext in the queue. Drop stale previews at the send
        # boundary, reserving the entire HTTP timeout, rather than retaining
        # plaintext for a later rebuild. This metadata must never leave the host.
        expires_at = fields.pop("_preview_expires_at", None)
        if expires_at is not None and self.wall_clock() + self.timeout >= expires_at:
            raise SessionReadsError("push_unavailable")
        payload = json.dumps(
            {"wake_handle": handle, **fields},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_PUSH_BODY_BYTES:
            raise SessionReadsError("push_unavailable")
        async with self._client.stream(
            "POST",
            f"{self.url}/{action}",
            headers={
                "Authorization": "Bearer " + self.token_provider(),
                "Content-Type": "application/json",
            },
            content=payload,
        ) as response:
            if not 200 <= response.status_code < 300:
                raise SessionReadsError("push_unavailable")

    def _retire_others(self, handle):
        current = self.rows[handle]
        retired = []
        for other, row in self.rows.items():
            if other == handle or row["device"] != current["device"]:
                continue
            self._drop_queued(other)
            self._make_debt(other)
            retired.append(other)
            if self._http_handle == other and self._http_task is not None:
                self._http_task.cancel()
        return retired

    async def _run(self):
        while True:
            try:
                action, handle, fields, future, generation = await asyncio.wait_for(
                    self.queue.get(), 60
                )
            except TimeoutError:
                for handle, row in self.rows.items():
                    if row["status"] == "debt" and self._bound(row):
                        self._enqueue("unregister", handle, {})
                continue
            if action == "close":
                self.queue.task_done()
                return
            success = False
            retired = []
            try:
                row = self.rows.get(handle)
                current = row is not None and self._generation.get(handle) == generation
                if action == "unregister":
                    if not current or row["status"] != "debt":
                        continue
                elif action == "register":
                    if (
                        not current
                        or row["status"] not in {"active", "pending"}
                        or not self._valid_scope(row)
                    ):
                        continue
                elif not current or not self._valid(handle):
                    continue
                self._http_handle = handle
                self._http_task = asyncio.create_task(self._post(action, handle, fields))
                try:
                    await asyncio.wait_for(self._http_task, self.timeout)
                    success = True
                except asyncio.CancelledError:
                    # Revocation/shutdown cancels only this HTTP operation; the
                    # serialized worker continues to cleanup or consume close.
                    pass
                except Exception:
                    pass
                if (
                    action == "unregister"
                    and success
                    and self._generation.get(handle) == generation
                ):
                    self.rows.pop(handle, None)
                    self._generation.pop(handle, None)
                    self._save()
                elif action == "register" and self._generation.get(handle) == generation:
                    row = self.rows.get(handle)
                    if success and row is not None and self._valid_scope(row):
                        if row["status"] == "pending":
                            row["status"] = "active"
                            retired = self._retire_others(handle)
                            self._save()
                    elif row is not None and row["status"] == "pending":
                        self._make_debt(handle)
                        self._save()
                        self._enqueue("unregister", handle, {})
            except SessionReadsError:
                success = False
            finally:
                if action == "wake" and not success:
                    self._clear_pending(handle, fields.get("event_id"))
                    self._clear_arrival(handle, fields.get("event_id"))
                self._http_handle = self._http_task = None
                for retired_handle in retired:
                    self._enqueue("unregister", retired_handle, {})
                if future is not None and not future.done():
                    if success and self._valid(handle):
                        future.set_result(None)
                    else:
                        future.set_exception(SessionReadsError("push_unavailable"))
                fields.clear()
                self.queue.task_done()

    async def drain(self):
        self.start()
        await self.queue.join()

    async def close(self):
        self.closed = True
        if self._http_task is not None and not self._http_task.done():
            self._http_task.cancel()
        while not self.queue.empty():
            _, _, fields, future, _ = self.queue.get_nowait()
            fields.clear()
            if future is not None and not future.done():
                future.cancel()
            self.queue.task_done()
        if self._task is not None and not self._task.done():
            self.queue.put_nowait(("close", "", {}, None, 0))
            await asyncio.gather(self._task, return_exceptions=True)
        self.pending_routes.clear()
        self.arrival_routes.clear()
        for row in self.rows.values():
            if row["status"] != "active":
                row["preview"] = None
        await self._client.aclose()


class PushObserver:
    """Observe only live retained controller output, never transcript/replay reads."""

    def __init__(self, bridge, device, epoch, recovery_projection):
        self.bridge, self.device, self.epoch = bridge, device, epoch
        self.recovery_projection = recovery_projection
        self.turns = OrderedDict()
        self.titles = OrderedDict()
        self.serial = 0

    def observe(self, text):
        try:
            value = loads_strict(text)
            if not isinstance(value, dict) or value.get("method") != "event":
                return
            params = value.get("params", {})
            payload = params.get("payload", {})
            if not isinstance(params, dict) or not isinstance(payload, dict):
                return
            if any(
                source.get(flag)
                for source in (params, payload)
                for flag in ("replay", "historical", "interim", "interrupted")
            ):
                return
            sid, kind = params.get("session_id"), params.get("type")
            if not isinstance(sid, str) or not 1 <= len(sid) <= 128:
                return
            if kind == "session.title":
                title = normalize_title(payload.get("title"))
                if title:
                    self.titles[sid] = title
                    self.titles.move_to_end(sid)
                    while len(self.titles) > 64:
                        self.titles.popitem(last=False)
                return
            seq = params.get("seq")
            if kind == "message.start":
                self.serial += 1
                self.turns[sid] = (seq if type(seq) is int else self.serial, False)
                if len(self.turns) > 64:
                    self.turns.popitem(last=False)
                return
            if kind == "message.complete":
                content = payload.get("text")
                if (
                    payload.get("role", "assistant") != "assistant"
                    or payload.get("status", "complete") != "complete"
                    or not isinstance(content, str)
                    or not content.strip()
                    or content.strip().startswith("Operation interrupted:")
                ):
                    return
                turn = self.turns.get(sid)
                if turn:
                    if turn[1]:
                        return
                    self.turns[sid] = (turn[0], True)
                    identity = (sid, kind, "turn", turn[0])
                else:
                    identity = (sid, kind, seq, hashlib.sha256(content.encode()).hexdigest())
                preview_data = {
                    "kind": "completion",
                    "response_text": content,
                    "title": self.titles.get(sid),
                }
            elif kind in INPUT_EVENTS:
                request = payload.get("request_id")
                if (
                    not isinstance(request, str)
                    or not 1 <= len(request) <= 128
                    or payload.get("blocking") is False
                ):
                    return
                identity = (sid, kind, request)
                preview_data = {"kind": "attention", "attention_kind": kind}
            else:
                return
            digest = hashlib.sha256(repr(identity).encode()).digest()
            binding = self.recovery_projection.binding_for_runtime(sid)
            route = (
                {
                    "durable_session_id": binding["durable_session_id"],
                    "profile": binding["profile"],
                }
                if binding
                else None
            )
            # Titles are useful only when the same live runtime has a proven durable route.
            if route is None:
                preview_data.pop("title", None)
            self.bridge.wake(self.device, self.epoch, digest, route, preview_data)
        except (ValueError, TypeError, AttributeError):
            return
