"""Opt-in, content-free push bridge owned by the admission lifecycle.

The single queue serializes registry changes and wakes. Revocation invalidates
locally *before* any await, cancels an in-flight request, and leaves a private
cleanup tombstone on failure. Already accepted HTTP/APNs deliveries cannot be
recalled. No Hermes content, APNs credentials, or device tokens are persisted.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
from collections import OrderedDict

import httpx

from .config import canonicalize_relay_origin
from .session_reads import SessionReadsError
from .state_store import _atomic_write, _read_bounded
from .strict_json import loads_strict

MAX_ROWS = 64
MAX_STATE_BYTES = 128 * 1024
QUEUE_SIZE = 64
TIMEOUT = 5.0
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


def _push_origin(value):
    origin = canonicalize_relay_origin(value)
    authority = origin.split("://", 1)[1]
    if authority.endswith(":443"):
        authority = authority[:-4]
    return "https://" + authority


def _binding_valid(row):
    origin, route = row["origin"], row["route"]
    if origin is None or route is None:
        return origin is None and route is None and not row["active"]
    if not isinstance(route, str) or not _HANDLE.fullmatch(route):
        return False
    canonical_route = base64.urlsafe_b64encode(base64.urlsafe_b64decode(route + "=")).decode()
    return canonical_route.rstrip("=") == route and _push_origin(origin) == origin


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
    ):
        if not isinstance(installation_id, bytes) or len(installation_id) != 32:
            raise ValueError("invalid installation")
        origin = _push_origin(relay_origin)
        route = base64.urlsafe_b64encode(installation_id).decode("ascii").rstrip("=")
        self.origin, self.route = origin, route
        self.url = origin + f"/v1/push/{route}"
        self.token_provider = token_provider
        self.authorized = authorized
        self.timeout = timeout
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
        try:
            data = loads_strict(_read_bounded(self.path, MAX_STATE_BYTES).decode("utf-8"))
        except FileNotFoundError:
            data = {"version": 2, "rows": {}}
        if (
            not isinstance(data, dict)
            or set(data) != {"version", "rows"}
            or type(data["version"]) is not int
            or data["version"] not in {1, 2}
            or not isinstance(data["rows"], dict)
            or len(data["rows"]) > MAX_ROWS
        ):
            raise ValueError("invalid push state")
        legacy = data["version"] == 1
        dirty = legacy
        for handle, row in data["rows"].items():
            if (
                not _HANDLE.fullmatch(handle)
                or not isinstance(row, dict)
                or set(row)
                != (
                    {"device", "epoch", "active"}
                    if legacy
                    else {"device", "epoch", "active", "origin", "route"}
                )
                or not isinstance(row["device"], str)
                or not 1 <= len(row["device"]) <= 128
                or type(row["epoch"]) is not int
                or not 0 <= row["epoch"] <= 2**31 - 1
                or type(row["active"]) is not bool
            ):
                raise ValueError("invalid push state")
            if legacy:
                # There is no evidence of the old destination: never guess it.
                row = {**row, "active": False, "origin": None, "route": None}
            if not _binding_valid(row):
                raise ValueError("invalid push state")
            self.rows[handle] = row
            if row["active"] and not self._valid(handle):
                row["active"] = False
                dirty = True
        if dirty:
            self._save()  # Persist fences even if this lifecycle never starts its worker.
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

    def _authorized(self, device, epoch):
        try:
            return self.available and self.authorized(device, epoch)
        except Exception:
            return False

    def _valid(self, handle):
        row = self.rows.get(handle)
        return bool(
            row
            and self._bound(row)
            and row["active"]
            and self._authorized(row["device"], row["epoch"])
        )

    def _bound(self, row):
        # token_provider is scoped to this lifecycle, not to historical registries.
        return row["origin"] == self.origin and row["route"] == self.route

    def _save(self):
        try:
            _atomic_write(self.path, json.dumps({"version": 2, "rows": self.rows}).encode())
        except Exception:
            self.failed = True
            raise SessionReadsError("push_unavailable") from None

    def start(self):
        if self._task is None and not self.closed:
            # Retry old cleanup debt, and fence registrations from an earlier epoch.
            for handle, row in self.rows.items():
                if not self._valid(handle):
                    row["active"] = False
                    self.queue.put_nowait(("unregister", handle, {}, None))
            self._task = asyncio.create_task(self._run(), name="mercury-push-worker")

    def _enqueue(self, action, handle, fields, future=None):
        self.start()
        try:
            self.queue.put_nowait((action, handle, fields, future))
            return True
        except asyncio.QueueFull:
            return False

    def _drop_queued(self, handle):
        # Discard stale queued tokens/wakes synchronously before revocation returns.
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

    def revoke(self, device, epoch=None):
        """Synchronous local fence; deletion is best effort and never reactivates."""
        dirty = False
        for handle, row in list(self.rows.items()):
            if row["device"] != device or (epoch is not None and row["epoch"] != epoch):
                continue
            row["active"] = False
            self._drop_queued(handle)
            dirty = True
            if self._http_handle == handle and self._http_task is not None:
                self._http_task.cancel()
            self._enqueue("unregister", handle, {})
        if dirty:
            self._save()

    async def dispatch(self, device, epoch, method, params):
        if not self._authorized(device, epoch):
            raise SessionReadsError("push_unavailable")
        if method == "relay.push.unregister":
            if params:
                raise SessionReadsError("invalid_params")
            self.revoke(device, epoch)
            return {"registered": False}
        token = params.get("device_token")
        if (
            method != "relay.push.register"
            or set(params) != {"device_token", "environment"}
            or not isinstance(token, str)
            or not _TOKEN.fullmatch(token)
            or len(token) % 2
            or params["environment"] != "sandbox"
        ):
            raise SessionReadsError("invalid_params")
        self.start()
        if self.queue.full() or len(self.rows) >= MAX_ROWS:
            raise SessionReadsError("rate_limited")
        self.revoke(device)  # also remove any stale-epoch registration
        handle = secrets.token_urlsafe(32)
        self.rows[handle] = {
            "device": device,
            "epoch": epoch,
            "active": True,
            "origin": self.origin,
            "route": self.route,
        }
        self._save()  # a lost response can still be revoked; token is memory-only
        future = asyncio.get_running_loop().create_future()
        if not self._enqueue(
            "register",
            handle,
            {
                "device_token": token,
                "environment": "sandbox",
            },
            future,
        ):
            self.rows[handle]["active"] = False
            self._save()
            raise SessionReadsError("rate_limited")
        await future
        if not self._valid(handle):
            raise SessionReadsError("push_unavailable")
        return {"registered": True, "wake_handle": handle}

    def wake(self, device, epoch, identity):
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
        for handle in handles:
            self._enqueue("wake", handle, {"event_id": secrets.token_urlsafe(32)})

    async def _post(self, action, handle, fields):
        row = self.rows.get(handle)
        if row is None or not self._bound(row):
            # Keep blocked debt. Never mint/replay current credentials for it.
            raise SessionReadsError("push_unavailable")
        # Fresh routing JWT per request, no redirect or unbounded response body.
        async with self._client.stream(
            "POST",
            f"{self.url}/{action}",
            headers={"Authorization": "Bearer " + self.token_provider()},
            json={"wake_handle": handle, **fields},
        ) as response:
            if not 200 <= response.status_code < 300:
                raise SessionReadsError("push_unavailable")

    async def _run(self):
        while True:
            try:
                action, handle, fields, future = await asyncio.wait_for(self.queue.get(), 60)
            except TimeoutError:
                # Bounded cleanup debt retry while idle; no token/content is needed.
                for handle, row in self.rows.items():
                    if not self._valid(handle):
                        row["active"] = False
                        self._enqueue("unregister", handle, {})
                continue
            success = False
            try:
                if action != "unregister" and not self._valid(handle):
                    continue
                self._http_handle = handle
                self._http_task = asyncio.create_task(self._post(action, handle, fields))
                try:
                    await asyncio.wait_for(self._http_task, self.timeout)
                    success = True
                except asyncio.CancelledError:
                    if self.closed:
                        raise
                    # revoke() cancelled just this HTTP operation, not the worker.
                except Exception:
                    pass  # deliberately never log payloads/provider exceptions
                if action == "unregister" and success:
                    self.rows.pop(handle, None)
                    self._save()
                elif action == "register" and not success and handle in self.rows:
                    self.rows[handle]["active"] = False
                    self._save()
                    self._enqueue("unregister", handle, {})
            except SessionReadsError:
                success = False
            finally:
                self._http_handle = self._http_task = None
                if future is not None and not future.done():
                    if success and self._valid(handle):
                        future.set_result(None)
                    else:
                        future.set_exception(SessionReadsError("push_unavailable"))
                fields.clear()  # discard device token promptly
                self.queue.task_done()

    async def drain(self):
        """Deterministic offline-harness barrier; not called by the lease pump."""
        self.start()
        await self.queue.join()

    async def close(self):
        self.closed = True
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        while not self.queue.empty():
            _, _, fields, future = self.queue.get_nowait()
            fields.clear()
            if future is not None and not future.done():
                future.cancel()
            self.queue.task_done()
        await self._client.aclose()


class PushObserver:
    """Observe only live retained controller output, never transcript/replay reads."""

    def __init__(self, bridge, device, epoch):
        self.bridge, self.device, self.epoch = bridge, device, epoch
        self.turns = OrderedDict()
        self.serial = 0

    def observe(self, text):
        try:
            value = loads_strict(text)
            if not isinstance(value, dict) or value.get("method") != "event":
                return
            params = value.get("params", {})
            payload = params.get("payload", {})
            if not isinstance(payload, dict):
                return
            if any(
                p.get(k)
                for p in (params, payload)
                for k in ("replay", "historical", "interim", "interrupted")
            ):
                return
            sid, kind = params.get("session_id"), params.get("type")
            if not isinstance(sid, str) or not 1 <= len(sid) <= 128:
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
            elif kind in INPUT_EVENTS:
                request = payload.get("request_id")
                if (
                    not isinstance(request, str)
                    or not 1 <= len(request) <= 128
                    or payload.get("blocking") is False
                ):
                    return
                identity = (sid, kind, request)
            else:
                return
            # Only an opaque, local dedup digest reaches the bridge, never content.
            digest = hashlib.sha256(repr(identity).encode()).digest()
            self.bridge.wake(self.device, self.epoch, digest)
        except (ValueError, TypeError, AttributeError):
            return
