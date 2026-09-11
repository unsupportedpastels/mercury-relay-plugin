"""Bounded host-owned controller leases surviving outer transport loss.

A :class:`SessionLease` owns one inner Hermes controller for one authorized
device.  The lease pumps every exact Hermes frame out of the controller's
virtual WebSocket, stamps it with a monotonic *lease sequence* (independent of
any Noise nonce sequence), retains it in a bounded ring, and forwards it to at
most one live encrypted attachment.  When the outer mobile or hosted transport
detaches, the controller and any running turn stay alive until a bounded
detach TTL, a retention cap, a revoke, a terminal inner close, or plugin
shutdown releases the lease — exactly once.

Repeated logical ``prompt.submit`` requests carrying the same
``submission_id`` return the original acceptance outcome and are never
dispatched to Hermes twice, so an outer reconnect can retry safely without
replaying mutations.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .lease_recovery import RecoveryProjection
from .session_reads import (
    RELAY_LOCAL_METHODS,
    RELAY_MUTATION_METHODS,
    SessionReadsError,
)
from .strict_json import StrictJsonError, loads_strict
from .virtual_ws import VirtualWebSocketClosed, VirtualWebSocketError

MAX_SUBMISSION_ID_TEXT = 128
MAX_CURSOR = 2**63 - 1
MAX_READS_IN_FLIGHT = 8
MAX_LOCAL_MUTATIONS = 8
MAX_LOCAL_REQUEST_ID_BYTES = 128


def _valid_local_request_id(request_id: Any) -> bool:
    """Whether a local JSON-RPC response can safely echo *request_id*."""

    try:
        return (
            1 <= len(request_id.encode("utf-8")) <= MAX_LOCAL_REQUEST_ID_BYTES
            if isinstance(request_id, str)
            else -(2**63) <= request_id < 2**63
        )
    except (TypeError, UnicodeError):
        return False


class SessionLeaseError(RuntimeError):
    """One stable lease failure without peer-controlled detail."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class LeaseReleased(SessionLeaseError):
    """The lease has been released; the inner controller is gone."""

    def __init__(self) -> None:
        super().__init__("lease_released")


class LeaseAttachRejected(SessionLeaseError):
    """An attachment request cannot be satisfied."""


@dataclass(frozen=True, slots=True)
class LeaseLimits:
    """Bounded retention and dedup limits for one lease."""

    max_events: int = 256
    max_event_bytes: int = 4_194_304
    max_event_age_seconds: float = 600.0
    detach_ttl_seconds: float = 300.0
    max_tracked_submissions: int = 64

    def validate(self) -> LeaseLimits:
        if (
            self.max_events < 1
            or self.max_event_bytes < 1
            or self.max_event_age_seconds <= 0
            or self.detach_ttl_seconds <= 0
            or self.max_tracked_submissions < 1
        ):
            raise ValueError("lease limits must be positive")
        return self


@dataclass(frozen=True, slots=True)
class RetainedEvent:
    lease_seq: int
    text: str
    size: int
    stored_at: float


class LeaseAttachment:
    """At most one live outer consumer of a lease's retained event stream."""

    def __init__(
        self,
        lease: SessionLease,
        replay: list[RetainedEvent],
        *,
        gap: bool,
        preamble: str | None = None,
        recovery: bool = False,
    ) -> None:
        self._lease = lease
        self._replay: deque[RetainedEvent] = deque(replay)
        self.replay_gap = gap
        # Ordered attach-status control frame (PROTOCOL §9): delivered before
        # any replayed or live event so the device knows whether the replay
        # is contiguous or gapped. It is relay transport control, not a
        # Hermes event, and never advances the device's resume_cursor.
        self._preamble = preamble
        self.recovery = recovery
        self._replay_complete = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "relay.lease.replay_complete",
                    "params": {"lease_id": lease.lease_id, "last_seq": lease.last_seq},
                }
            )
            if recovery
            else None
        )
        self._live: deque[str] = deque()
        self._live_bytes = 0
        self._wakeup = asyncio.Event()
        self.detached = False
        self.detach_reason: str | None = None

    @property
    def lease(self) -> SessionLease:
        return self._lease

    def _deliver(self, text: str, size: int) -> None:
        limits = self._lease.limits
        if len(self._live) >= limits.max_events or self._live_bytes + size > limits.max_event_bytes:
            self._lease.detach(self, reason="attachment_backpressure")
            return
        self._live.append(text)
        self._live_bytes += size
        self._wakeup.set()

    def _mark_detached(self, reason: str) -> None:
        # An invalidated controller must not drain queued private replay/snapshots.
        if reason in {"lease_released", "attachment_replaced"}:
            self._preamble = None
            self._replay_complete = None
            self._replay.clear()
            self._live.clear()
            self._live_bytes = 0
        if not self.detached:
            self.detached = True
            self.detach_reason = reason
            self._wakeup.set()

    async def feed_text(self, text: str) -> None:
        """Submit one exact decrypted Hermes request through lease dedup."""

        if self.detached:
            raise SessionLeaseError("attachment_detached")
        await self._lease.submit_text(self, text)

    async def next_text(self, *, timeout: float | None = None) -> str:
        """Return the next replayed or live exact Hermes frame in order."""

        if timeout is not None:
            return await asyncio.wait_for(self.next_text(), timeout=timeout)
        while True:
            if self._lease.released:
                raise LeaseReleased
            if self._preamble is not None:
                text, self._preamble = self._preamble, None
                return text
            if self._replay:
                event = self._replay.popleft()
                return self._lease.frame_text(event, replay=True) if self.recovery else event.text
            if self._replay_complete is not None:
                text, self._replay_complete = self._replay_complete, None
                return text
            if self._live:
                text = self._live.popleft()
                self._live_bytes -= len(text.encode("utf-8"))
                return text
            if self.detached:
                if self.detach_reason == "lease_released":
                    raise LeaseReleased
                raise SessionLeaseError(self.detach_reason or "attachment_detached")
            self._wakeup.clear()
            await self._wakeup.wait()

    def detach(self, *, reason: str = "detached") -> None:
        """Sever only this outer attachment; the lease and controller survive."""

        self._lease.detach(self, reason=reason)


class _SubmissionRecord:
    __slots__ = ("request_id", "outcome", "waiters")

    def __init__(self, request_id: Any) -> None:
        self.request_id = request_id
        self.outcome: dict[str, Any] | None = None
        self.waiters: list[Any] = []


class _LocalMutationRecord:
    __slots__ = ("payload_fingerprint", "outcome", "waiters")

    def __init__(self, payload_fingerprint: str) -> None:
        self.payload_fingerprint = payload_fingerprint
        self.outcome: dict[str, Any] | None = None
        self.waiters: list[Any] = []


class SessionLease:
    """Own one inner Hermes controller across outer transport loss."""

    def __init__(
        self,
        *,
        device_id: str,
        profile: str,
        controller_id: str,
        channel: str = "",
        websocket: Any,
        close_controller: Callable[[str], Awaitable[bool]],
        limits: LeaseLimits | None = None,
        clock: Callable[[], float] | None = None,
        read_dispatcher: Callable[[str, Mapping[str, Any]], Awaitable[dict[str, Any]]]
        | None = None,
        on_release: Callable[[], None] | None = None,
        recovery_projection: RecoveryProjection | None = None,
        authorization_epoch: int | None = None,
        routing_token_provider: Callable[[], str | None] | None = None,
        push_bridge=None,
    ) -> None:
        if not isinstance(device_id, str) or not 1 <= len(device_id) <= 128:
            raise ValueError("invalid device identifier")
        if not isinstance(profile, str) or not profile:
            raise ValueError("invalid profile")
        if not callable(close_controller):
            raise TypeError("close_controller must be callable")
        if read_dispatcher is not None and not callable(read_dispatcher):
            raise TypeError("read_dispatcher must be callable")
        if on_release is not None and not callable(on_release):
            raise TypeError("on_release must be callable")
        if not isinstance(channel, str) or len(channel) > 64:
            raise ValueError("invalid lease channel")
        self._push_bridge = push_bridge
        self.device_id = device_id
        # One device may hold one lease per channel (one per open session);
        # "" is the legacy default channel.
        self.channel = channel
        # Mints a fresh routing-admission token for the attached device. The
        # attach preamble carries it over the authenticated channel so a
        # device's router credential is renewed on every successful attach
        # and never expires while the device keeps connecting.
        self._routing_token_provider = routing_token_provider
        self.profile = profile
        self.controller_id = controller_id
        self._lease_id = secrets.token_hex(16)
        self.authorization_epoch = authorization_epoch
        self.recovery_projection = recovery_projection or RecoveryProjection(profile)
        self._push_observer = None
        if push_bridge is not None:
            from .push import PushObserver

            self._push_observer = PushObserver(
                push_bridge, device_id, authorization_epoch, self.recovery_projection
            )
        self._recovery_enabled = False
        self.websocket = websocket
        self.limits = (limits or LeaseLimits()).validate()
        self._clock = clock or time.monotonic
        self._close_controller = close_controller
        self._ring: deque[RetainedEvent] = deque()
        self._ring_bytes = 0
        self.last_seq = 0
        self.trimmed_through = 0
        self._attachment: LeaseAttachment | None = None
        self._submissions: OrderedDict[str, _SubmissionRecord] = OrderedDict()
        self._mutations: OrderedDict[str, _LocalMutationRecord] = OrderedDict()
        self._read_dispatcher = read_dispatcher
        self._on_release = on_release
        self._read_tasks: set[asyncio.Task[None]] = set()
        self.released = False
        self.release_reason: str | None = None
        self._release_started = False
        self._release_done = asyncio.Event()
        self._pump_task: asyncio.Task[None] | None = None
        self._expiry_task: asyncio.Task[None] | None = None

    # -- lifecycle -----------------------------------------------------------

    @property
    def lease_id(self) -> str:
        return self._lease_id

    def start(self) -> None:
        """Start pumping controller output; must run inside the event loop."""

        if self.released or self._pump_task is not None:
            return
        self._pump_task = asyncio.create_task(self._pump(), name="mercury-session-lease-pump")
        self._schedule_expiry()

    async def _pump(self) -> None:
        try:
            while True:
                text = await self.websocket.next_text()
                self._retain(text)
        except asyncio.CancelledError:
            raise
        except VirtualWebSocketClosed:
            # release() skips cancelling the task it runs inside, so the pump
            # completes the full release inline before it finishes.
            await self.release("controller_closed")
        except Exception:
            await self.release("controller_failed")

    def _schedule_expiry(self) -> None:
        self._cancel_expiry()
        if self.released or self._attachment is not None:
            return

        async def expire() -> None:
            await asyncio.sleep(self.limits.detach_ttl_seconds)
            await self.release("expired")

        self._expiry_task = asyncio.create_task(expire(), name="mercury-session-lease-expiry")

    def _cancel_expiry(self) -> None:
        task, self._expiry_task = self._expiry_task, None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()

    async def release(self, reason: str = "released") -> bool:
        """Release the inner controller exactly once; later calls are no-ops."""

        if self._release_started:
            await self._release_done.wait()
            return False
        self._release_started = True
        self.released = True
        self.release_reason = reason
        try:
            self._cancel_expiry()
            attachment, self._attachment = self._attachment, None
            if attachment is not None:
                attachment._mark_detached("lease_released")
            pump = self._pump_task
            if pump is not None and pump is not asyncio.current_task() and not pump.done():
                pump.cancel()
                await asyncio.gather(pump, return_exceptions=True)
            reads = [task for task in self._read_tasks if not task.done()]
            for task in reads:
                task.cancel()
            if reads:
                await asyncio.gather(*reads, return_exceptions=True)
            self._read_tasks.clear()
            self._ring.clear()
            self._ring_bytes = 0
            self._submissions.clear()
            with contextlib.suppress(Exception):
                await self.websocket.close(code=1000, reason="lease_released")
            cleanup = asyncio.ensure_future(self._close_controller(self.controller_id))
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await asyncio.gather(cleanup, return_exceptions=True)
                raise
            except Exception:
                raise SessionLeaseError("controller_release_failed") from None
            return True
        finally:
            if self._on_release is not None:
                with contextlib.suppress(Exception):
                    self._on_release()
            self._release_done.set()

    # -- retention -----------------------------------------------------------

    def _retain(self, text: str) -> None:
        self.last_seq += 1
        size = len(text.encode("utf-8"))
        now = self._clock()
        self._record_outcome(text)
        self.recovery_projection.observe(text)
        if self._push_observer is not None:
            with contextlib.suppress(Exception):
                self._push_observer.observe(text)
        self._ring.append(
            RetainedEvent(lease_seq=self.last_seq, text=text, size=size, stored_at=now)
        )
        self._ring_bytes += size
        overflow = self._trim(now)
        if overflow and self._attachment is None and not self._recovery_enabled:
            # Retention can no longer prove contiguous replay to an absent
            # device; fail closed and let durable transcript reconcile.
            asyncio.ensure_future(self.release("retention_cap"))
            return
        if self._attachment is not None:
            if self._attachment.recovery:
                text = self.frame_text(RetainedEvent(self.last_seq, text, size, now), replay=False)
                size = len(text.encode("utf-8"))
            self._attachment._deliver(text, size)

    def frame_text(self, event: RetainedEvent, *, replay: bool) -> str:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "relay.lease.frame",
                "params": {
                    "lease_id": self.lease_id,
                    "seq": event.lease_seq,
                    "replay": replay,
                    "frame": event.text,
                },
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _trim(self, now: float) -> bool:
        overflow = False
        while self._ring and (
            len(self._ring) > self.limits.max_events
            or self._ring_bytes > self.limits.max_event_bytes
            or now - self._ring[0].stored_at > self.limits.max_event_age_seconds
        ):
            dropped = self._ring.popleft()
            self._ring_bytes -= dropped.size
            self.trimmed_through = dropped.lease_seq
            if (
                len(self._ring) + 1 > self.limits.max_events
                or self._ring_bytes + dropped.size > self.limits.max_event_bytes
            ):
                overflow = True
        return overflow

    # -- attachment ----------------------------------------------------------

    def attach(
        self,
        cursor: int = 0,
        *,
        recovery: bool = False,
        recovery_reset: bool = False,
        replace_attached: bool = False,
    ) -> LeaseAttachment:
        """Attach one outer consumer, replaying retained events after *cursor*."""

        if self.released:
            raise LeaseReleased
        if isinstance(cursor, bool) or not isinstance(cursor, int) or not 0 <= cursor <= MAX_CURSOR:
            raise LeaseAttachRejected("invalid_cursor")
        if cursor > self.last_seq:
            raise LeaseAttachRejected("cursor_ahead")
        if self._attachment is not None and not (recovery and replace_attached):
            raise LeaseAttachRejected("already_attached")
        self._trim(self._clock())
        replay = [event for event in self._ring if event.lease_seq > cursor]
        gap = cursor < self.trimmed_through
        # BR-03: the gap must be observable on the wire, not just recorded
        # host-side. The attach-status control is the first ordered frame the
        # device receives; on a gap it reconciles from durable transcript
        # reads instead of trusting the replayed suffix.
        relay_token = None
        if self._routing_token_provider is not None:
            try:
                relay_token = self._routing_token_provider()
            except Exception:
                relay_token = None
        preamble = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "relay.lease.attached",
                "params": {
                    **({"relay_token": relay_token} if relay_token else {}),
                    **(
                        {
                            "capabilities": {
                                "push_notifications_v1": True,
                                "push_notifications_v2": True,
                            }
                        }
                        if self._push_bridge is not None and self._push_bridge.available
                        else {}
                    ),
                    "last_seq": self.last_seq,
                    "replay_gap": gap,
                    "replayed_from": replay[0].lease_seq if replay else None,
                    "resume_cursor": cursor,
                    **(
                        {
                            "recovery_version": 1,
                            "lease_id": self.lease_id,
                            "recovery_reset": recovery_reset,
                            "snapshot_through": self.last_seq,
                            **self.recovery_projection.snapshot(),
                        }
                        if recovery
                        else {}
                    ),
                },
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        attachment = LeaseAttachment(self, replay, gap=gap, preamble=preamble, recovery=recovery)
        # Admission alone grants replacement after fresh same-device/epoch/profile
        # authorization and explicit cursor validation. No await between candidate
        # construction, invalidation, and publication: the inner owner never detaches.
        # Late old-transport cleanup is fenced by detach()'s attachment identity.
        if self._attachment is not None:
            self._attachment._mark_detached("attachment_replaced")
        self._recovery_enabled = self._recovery_enabled or recovery
        self._attachment = attachment
        self._cancel_expiry()
        return attachment

    def detach(self, attachment: LeaseAttachment, *, reason: str = "detached") -> None:
        """Detach one outer consumer; the lease keeps the controller running."""

        if self._attachment is attachment:
            self._attachment = None
            self._schedule_expiry()
        attachment._mark_detached(reason)

    # -- inbound dedup -------------------------------------------------------

    async def submit_text(self, attachment: LeaseAttachment, text: str) -> None:
        if self.released:
            raise LeaseReleased
        if self._attachment is not attachment:
            raise SessionLeaseError("attachment_detached")
        try:
            value: Any = loads_strict(text)
        except StrictJsonError:
            # The method policy on the virtual WebSocket is the authority for
            # rejecting malformed requests; pass bytes through unchanged.
            value = None
        if (
            isinstance(value, Mapping)
            and value.get("method") in RELAY_LOCAL_METHODS
            and self._read_dispatcher is not None
        ):
            if value.get("method") in RELAY_MUTATION_METHODS:
                self._start_mutation(value, attachment)
            else:
                self._start_read(value, attachment)
            return
        submission = self._parse_submission(value)
        if submission is None:
            await self.websocket.feed_text(text)
            self.recovery_projection.request(value)
            return
        submission_id, request_id = submission
        record = self._submissions.get(submission_id)
        if record is None:
            if len(self._submissions) >= self.limits.max_tracked_submissions:
                evicted = False
                for key in list(self._submissions):
                    if self._submissions[key].outcome is not None:
                        del self._submissions[key]
                        evicted = True
                        break
                if not evicted:
                    raise SessionLeaseError("submission_tracking_exhausted")
            self._submissions[submission_id] = _SubmissionRecord(request_id)
            try:
                await self.websocket.feed_text(text)
            except VirtualWebSocketError:
                self._submissions.pop(submission_id, None)
                raise
            return
        if record.outcome is not None:
            self._deliver_outcome(record.outcome, request_id, attachment)
            return
        # The original submission is still in flight; answer this duplicate
        # with the original outcome once it exists, never resubmitting.
        if len(record.waiters) < 8 and (request_id, attachment) not in record.waiters:
            record.waiters.append((request_id, attachment))

    def _start_read(self, request: Mapping[str, Any], attachment: LeaseAttachment) -> None:
        """Serve one bounded read without retaining it or reaching Hermes."""

        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params", {})
        if (
            request.get("jsonrpc") != "2.0"
            or not set(request) <= {"jsonrpc", "id", "method", "params"}
            or request_id is None
            or isinstance(request_id, bool)
            or not isinstance(request_id, (str, int))
            or (isinstance(request_id, str) and not request_id)
            or not isinstance(params, Mapping)
        ):
            raise SessionLeaseError("invalid_read_request")
        dispatcher = self._read_dispatcher
        if not _valid_local_request_id(request_id):
            raise SessionLeaseError("invalid_read_request")
        assert dispatcher is not None
        live = sum(1 for task in self._read_tasks if not task.done())
        if live >= MAX_READS_IN_FLIGHT:
            self._deliver_local(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": "rate_limited"},
                },
                attachment,
            )
            return

        async def run() -> None:
            try:
                result = await dispatcher(str(method), dict(params))
                response: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "result": result}
            except asyncio.CancelledError:
                raise
            except SessionReadsError as error:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": error.reason},
                }
            except Exception:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": "read_failed"},
                }
            self._deliver_local(response, attachment)

        task = asyncio.create_task(run(), name="mercury-session-lease-read")
        self._read_tasks.add(task)
        task.add_done_callback(self._read_tasks.discard)

    def _start_mutation(self, request: Mapping[str, Any], attachment: LeaseAttachment) -> None:
        """Run one Mercury-owned mutation with retained semantic deduplication.

        A request id is the retry identity. Clients namespace ids per socket,
        so a new connection gets a new identity even when it restarts numeric
        ids. The payload fingerprint fences accidental reuse of one id for a
        different mutation. This is intentionally separate from the Hermes
        ``prompt.submit`` ledger: folder creation is local to the relay and
        must never enter the inner Hermes controller.
        """

        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params", {})
        if (
            request.get("jsonrpc") != "2.0"
            or not set(request) <= {"jsonrpc", "id", "method", "params"}
            or request_id is None
            or isinstance(request_id, bool)
            or not isinstance(request_id, (str, int))
            or (isinstance(request_id, str) and not request_id)
            or not isinstance(method, str)
            or method not in RELAY_MUTATION_METHODS
            or not isinstance(params, Mapping)
        ):
            raise SessionLeaseError("invalid_read_request")
        try:
            bounded_id = _valid_local_request_id(request_id)
            payload_fingerprint = hashlib.sha256(
                json.dumps(
                    {"method": method, "params": dict(params)},
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
            request_identity = hashlib.sha256(
                json.dumps(
                    {"method": method, "id": request_id},
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()
        except (TypeError, UnicodeError, ValueError, RecursionError):
            bounded_id = False
            payload_fingerprint = ""
            request_identity = ""
        if not bounded_id:
            raise SessionLeaseError("invalid_read_request")

        record = self._mutations.get(request_identity)
        if record is not None:
            self._mutations.move_to_end(request_identity)
            if record.payload_fingerprint != payload_fingerprint:
                self._deliver_local(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32000, "message": "invalid_params"},
                    },
                    attachment,
                )
            elif record.outcome is not None:
                self._deliver_outcome(record.outcome, request_id, attachment)
            elif (request_id, attachment) not in record.waiters:
                # A lease has one current attachment. Keep only its waiter;
                # repeated outer reconnects must not retain detached sockets
                # while a slow filesystem mutation is still in flight.
                record.waiters[:] = [(request_id, attachment)]
            return

        if len(self._mutations) >= min(self.limits.max_tracked_submissions, MAX_LOCAL_MUTATIONS):
            evicted = False
            for key, candidate in list(self._mutations.items()):
                if candidate.outcome is not None:
                    del self._mutations[key]
                    evicted = True
                    break
            if not evicted:
                self._deliver_local(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32000, "message": "rate_limited"},
                    },
                    attachment,
                )
                return

        record = _LocalMutationRecord(payload_fingerprint)
        record.waiters.append((request_id, attachment))
        self._mutations[request_identity] = record
        dispatcher = self._read_dispatcher
        assert dispatcher is not None

        async def run() -> None:
            try:
                result = await dispatcher(method, dict(params))
                outcome: dict[str, Any] = {"result": result}
            except asyncio.CancelledError:
                raise
            except SessionReadsError as error:
                outcome = {
                    "error": {"code": -32000, "message": error.reason},
                }
            except Exception:
                outcome = {
                    "error": {"code": -32000, "message": "read_failed"},
                }
            if self.released:
                return
            record.outcome = outcome
            waiters, record.waiters = record.waiters, []
            for waiter, waiter_attachment in waiters:
                self._deliver_outcome(outcome, waiter, waiter_attachment)
            if "error" in outcome and self._mutations.get(request_identity) is record:
                # A new namespaced request must be able to retry a transient
                # host failure instead of inheriting a stale error forever.
                del self._mutations[request_identity]

        task = asyncio.create_task(run(), name="mercury-session-lease-mutation")
        self._read_tasks.add(task)
        task.add_done_callback(self._read_tasks.discard)

    def _deliver_local(self, response: Mapping[str, Any], attachment: LeaseAttachment) -> None:
        """Deliver one synthesized response to the current attachment only.

        Read and dedup responses are deterministic and retryable; they are
        never retained in the ring or forwarded to Hermes.
        """

        if self.released or self._attachment is not attachment or attachment.detached:
            return
        text = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
        attachment._deliver(text, len(text.encode("utf-8")))

    def _parse_submission(self, value: Any) -> tuple[str, Any] | None:
        if not isinstance(value, Mapping) or value.get("method") != "prompt.submit":
            return None
        params = value.get("params")
        if not isinstance(params, Mapping) or "submission_id" not in params:
            return None
        submission_id = params["submission_id"]
        request_id = value.get("id")
        if (
            not isinstance(submission_id, str)
            or not 1 <= len(submission_id) <= MAX_SUBMISSION_ID_TEXT
        ):
            raise SessionLeaseError("invalid_submission_id")
        return submission_id, request_id

    def _record_outcome(self, text: str) -> None:
        if not self._submissions:
            return
        try:
            value = loads_strict(text)
        except StrictJsonError:
            return
        if not isinstance(value, Mapping) or "method" in value:
            return
        response_id = value.get("id")
        if response_id is None:
            return
        for record in self._submissions.values():
            if record.outcome is None and record.request_id == response_id:
                outcome: dict[str, Any] = {}
                if "result" in value:
                    outcome["result"] = value["result"]
                elif "error" in value:
                    outcome["error"] = value["error"]
                else:
                    return
                record.outcome = outcome
                waiters, record.waiters = record.waiters, []
                for waiter, attachment in waiters:
                    self._deliver_outcome(outcome, waiter, attachment)
                return

    def _deliver_outcome(
        self, outcome: Mapping[str, Any], request_id: Any, attachment: LeaseAttachment
    ) -> None:
        response: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
        response.update(outcome)
        self._deliver_local(response, attachment)


class SessionLeaseManager:
    """Installation-scoped registry: at most one lease per (device, channel).

    A device with no channel (legacy clients) still gets exactly one lease.
    Devices that name channels hold one lease per channel, so one phone can
    keep several Hermes sessions open, bounded by ``max_leases`` overall.
    """

    def __init__(self, *, max_leases: int = 8) -> None:
        if isinstance(max_leases, bool) or not isinstance(max_leases, int) or max_leases < 1:
            raise ValueError("max_leases must be a positive integer")
        self.max_leases = max_leases
        self._leases: dict[tuple[str, str], SessionLease] = {}
        self.closed = False

    @property
    def active_count(self) -> int:
        return sum(1 for lease in self._leases.values() if not lease.released)

    def get(self, device_id: str, channel: str = "") -> SessionLease | None:
        key = (device_id, channel)
        lease = self._leases.get(key)
        if lease is not None and lease.released:
            del self._leases[key]
            return None
        return lease

    def leases_for(self, device_id: str) -> list[SessionLease]:
        """Every live lease the device holds, across channels."""

        return [
            lease
            for (owner, _channel), lease in list(self._leases.items())
            if owner == device_id and not lease.released
        ]

    def register(self, lease: SessionLease) -> None:
        if self.closed:
            raise SessionLeaseError("manager_closed")
        if not isinstance(lease, SessionLease):
            raise TypeError("lease must be a SessionLease")
        if self.get(lease.device_id, lease.channel) is not None:
            raise SessionLeaseError("device_already_leased")
        self._leases = {key: item for key, item in self._leases.items() if not item.released}
        if len(self._leases) >= self.max_leases:
            raise SessionLeaseError("lease_limit_reached")
        self._leases[(lease.device_id, lease.channel)] = lease
        lease.start()

    async def release_lease(
        self, device_id: str, channel: str = "", *, reason: str = "released"
    ) -> bool:
        """Release exactly one (device, channel) lease."""

        lease = self._leases.pop((device_id, channel), None)
        if lease is None:
            return False
        return await lease.release(reason)

    async def release_device(self, device_id: str, *, reason: str = "released") -> bool:
        """Release every lease the device holds (revocation, epoch change)."""

        keys = [key for key in self._leases if key[0] == device_id]
        released = False
        failure: SessionLeaseError | None = None
        for key in keys:
            lease = self._leases.pop(key, None)
            if lease is None:
                continue
            try:
                released = await lease.release(reason) or released
            except SessionLeaseError as error:
                failure = error
        if failure is not None:
            raise failure
        return released

    async def close(self) -> None:
        """Release every lease exactly once at plugin shutdown."""

        self.closed = True
        leases = list(self._leases.values())
        self._leases.clear()
        for lease in leases:
            with contextlib.suppress(SessionLeaseError):
                await lease.release("plugin_shutdown")


__all__ = [
    "LeaseAttachRejected",
    "LeaseAttachment",
    "LeaseLimits",
    "LeaseReleased",
    "RetainedEvent",
    "SessionLease",
    "SessionLeaseError",
    "SessionLeaseManager",
]
