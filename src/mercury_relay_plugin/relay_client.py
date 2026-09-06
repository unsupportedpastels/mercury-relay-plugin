"""Outbound hosted-relay connector over the opaque Cloudflare router.

One persistent outbound WebSocket carries this installation's host role
(PROTOCOL §6): binary frames are Noise ciphertext relayed verbatim, and the
router's two text control frames — ``{"t":"open"}`` and ``{"t":"close"}`` —
mark device logical-connection boundaries. Each boundary becomes one
:class:`OuterConnection` handed to the existing
:class:`~.connector.RelayConnectorService` session loops, so nothing above
this module changes between the in-memory fake and the hosted path.

The socket reconnects forever with capped exponential backoff and full
jitter. Everything is bounded: frame size, per-connection inbound queue,
control-frame size. Any router protocol violation drops the socket and
reconnects fresh; no detail is logged.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import random
import time
from collections.abc import Callable
from typing import Any

from .config import ProfileConfigError, canonicalize_relay_origin
from .connection_journal import ConnectionJournal, exception_category, upgrade_refused_status
from .connector import ConnectorClosed
from .identity import _b64url_encode
from .secure_channel import MAX_CIPHERTEXT_RECORD_BYTES
from .strict_json import StrictJsonError, loads_strict

CONTROL_OPEN = '{"t":"open"}'
CONTROL_CLOSE = '{"t":"close"}'
MAX_CONTROL_FRAME_BYTES = 64
# Mux protocol (host leg only): every binary frame is prefixed with the
# router-assigned 8-byte connection id, and control frames carry the id as
# 16 lowercase hex characters. Device legs stay raw ciphertext.
CONNECTION_ID_BYTES = 8
INBOUND_QUEUE_LIMIT = 64
ACCEPT_QUEUE_LIMIT = 8
DEFAULT_INITIAL_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_BACKOFF_SECONDS = 60.0


def _token_generation(token: str) -> int | None:
    """Read the Worker-correlated ``iat`` without retaining token material."""

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        claims = json.loads(raw.decode("ascii"))
        generation = claims.get("iat") if isinstance(claims, dict) else None
        if isinstance(generation, bool) or not isinstance(generation, int):
            return None
        return generation if 0 <= generation <= 2**31 - 1 else None
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return None


def _close_code(value: Any) -> int | None:
    """Extract only the numeric WebSocket close code, never its reason text."""

    try:
        candidate = getattr(value, "code", value)
        if isinstance(candidate, bool) or not isinstance(candidate, int):
            return None
        return candidate if 0 <= candidate <= 65_535 else None
    except Exception:
        return None


class RelayClientError(RuntimeError):
    """One stable relay-client failure without transport detail."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def host_socket_url(relay_origin: str, installation_id: bytes) -> str:
    """Build the opaque host-role WebSocket URL for this installation.

    ``?mux=1`` opts into the router's multi-device protocol: concurrent
    device sockets, id-tagged control frames, and id-prefixed binary frames
    on this host socket."""

    # Re-validate at connection time: only a canonical https/wss origin with
    # no userinfo, path, query, or fragment may become the outbound target.
    try:
        canonical = canonicalize_relay_origin(relay_origin)
    except ProfileConfigError:
        raise RelayClientError("invalid_relay_origin") from None
    if not isinstance(installation_id, bytes) or len(installation_id) != 32:
        raise RelayClientError("invalid_installation_id")
    origin = "wss://" + canonical.split("://", 1)[1]
    return f"{origin}/v1/host/{_b64url_encode(installation_id)}?mux=1"


class HostedDeviceConnection:
    """One device logical connection carried over the shared host socket."""

    def __init__(self, client: CloudflareRelayConnector, connection_id: bytes) -> None:
        self._client = client
        self.connection_id = bytes(connection_id)
        self._inbound: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=INBOUND_QUEUE_LIMIT)
        self.closed = False

    def _feed(self, data: bytes | None) -> bool:
        """Queue one inbound frame; False means the bounded queue overflowed."""

        if self.closed and data is not None:
            return True
        try:
            self._inbound.put_nowait(data)
            return True
        except asyncio.QueueFull:
            return False

    def _mark_closed(self) -> None:
        if not self.closed:
            self.closed = True
            with contextlib.suppress(asyncio.QueueFull):
                self._inbound.put_nowait(None)

    async def receive(self) -> bytes | None:
        if self.closed and self._inbound.empty():
            return None
        data = await self._inbound.get()
        if data is None:
            self.closed = True
        return data

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionError("connection closed")
        await self._client._send_binary(self, bytes(data))

    async def close(self) -> None:
        """Host-side close: tell the router to end the device connection."""

        if self.closed:
            return
        self._mark_closed()
        await self._client._close_device(self)


class CloudflareRelayConnector:
    """Own the persistent outbound host socket and its reconnect loop."""

    def __init__(
        self,
        *,
        relay_origin: str,
        installation_id: bytes,
        ws_connect: Callable[[str, dict[str, str]], Any] | None = None,
        token_provider: Callable[[], str] | None = None,
        initial_backoff: float = DEFAULT_INITIAL_BACKOFF_SECONDS,
        max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
        rng: Callable[[], float] | None = None,
        journal: ConnectionJournal | None = None,
    ) -> None:
        if initial_backoff <= 0 or max_backoff < initial_backoff:
            raise ValueError("invalid backoff bounds")
        self.url = host_socket_url(relay_origin, installation_id)
        self._ws_connect = ws_connect or _default_ws_connect
        # Routing admission (MR-01): a fresh short-lived host token is minted
        # for every connect attempt and travels only in the upgrade header.
        self._token_provider = token_provider
        self._initial_backoff = float(initial_backoff)
        self._max_backoff = float(max_backoff)
        self._rng = rng or random.random
        self.journal = journal
        self._attempt_number = 0
        self._last_protocol_generation: int | None = None
        self._host_generation: int | None = None
        self._accepted: asyncio.Queue[HostedDeviceConnection | None] = asyncio.Queue(
            maxsize=ACCEPT_QUEUE_LIMIT
        )
        self._connections: dict[bytes, HostedDeviceConnection] = {}
        self._socket: Any | None = None
        # worker/src/index.ts: binary host socket (all mux devices combined),
        # 2,000 messages / 25,000,000 bytes per 10 seconds. Smooth output at
        # 90% of both rates, leaving room for receive-side network jitter.
        # No accumulated idle credit and no extra queue: callers backpressure
        # through the existing bounded attachment buffers. One host-wide lock
        # preserves each channel's already-serialized Noise record order.
        self._outbound_lock = asyncio.Lock()
        self._outbound_clock = time.monotonic
        self._outbound_sleep = asyncio.sleep
        self._outbound_next = 0.0
        self._runner: asyncio.Task[None] | None = None
        self.closed = False

    def _journal_call(self, method: str, *args, **kwargs) -> None:
        """Connection telemetry is optional and never part of transport flow."""

        if self.journal is None:
            return
        try:
            getattr(self.journal, method)(*args, **kwargs)
        except Exception:
            return

    # -- connector protocol (used by RelayConnectorService) ------------------

    #: ``"unauthorized"`` after the relay refused the last upgrade with
    #: 401/403 (this machine is not allowlisted); ``None`` otherwise.
    last_refusal: str | None = None

    @property
    def connected(self) -> bool:
        """True while the outbound host socket is live (phone-reachable)."""

        return not self.closed and self._socket is not None

    async def start(self) -> None:
        if self._runner is None and not self.closed:
            self._runner = asyncio.create_task(self._run(), name="mercury-relay-host-socket")

    async def accept(self) -> HostedDeviceConnection:
        connection = await self._accepted.get()
        if connection is None:
            raise ConnectorClosed("connector closed")
        return connection

    async def close(self) -> None:
        self.closed = True
        runner, self._runner = self._runner, None
        if runner is not None and not runner.done():
            runner.cancel()
            await asyncio.gather(runner, return_exceptions=True)
        await self._drop_socket()
        self._end_all_connections()
        with contextlib.suppress(asyncio.QueueFull):
            self._accepted.put_nowait(None)

    # -- host socket lifecycle ----------------------------------------------

    async def _run(self) -> None:
        backoff = self._initial_backoff
        while not self.closed:
            self._attempt_number += 1
            attempt_id: str | None = None
            if self.journal is not None:
                try:
                    attempt_id = self.journal.new_attempt_id()
                except Exception:
                    attempt_id = None
            self._last_protocol_generation = None
            self._journal_call(
                "reconnect_attempt",
                attempt_id=attempt_id,
                attempt_number=self._attempt_number,
            )
            try:
                socket = await self._ws_connect(self.url, self._auth_headers())
            except asyncio.CancelledError:
                raise
            except Exception as error:
                # A 401/403 on the upgrade means the relay refused this
                # machine (not allowlisted); the UI shows that instead of a
                # generic "host offline". Any other failure clears it.
                self.last_refusal = (
                    "unauthorized" if upgrade_refused_status(error) in (401, 403) else None
                )
                self._journal_call(
                    "reconnect_result",
                    attempt_id=attempt_id,
                    outcome="failed",
                    reason="connect_failed",
                    exception_category_value=exception_category(error),
                )
                delay = self._jittered(backoff)
                self._journal_call(
                    "reconnect_backoff",
                    attempt_id=attempt_id,
                    backoff_ms=max(0, int(delay * 1000)),
                )
                await asyncio.sleep(delay)
                backoff = min(backoff * 2, self._max_backoff)
                continue
            self._socket = socket
            self.last_refusal = None
            self._host_generation = self._last_protocol_generation
            self._journal_call(
                "reconnect_result",
                attempt_id=attempt_id,
                outcome="success",
                reason="connect_started",
            )
            self._journal_call(
                "host_open",
                attempt_id=attempt_id,
                generation=self._host_generation,
            )
            backoff = self._initial_backoff
            close_code: int | None = None
            disconnect_exception_category: str | None = None
            try:
                await self._read_loop(socket)
            except asyncio.CancelledError:
                close_code = _close_code(socket)
                disconnect_exception_category = "cancelled"
                self._journal_call(
                    "reconnect_result",
                    attempt_id=attempt_id,
                    outcome="closed",
                    reason="shutdown",
                    exception_category_value="cancelled",
                )
                raise
            except Exception as error:
                close_code = _close_code(getattr(error, "rcvd", None)) or _close_code(socket)
                disconnect_exception_category = exception_category(error)
                self._journal_call(
                    "reconnect_result",
                    attempt_id=attempt_id,
                    outcome="failed",
                    reason="socket_closed",
                    exception_category_value=exception_category(error),
                )
            finally:
                self._journal_call(
                    "host_disconnect",
                    attempt_id=attempt_id,
                    reason="shutdown" if self.closed else "socket_closed",
                    exception_category_value=disconnect_exception_category,
                    close_code=close_code,
                )
                self._socket = None
                await self._drop_socket(socket)
                self._end_all_connections()
            delay = self._jittered(backoff)
            self._journal_call(
                "reconnect_backoff",
                attempt_id=attempt_id,
                backoff_ms=max(0, int(delay * 1000)),
            )
            await asyncio.sleep(delay)
            backoff = min(backoff * 2, self._max_backoff)

    def _jittered(self, delay: float) -> float:
        return delay * (0.5 + 0.5 * float(self._rng()))

    def _auth_headers(self) -> dict[str, str]:
        self._last_protocol_generation = None
        if self._token_provider is None:
            return {}
        token = self._token_provider()
        if not isinstance(token, str) or not token:
            raise RelayClientError("invalid_routing_token")
        self._last_protocol_generation = _token_generation(token)
        return {"Authorization": f"Bearer {token}"}

    async def _read_loop(self, socket: Any) -> None:
        while True:
            message = await socket.recv()
            self._journal_call("mark_receive")
            if isinstance(message, str):
                self._handle_control(message)
                continue
            data = bytes(message)
            if len(data) > MAX_CIPHERTEXT_RECORD_BYTES + CONNECTION_ID_BYTES:
                raise RelayClientError("frame_too_large")
            if len(data) < CONNECTION_ID_BYTES:
                raise RelayClientError("protocol_violation")
            connection = self._connections.get(data[:CONNECTION_ID_BYTES])
            if connection is None:
                # Frames for a connection we already closed are dropped; the
                # router raced our close notice.
                continue
            if not connection._feed(data[CONNECTION_ID_BYTES:]):
                # Bounded inbound queue overflowed: fail this one device
                # connection closed rather than buffering without limit.
                await self._close_device(connection)

    def _handle_control(self, message: str) -> None:
        if len(message) > MAX_CONTROL_FRAME_BYTES:
            raise RelayClientError("protocol_violation")
        try:
            value = loads_strict(message)
        except StrictJsonError:
            raise RelayClientError("protocol_violation") from None
        if not isinstance(value, dict):
            raise RelayClientError("protocol_violation")
        kind = value.get("t")
        raw_id = value.get("id")
        if (
            set(value) != {"t", "id"}
            or kind not in {"open", "close"}
            or not isinstance(raw_id, str)
            or len(raw_id) != 2 * CONNECTION_ID_BYTES
        ):
            raise RelayClientError("protocol_violation")
        try:
            connection_id = bytes.fromhex(raw_id)
        except ValueError:
            raise RelayClientError("protocol_violation") from None
        if kind == "open":
            stale = self._connections.pop(connection_id, None)
            if stale is not None:
                stale._mark_closed()
            connection = HostedDeviceConnection(self, connection_id)
            self._connections[connection_id] = connection
            try:
                self._accepted.put_nowait(connection)
            except asyncio.QueueFull:
                # The session loops are saturated; refuse the device.
                del self._connections[connection_id]
                connection._mark_closed()
                raise RelayClientError("backpressure") from None
            return
        closing = self._connections.pop(connection_id, None)
        if closing is not None:
            closing._mark_closed()

    def _end_all_connections(self) -> None:
        connections, self._connections = self._connections, {}
        for connection in connections.values():
            connection._mark_closed()

    async def _drop_socket(self, socket: Any | None = None) -> None:
        target = socket if socket is not None else self._socket
        self._socket = None
        if target is not None:
            with contextlib.suppress(Exception):
                await target.close()

    # -- outgoing path (called from HostedDeviceConnection) ------------------

    async def _send_binary(self, connection: HostedDeviceConnection, data: bytes) -> None:
        socket = self._socket
        if self._connections.get(connection.connection_id) is not connection or socket is None:
            raise ConnectionError("connection closed")
        try:
            async with self._outbound_lock:
                delay = self._outbound_next - self._outbound_clock()
                if delay > 0:
                    await self._outbound_sleep(delay)
                # Waiting must not allow a detached channel to publish into a
                # replaced host socket or a newly admitted device attachment.
                if (
                    self._socket is not socket
                    or connection.closed
                    or self._connections.get(connection.connection_id) is not connection
                ):
                    raise ConnectionError("connection closed")
                size = CONNECTION_ID_BYTES + len(data)
                await socket.send(connection.connection_id + data)
                self._outbound_next = self._outbound_clock() + max(
                    10.0 / (2000 * 0.9), size * 10.0 / (25_000_000 * 0.9)
                )
                self._journal_call("mark_send")
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ConnectionError("connection closed") from None

    async def _close_device(self, connection: HostedDeviceConnection) -> None:
        connection._mark_closed()
        if self._connections.get(connection.connection_id) is not connection:
            return
        del self._connections[connection.connection_id]
        socket = self._socket
        if socket is not None:
            with contextlib.suppress(Exception):
                await socket.send('{"t":"close","id":"' + connection.connection_id.hex() + '"}')
                self._journal_call("mark_send")


async def _default_ws_connect(url: str, headers: dict[str, str]) -> Any:
    import websockets

    kwargs: dict[str, Any] = {
        "max_size": MAX_CIPHERTEXT_RECORD_BYTES + CONNECTION_ID_BYTES + 1024,
        "compression": None,
    }
    try:
        return await websockets.connect(url, additional_headers=headers, **kwargs)
    except TypeError:
        # Older websockets releases spell the same parameter extra_headers.
        return await websockets.connect(url, extra_headers=headers, **kwargs)


__all__ = [
    "CloudflareRelayConnector",
    "HostedDeviceConnection",
    "RelayClientError",
    "host_socket_url",
]
