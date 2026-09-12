"""Outer-connection acceptance and per-connection session loops.

This module owns the glue between a hosted connector (fake in Phase 1, the
Cloudflare relay client later) and the admission/lease/transport stack:
accept one outer message-oriented connection, run the Noise handshake bytes
through the admission service, then pump ciphertext both ways until either
side ends.  Every connection is bounded (frame size, handshake deadline,
concurrent count) and every failure collapses to a stable reason string —
no logging, no peer-controlled detail.

Deriving the transport ``channel_id`` from the first 16 bytes of the Noise
channel binding keeps both endpoints in agreement without negotiation and
binds the framing channel to this exact handshake (PROTOCOL §7).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Protocol

from .admission import AdmissionRejected, DeviceAdmissionService
from .connection_journal import ConnectionJournal, exception_category
from .controller_transport import ControllerTransportError
from .framing import CHANNEL_ID_SIZE
from .secure_channel import MAX_CIPHERTEXT_RECORD_BYTES, SecureChannelError

HANDSHAKE_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONNECTIONS = 16
_QUEUE_LIMIT = 64


class OuterConnection(Protocol):
    """One message-oriented outer transport (hosted WebSocket-shaped)."""

    async def receive(self) -> bytes | None: ...

    async def send(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


class ConnectorClosed(RuntimeError):
    """The hosted connector stopped accepting connections."""


class _Pipe:
    """One bounded in-memory byte-message stream."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=_QUEUE_LIMIT)
        self._closed = False

    async def put(self, data: bytes | None) -> None:
        if self._closed:
            return
        if data is None:
            self._closed = True
        await self._queue.put(data)

    async def get(self) -> bytes | None:
        item = await self._queue.get()
        if item is None:
            self._closed = True
        return item


class InMemoryConnection:
    """One endpoint of an in-memory duplex outer connection."""

    def __init__(self, inbound: _Pipe, outbound: _Pipe) -> None:
        self._inbound = inbound
        self._outbound = outbound
        self.closed = False

    async def receive(self) -> bytes | None:
        if self.closed:
            return None
        data = await self._inbound.get()
        if data is None:
            self.closed = True
        return data

    async def send(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionError("connection closed")
        await self._outbound.put(bytes(data))

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self._outbound.put(None)


class InMemoryHostedConnector:
    """Deterministic hosted-connector fake for the Phase 1 vertical slice."""

    def __init__(self) -> None:
        self._accepted: asyncio.Queue[InMemoryConnection | None] = asyncio.Queue()
        self.closed = False

    async def connect(self) -> InMemoryConnection:
        """Device side: open one new outer connection to the host."""

        if self.closed:
            raise ConnectorClosed("connector closed")
        device_to_host = _Pipe()
        host_to_device = _Pipe()
        host_side = InMemoryConnection(device_to_host, host_to_device)
        device_side = InMemoryConnection(host_to_device, device_to_host)
        await self._accepted.put(host_side)
        return device_side

    async def accept(self) -> InMemoryConnection:
        connection = await self._accepted.get()
        if connection is None:
            raise ConnectorClosed("connector closed")
        return connection

    async def close(self) -> None:
        self.closed = True
        await self._accepted.put(None)


class RelayConnectorService:
    """Supervise the accept loop and every per-connection session loop."""

    def __init__(
        self,
        admission: DeviceAdmissionService,
        connector,
        *,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        handshake_timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
        routing_issuer=None,
        journal: ConnectionJournal | None = None,
    ) -> None:
        if not isinstance(admission, DeviceAdmissionService):
            raise TypeError("admission must be a DeviceAdmissionService")
        if max_connections < 1 or handshake_timeout <= 0:
            raise ValueError("connector bounds must be positive")
        self.admission = admission
        self.connector = connector
        self.journal = journal or getattr(admission, "journal", None)
        # Optional Phase 0 static routing issuer: when present, the pairing
        # ack also delivers the device's routing token over the
        # authenticated Noise channel (MR-01). The installation id is
        # immutable for the process, so capture it once here rather than
        # re-reading identity from disk on the event loop per pairing ack.
        self.routing_issuer = routing_issuer
        self._installation_id: bytes | None = None
        if routing_issuer is not None:
            try:
                self._installation_id = (
                    admission.repository.identity_store.load_or_create().installation_id
                )
            except Exception:
                self._installation_id = None
            # Renew the device's routing token on every lease attach so a
            # paired phone never has to re-pair just because its Phase 0
            # token aged out.
            admission.routing_token_provider = self._mint_device_routing_token
        self.max_connections = max_connections
        self.handshake_timeout = float(handshake_timeout)
        self._accept_task: asyncio.Task[None] | None = None
        self._connections: set[asyncio.Task[str]] = set()
        self.closed = False

    def _journal_call(self, method: str, *args, **kwargs) -> None:
        """Journal best effort: diagnostics can never change transport flow."""

        if self.journal is None:
            return
        try:
            getattr(self.journal, method)(*args, **kwargs)
        except Exception:
            return

    @property
    def connected(self) -> bool:
        """Whether the underlying hosted transport is live, when it reports it.

        A connector that maintains its own socket (the Cloudflare host socket)
        exposes ``connected``; fakes without one are treated as always ready.
        """

        state = getattr(self.connector, "connected", None)
        if isinstance(state, bool):
            return state
        return not self.closed

    @property
    def last_refusal(self) -> str | None:
        """Why the hosted transport last refused us, when it reports it."""

        value = getattr(self.connector, "last_refusal", None)
        return value if isinstance(value, str) else None

    async def start(self) -> None:
        if self._accept_task is None and not self.closed:
            # A connector that opens its own transport (the hosted host
            # socket) must be started before the accept loop can receive
            # connections. Fakes that are driven externally omit start().
            connector_start = getattr(self.connector, "start", None)
            if callable(connector_start):
                await connector_start()
            self._accept_task = asyncio.create_task(
                self._accept_loop(), name="mercury-relay-accept"
            )

    async def _accept_loop(self) -> None:
        while True:
            try:
                connection = await self.connector.accept()
            except (ConnectorClosed, asyncio.CancelledError):
                return
            except Exception:
                return
            task = asyncio.create_task(
                self._serve_connection(connection), name="mercury-relay-connection"
            )
            self._connections.add(task)
            task.add_done_callback(self._connections.discard)

    async def _receive_bounded(
        self,
        connection: OuterConnection,
        *,
        timeout: float | None,
        connection_id: str | None = None,
    ) -> bytes:
        if timeout is None:
            data = await connection.receive()
        else:
            data = await asyncio.wait_for(connection.receive(), timeout=timeout)
        if data is None:
            raise ConnectionError("connection closed")
        if len(data) > MAX_CIPHERTEXT_RECORD_BYTES:
            raise ConnectionError("frame too large")
        self._journal_call("mark_receive", connection_id)
        return data

    async def _send_bounded(
        self, connection: OuterConnection, data: bytes, *, connection_id: str | None = None
    ) -> None:
        await connection.send(data)
        self._journal_call("mark_send", connection_id)

    async def _serve_connection(self, connection: OuterConnection) -> str:
        connection_id: str | None = None
        if self.journal is not None:
            try:
                connection_id = self.journal.new_connection_id()
            except Exception:
                connection_id = None
        if connection_id is not None:
            self._journal_call("connection_attempt", connection_id)
        result = "connection_failed"
        failure_category = None
        try:
            if sum(1 for task in self._connections if not task.done()) > self.max_connections:
                result = "connection_limit"
                return result
            if connection_id is not None:
                self._journal_call("connection_open", connection_id)
            result = await self._session_loop(connection, connection_id)
            return result
        except asyncio.CancelledError:
            result = "connection_closed"
            failure_category = "cancelled"
            raise
        except Exception as error:
            result = "connection_failed"
            failure_category = exception_category(error)
            return result
        finally:
            with contextlib.suppress(Exception):
                await connection.close()
            if connection_id is not None:
                self._journal_call(
                    "connection_disconnect",
                    connection_id,
                    reason=result,
                    exception_category_value=failure_category,
                )

    def _mint_device_routing_token(self) -> str | None:
        if self.routing_issuer is None:
            return None
        if self._installation_id is None:
            try:
                # A transient state-file lock during plugin startup must not
                # permanently strand every later mobile pairing without the
                # authorized-device token required for reconnects.
                self._installation_id = (
                    self.admission.repository.identity_store.load_or_create().installation_id
                )
            except Exception:
                return None
        from .routing_auth import (
            AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS,
            ROLE_AUTHORIZED_DEVICE,
        )

        try:
            # installation_id was captured at construction: this is a pure
            # in-memory mint with no disk I/O on the event loop.
            return self.routing_issuer.mint(
                role=ROLE_AUTHORIZED_DEVICE,
                installation_id=self._installation_id,
                ttl_seconds=AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS,
            )
        except Exception:
            # The ack still delivers the device_id; the device can obtain a
            # routing token through a later pairing if minting failed.
            return None

    async def _session_loop(
        self, connection: OuterConnection, connection_id: str | None = None
    ) -> str:
        channel = self.admission.new_host_channel()
        try:
            first = await self._receive_bounded(
                connection, timeout=self.handshake_timeout, connection_id=connection_id
            )
            if channel.read_handshake(first):
                self._journal_call(
                    "handshake_outcome",
                    connection_id,
                    outcome="failed",
                    reason="protocol_violation",
                    exception_category_value="protocol",
                )
                return "protocol_violation"
            await self._send_bounded(
                connection, channel.write_handshake(), connection_id=connection_id
            )
            final = channel.read_handshake(
                await self._receive_bounded(
                    connection, timeout=self.handshake_timeout, connection_id=connection_id
                )
            )
        except (SecureChannelError, ConnectionError, TimeoutError) as error:
            channel.close()
            timed_out = isinstance(error, TimeoutError)
            self._journal_call(
                "handshake_outcome",
                connection_id,
                outcome="timeout" if timed_out else "failed",
                reason="handshake_timeout" if timed_out else "handshake_failed",
                exception_category_value=exception_category(error),
            )
            return "handshake_failed"

        self._journal_call("handshake_outcome", connection_id, outcome="success")

        if final:
            # Pairing connection: the encrypted final payload carries the
            # one-time capability; consume it, deliver the pairing
            # acknowledgement, and end the connection. The operator approves
            # the pending device out of band.
            try:
                summary = self.admission.complete_pairing(channel, final)
            except Exception as error:
                channel.close()
                self._journal_call(
                    "admission_outcome",
                    connection_id,
                    outcome="rejected",
                    reason="pairing_rejected",
                    exception_category_value=exception_category(error),
                )
                return "pairing_rejected"
            self._journal_call(
                "admission_outcome", connection_id, outcome="success", reason="pairing_pending"
            )
            try:
                # The ack is the only way the device learns its host-assigned
                # device_id (PROTOCOL §4 step 6a). With a routing issuer it
                # also carries the device's routing token for authorized
                # reconnects — delivered only inside the authenticated
                # channel, never persisted host-side.
                payload: dict[str, object] = {
                    "device_id": summary.device_id,
                    "type": "pairing.pending",
                }
                relay_token = self._mint_device_routing_token()
                if relay_token is not None:
                    payload["relay_token"] = relay_token
                ack = json.dumps(
                    payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                await self._send_bounded(
                    connection, channel.encrypt(ack), connection_id=connection_id
                )
                return "pairing_pending"
            except Exception as error:
                # Without the ack the device never learns its device_id and
                # the consumed capability cannot be retried, so the pending
                # record is unusable: roll it back rather than stranding an
                # active-device slot (BR-04). The device re-pairs with a
                # fresh QR.
                with contextlib.suppress(Exception):
                    self.admission.repository.deny(summary.device_id)
                self._journal_call(
                    "admission_outcome",
                    connection_id,
                    outcome="failed",
                    reason="pairing_ack_failed",
                    exception_category_value=exception_category(error),
                )
                return "pairing_ack_failed"
            finally:
                channel.close()

        try:
            envelope = await self._receive_bounded(
                connection, timeout=self.handshake_timeout, connection_id=connection_id
            )
        except (ConnectionError, TimeoutError) as error:
            channel.close()
            self._journal_call(
                "admission_outcome",
                connection_id,
                outcome="timeout" if isinstance(error, TimeoutError) else "failed",
                reason="timeout" if isinstance(error, TimeoutError) else "connection_failed",
                exception_category_value=exception_category(error),
            )
            return "handshake_failed"
        try:
            admitted = await self.admission.open_controller(channel, envelope)
            transport = self.admission.bind_controller(
                admitted,
                channel_id=admitted.channel.channel_binding[:CHANNEL_ID_SIZE],
            )
            self._journal_call("admission_outcome", connection_id, outcome="success")
        except AdmissionRejected as error:
            self._journal_call(
                "admission_outcome",
                connection_id,
                outcome="rejected",
                reason=error.reason,
                exception_category_value="admission",
            )
            return error.reason
        except asyncio.CancelledError:
            raise

        async def inbound() -> None:
            while True:
                data = await self._receive_bounded(
                    connection, timeout=None, connection_id=connection_id
                )
                await transport.feed_ciphertext(data)

        async def outbound() -> None:
            async def send(ciphertext: bytes) -> None:
                await self._send_bounded(connection, ciphertext, connection_id=connection_id)

            await transport.pump_outbound(send)

        pumps = [
            asyncio.create_task(inbound(), name="mercury-relay-inbound"),
            asyncio.create_task(outbound(), name="mercury-relay-outbound"),
        ]
        try:
            done, _pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                error = task.exception()
                if isinstance(error, ControllerTransportError):
                    return error.reason
            return "connection_closed"
        finally:
            for task in pumps:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            transport.close()

    async def close(self) -> None:
        """Stop accepting and settle every connection exactly once."""

        self.closed = True
        with contextlib.suppress(Exception):
            await self.connector.close()
        task, self._accept_task = self._accept_task, None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        connections = [task for task in self._connections if not task.done()]
        for connection in connections:
            connection.cancel()
        if connections:
            await asyncio.gather(*connections, return_exceptions=True)
        self._connections.clear()


__all__ = [
    "ConnectorClosed",
    "InMemoryConnection",
    "InMemoryHostedConnector",
    "OuterConnection",
    "RelayConnectorService",
]
