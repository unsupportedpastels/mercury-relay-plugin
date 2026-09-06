from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.connector import (  # noqa: E402
    InMemoryHostedConnector,
    RelayConnectorService,
)


class _StartableConnector:
    """A connector that must be started before it can accept, like the
    hosted Cloudflare host socket."""

    def __init__(self) -> None:
        self.started = 0
        self.closed = 0
        self._gate = asyncio.Event()

    async def start(self) -> None:
        self.started += 1
        self._gate.set()

    async def accept(self):
        await self._gate.wait()
        # Never actually yields a connection in this test; we only assert the
        # service propagated start() so the transport can open.
        await asyncio.Event().wait()

    async def close(self) -> None:
        self.closed += 1
        self._gate.set()


class _FakeAdmission:
    """Minimal stand-in accepted by RelayConnectorService's isinstance check
    via subclassing is unnecessary; the service only calls admission on a
    live connection, which this test never produces."""


def test_pairing_connection_delivers_encrypted_device_id_ack(tmp_path: Path) -> None:
    """PROTOCOL §4: after consuming the capability the host sends one
    encrypted pairing acknowledgement carrying the host-assigned device_id,
    then closes; the pending record awaits operator approval."""

    import hashlib
    import json
    import secrets

    from mercury_relay_plugin.admission import DeviceAdmissionService
    from mercury_relay_plugin.authorization import AuthorizationRepository
    from mercury_relay_plugin.config import profile_paths
    from mercury_relay_plugin.runtime import RelayRuntime
    from mercury_relay_plugin.secure_channel import NoiseChannel

    async def compatible_handle_ws(ws, *, auth_identity=None) -> None:
        del ws, auth_identity

    class _Bridge:
        def __init__(self, websocket) -> None:
            self.websocket = websocket

        async def start(self) -> None: ...

        async def close(self) -> None: ...

    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = RelayRuntime(
            loader=lambda: compatible_handle_ws,
            bridge_factory=lambda websocket: _Bridge(websocket),
            id_factory=lambda: "synthetic-controller",
            profile_authorizer=lambda profile: profile == "default",
        )
        await runtime.start()
        from mercury_relay_plugin.routing_auth import (
            RoutingIssuerStore,
            verify_routing_token,
        )

        admission = DeviceAdmissionService(repository, runtime, profile="default")
        issuer = RoutingIssuerStore(repository.store).load_or_create()
        connector = InMemoryHostedConnector()
        service = RelayConnectorService(admission, connector, routing_issuer=issuer)
        await service.start()

        offer = repository.create_offer()
        mobile = NoiseChannel.initiator(
            static_private_key=secrets.token_bytes(32),
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        device = await connector.connect()
        await device.send(mobile.write_handshake())
        assert mobile.read_handshake(await device.receive()) == b""
        await device.send(mobile.write_handshake(offer.capability))

        ack = json.loads(mobile.decrypt(await device.receive()).decode("ascii"))
        assert ack["type"] == "pairing.pending"
        # MR-01: the ack delivers the device's routing token inside the
        # authenticated channel; it verifies against the static issuer and
        # is scoped to this installation with the authorized-device role.
        claims = verify_routing_token(ack["relay_token"], public_key=issuer.public_key)
        assert claims["role"] == "authorized_device"
        devices = repository.list_devices()
        assert [record.device_id for record in devices] == [ack["device_id"]]
        assert devices[0].status == "pending"

        # The pairing connection ends after the ack.
        assert await device.receive() is None

        # The acked device_id is exactly what approval and admission key on.
        repository.approve(ack["device_id"], hashlib.sha256(mobile.channel_binding).digest())
        assert repository.list_devices()[0].status == "authorized"

        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_device_routing_token_recovers_after_transient_identity_read(
    tmp_path: Path, monkeypatch
) -> None:
    from mercury_relay_plugin.admission import DeviceAdmissionService
    from mercury_relay_plugin.authorization import AuthorizationRepository
    from mercury_relay_plugin.config import profile_paths
    from mercury_relay_plugin.routing_auth import RoutingIssuerStore, verify_routing_token
    from mercury_relay_plugin.runtime import RelayRuntime

    async def compatible_handle_ws(ws, *, auth_identity=None) -> None:
        del ws, auth_identity

    class _Bridge:
        def __init__(self, websocket) -> None:
            self.websocket = websocket

        async def start(self) -> None: ...

        async def close(self) -> None: ...

    root = tmp_path / "hermes"
    root.mkdir()
    repository = AuthorizationRepository(profile_paths(explicit_path=root))
    issuer = RoutingIssuerStore(repository.store).load_or_create()
    original_load = repository.identity_store.load_or_create
    calls = 0

    def transient_load():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("temporary state lock")
        return original_load()

    monkeypatch.setattr(repository.identity_store, "load_or_create", transient_load)
    runtime = RelayRuntime(
        loader=lambda: compatible_handle_ws,
        bridge_factory=lambda websocket: _Bridge(websocket),
        profile_authorizer=lambda profile: profile == "default",
    )
    admission = DeviceAdmissionService(repository, runtime, profile="default")
    service = RelayConnectorService(
        admission,
        InMemoryHostedConnector(),
        routing_issuer=issuer,
    )

    assert service._installation_id is None
    token = service._mint_device_routing_token()
    assert token is not None
    claims = verify_routing_token(token, public_key=issuer.public_key)
    assert len(claims["inst"]) == 43
    assert calls == 2


def test_service_start_propagates_to_a_startable_connector() -> None:
    async def exercise() -> None:
        connector = _StartableConnector()
        # Bypass the admission type check: this regression is purely about the
        # service starting its connector, which happens before any admission.
        service = RelayConnectorService.__new__(RelayConnectorService)
        service.admission = None  # type: ignore[assignment]
        service.connector = connector
        service.max_connections = 4
        service.handshake_timeout = 5.0
        service._accept_task = None
        service._connections = set()
        service.closed = False

        await service.start()
        # The hosted host socket cannot open unless the service started it.
        assert connector.started == 1
        assert service._accept_task is not None

        await service.close()
        assert connector.closed == 1

    asyncio.run(exercise())


def test_pairing_ack_failure_rolls_back_the_pending_record(tmp_path: Path) -> None:
    """BR-04: an undeliverable ack must not strand an active-device slot —
    the device never learned its device_id and the capability is consumed,
    so the pending record is rolled back and the owner can re-pair."""

    import secrets

    from mercury_relay_plugin.admission import DeviceAdmissionService
    from mercury_relay_plugin.authorization import AuthorizationRepository
    from mercury_relay_plugin.config import profile_paths
    from mercury_relay_plugin.runtime import RelayRuntime
    from mercury_relay_plugin.secure_channel import NoiseChannel

    async def compatible_handle_ws(ws, *, auth_identity=None) -> None:
        del ws, auth_identity

    class _Bridge:
        def __init__(self, websocket) -> None:
            self.websocket = websocket

        async def start(self) -> None: ...

        async def close(self) -> None: ...

    class ScriptedConnection:
        """Delivers the handshake but fails the send after it (the ack)."""

        def __init__(self) -> None:
            self.inbound: asyncio.Queue[bytes] = asyncio.Queue()
            self.sent: list[bytes] = []

        async def receive(self) -> bytes | None:
            return await self.inbound.get()

        async def send(self, data: bytes) -> None:
            if self.sent:
                raise ConnectionError("device vanished before the ack")
            self.sent.append(bytes(data))

        async def close(self) -> None: ...

    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = RelayRuntime(
            loader=lambda: compatible_handle_ws,
            bridge_factory=lambda websocket: _Bridge(websocket),
            id_factory=lambda: "synthetic-controller",
            profile_authorizer=lambda profile: profile == "default",
        )
        await runtime.start()
        admission = DeviceAdmissionService(repository, runtime, profile="default")
        service = RelayConnectorService(admission, InMemoryHostedConnector())

        offer = repository.create_offer()
        mobile = NoiseChannel.initiator(
            static_private_key=secrets.token_bytes(32),
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        connection = ScriptedConnection()
        loop_task = asyncio.create_task(service._session_loop(connection))
        await connection.inbound.put(mobile.write_handshake())
        while not connection.sent:
            await asyncio.sleep(0.01)
        assert mobile.read_handshake(connection.sent[0]) == b""
        await connection.inbound.put(mobile.write_handshake(offer.capability))

        assert await asyncio.wait_for(loop_task, 2) == "pairing_ack_failed"
        assert [device.status for device in repository.list_devices()] == ["denied"]

        # The slot is free again: a fresh offer pairs successfully.
        fresh = repository.create_offer()
        summary = repository.consume_offer(
            fresh.capability, secrets.token_bytes(32), secrets.token_bytes(32)
        )
        assert summary.status == "pending"

        await service.close()
        await runtime.close()

    asyncio.run(exercise())
