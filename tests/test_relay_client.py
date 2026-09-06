from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.connector import ConnectorClosed  # noqa: E402
from mercury_relay_plugin.relay_client import (  # noqa: E402
    CloudflareRelayConnector,
    RelayClientError,
    host_socket_url,
)


class FakeSocket:
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[str | bytes | Exception] = asyncio.Queue()
        self.sent: list[str | bytes] = []
        self.closed = False

    async def recv(self) -> str | bytes:
        item = await self.incoming.get()
        if isinstance(item, Exception):
            raise item
        return item

    async def send(self, data: str | bytes) -> None:
        if self.closed:
            raise ConnectionError("socket closed")
        self.sent.append(data)

    async def close(self) -> None:
        self.closed = True
        await self.incoming.put(ConnectionError("socket closed"))


def _connector(
    sockets: list[FakeSocket],
    attempts: list[str],
    *,
    token_provider=None,
    headers_seen: list[dict[str, str]] | None = None,
) -> CloudflareRelayConnector:
    async def fake_connect(url: str, headers: dict[str, str]) -> FakeSocket:
        attempts.append(url)
        if headers_seen is not None:
            headers_seen.append(dict(headers))
        if not sockets:
            raise ConnectionError("no socket available")
        return sockets.pop(0)

    return CloudflareRelayConnector(
        relay_origin="https://relay.example.net",
        installation_id=b"\x11" * 32,
        ws_connect=fake_connect,
        token_provider=token_provider,
        initial_backoff=0.01,
        max_backoff=0.05,
        rng=lambda: 0.0,
    )


def test_host_socket_url_is_opaque_and_bounded() -> None:
    url = host_socket_url("https://relay.example.net", b"\x00" * 32)
    assert url == "wss://relay.example.net/v1/host/" + "A" * 43 + "?mux=1"
    # A trailing-slash origin canonicalizes to the same opaque URL.
    assert host_socket_url("https://relay.example.net/", b"\x00" * 32) == url
    for origin in (
        "http://relay.example.net",
        "ftp://x",
        "x" * 300,
        "https://user@relay.example.net",
        "https://user:secret@relay.example.net",
        "https://relay.example.net/path",
        "https://relay.example.net?query=1",
        "https://relay.example.net#fragment",
        "https://relay.example.net:not-a-port",
        "https://",
    ):
        with pytest.raises(RelayClientError):
            host_socket_url(origin, b"\x00" * 32)
    with pytest.raises(RelayClientError):
        host_socket_url("https://relay.example.net", b"\x00" * 16)


def test_control_boundaries_become_logical_connections() -> None:
    async def exercise() -> None:
        socket = FakeSocket()
        attempts: list[str] = []
        connector = _connector([socket], attempts)
        await connector.start()

        id_a = bytes(range(8))
        id_b = bytes(range(8, 16))
        await socket.incoming.put('{"t":"open","id":"' + id_a.hex() + '"}')
        connection = await asyncio.wait_for(connector.accept(), 2)
        await socket.incoming.put(id_a + b"\x01\x02\x03")
        assert await asyncio.wait_for(connection.receive(), 2) == b"\x01\x02\x03"

        await connection.send(b"\x09\x08")
        assert socket.sent == [id_a + b"\x09\x08"]

        # A concurrent second device coexists on the same host socket.
        await socket.incoming.put('{"t":"open","id":"' + id_b.hex() + '"}')
        second = await asyncio.wait_for(connector.accept(), 2)
        assert second is not connection
        await socket.incoming.put(id_b + b"\xbb")
        assert await asyncio.wait_for(second.receive(), 2) == b"\xbb"
        await second.send(b"\xcc")
        assert socket.sent[-1] == id_b + b"\xcc"

        # Router-declared device detach ends only that logical connection.
        await socket.incoming.put('{"t":"close","id":"' + id_a.hex() + '"}')
        assert await asyncio.wait_for(connection.receive(), 2) is None
        with pytest.raises(ConnectionError):
            await connection.send(b"\x00")
        await socket.incoming.put(id_b + b"\xdd")
        assert await asyncio.wait_for(second.receive(), 2) == b"\xdd"

        # Frames for an unknown id are dropped, not fatal.
        await socket.incoming.put(bytes(range(16, 24)) + b"\xee")
        await socket.incoming.put(id_b + b"\xff")
        assert await asyncio.wait_for(second.receive(), 2) == b"\xff"

        # Host-side close tells the router to end that device connection.
        await second.close()
        assert socket.sent[-1] == '{"t":"close","id":"' + id_b.hex() + '"}'
        await connector.close()

    asyncio.run(exercise())


def test_socket_loss_reconnects_with_backoff_and_fails_connections_closed() -> None:
    async def exercise() -> None:
        first = FakeSocket()
        second = FakeSocket()
        attempts: list[str] = []
        connector = _connector([first, second], attempts)
        await connector.start()

        await first.incoming.put('{"t":"open","id":"' + ("00" * 8) + '"}')
        connection = await asyncio.wait_for(connector.accept(), 2)
        await first.incoming.put(ConnectionError("edge dropped"))

        # The logical connection fails closed; the socket reconnects.
        assert await asyncio.wait_for(connection.receive(), 2) is None
        await asyncio.wait_for(_wait_until(lambda: len(attempts) >= 2), 2)
        assert attempts[0] == attempts[1]

        await second.incoming.put('{"t":"open","id":"' + ("01" * 8) + '"}')
        resumed = await asyncio.wait_for(connector.accept(), 2)
        await second.incoming.put(bytes.fromhex("01" * 8) + b"\xaa")
        assert await asyncio.wait_for(resumed.receive(), 2) == b"\xaa"
        await connector.close()

    asyncio.run(exercise())


def test_protocol_violations_drop_the_socket() -> None:
    async def exercise() -> None:
        bad = FakeSocket()
        replacement = FakeSocket()
        attempts: list[str] = []
        connector = _connector([bad, replacement], attempts)
        await connector.start()

        await bad.incoming.put('{"t":"surprise"}')
        await asyncio.wait_for(_wait_until(lambda: bad.closed), 2)
        await asyncio.wait_for(_wait_until(lambda: len(attempts) >= 2), 2)

        oversized = FakeSocket()
        await replacement.incoming.put(b"\x00" * 65_552)
        connector2_sockets_unused = oversized  # noqa: F841 - explicit fixture note
        await asyncio.wait_for(_wait_until(lambda: replacement.closed), 2)
        await connector.close()

    asyncio.run(exercise())


def test_control_frames_are_never_written_to_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    """MR-02: control handling must not open any file (no debug log sink)."""

    opened: list[str] = []
    real_open = open

    def recording_open(file, *args, **kwargs):  # noqa: ANN001 - builtin signature
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", recording_open)

    async def exercise() -> None:
        socket = FakeSocket()
        connector = _connector([socket], [])
        await connector.start()
        sentinel = '{"t":"open","id":"' + ("ab" * 8) + '"}'
        await socket.incoming.put(sentinel)
        connection = await asyncio.wait_for(connector.accept(), 2)
        await socket.incoming.put('{"t":"close","id":"' + ("ab" * 8) + '"}')
        assert await asyncio.wait_for(connection.receive(), 2) is None
        await connector.close()

    asyncio.run(exercise())
    assert opened == []


def test_close_poisons_accept_and_is_idempotent() -> None:
    async def exercise() -> None:
        socket = FakeSocket()
        connector = _connector([socket], [])
        await connector.start()
        await connector.close()
        await connector.close()
        with pytest.raises(ConnectorClosed):
            await connector.accept()

    asyncio.run(exercise())


async def _wait_until(predicate) -> None:
    while not predicate():
        await asyncio.sleep(0.01)


def test_each_connect_attempt_sends_a_fresh_routing_token() -> None:
    """MR-01: the host leg authenticates every upgrade with a fresh token."""

    async def exercise() -> None:
        minted: list[str] = []

        def provider() -> str:
            minted.append(f"token-{len(minted)}")
            return minted[-1]

        first = FakeSocket()
        second = FakeSocket()
        attempts: list[str] = []
        headers_seen: list[dict[str, str]] = []
        connector = _connector(
            [first, second], attempts, token_provider=provider, headers_seen=headers_seen
        )
        await connector.start()
        await first.incoming.put(ConnectionError("edge dropped"))
        await asyncio.wait_for(_wait_until(lambda: len(headers_seen) >= 2), 2)
        assert headers_seen[0]["Authorization"] == "Bearer token-0"
        assert headers_seen[1]["Authorization"] == "Bearer token-1"
        await connector.close()

    asyncio.run(exercise())


def test_worker_generation_is_the_routing_token_iat_not_local_attempt_number() -> None:
    from mercury_relay_plugin.routing_auth import RoutingTokenIssuer

    issuer = RoutingTokenIssuer(b"\x22" * 32, clock=lambda: 1_720_000_123)
    connector = CloudflareRelayConnector(
        relay_origin="https://relay.example.net",
        installation_id=b"\x11" * 32,
        token_provider=lambda: issuer.mint_host_token(b"\x11" * 32),
    )

    headers = connector._auth_headers()

    assert set(headers) == {"Authorization"}
    assert connector._last_protocol_generation == 1_720_000_123
    assert connector._attempt_number == 0


def test_transport_continues_when_connection_journal_raises() -> None:
    class ExplodingJournal:
        def new_attempt_id(self):
            raise RuntimeError("private journal failure")

        def __getattr__(self, _name):
            def fail(*_args, **_kwargs):
                raise RuntimeError("private journal failure")

            return fail

    async def exercise() -> None:
        socket = FakeSocket()
        connector = _connector([socket], [])
        connector.journal = ExplodingJournal()
        await connector.start()
        await socket.incoming.put('{"t":"open","id":"' + ("00" * 8) + '"}')
        connection = await asyncio.wait_for(connector.accept(), 2)
        await connection.send(b"\x01")
        assert socket.sent[-1] == (b"\x00" * 8) + b"\x01"
        await connector.close()

    asyncio.run(exercise())
