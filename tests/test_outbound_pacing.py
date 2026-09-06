import asyncio

from mercury_relay_plugin.relay_client import CloudflareRelayConnector, HostedDeviceConnection


class Clock:
    now = 0.0

    async def sleep(self, seconds):
        self.now += seconds
        await asyncio.sleep(0)


class Socket:
    def __init__(self, clock):
        self.clock = clock
        self.sent = []

    async def send(self, data):
        self.sent.append((self.clock.now, data))


def test_host_binary_pacing_bounds_aggregate_mux_frames():
    async def run():
        clock = Clock()
        client = CloudflareRelayConnector(
            relay_origin="https://relay.example", installation_id=b"i" * 32
        )
        # Inject monotonic scheduling, not real delays, into the actual send path.
        client._outbound_clock = lambda: clock.now
        client._outbound_sleep = clock.sleep
        socket = Socket(clock)
        client._socket = socket
        devices = [HostedDeviceConnection(client, bytes([i]) * 8) for i in (1, 2)]
        client._connections = {d.connection_id: d for d in devices}
        for index in range(2200):
            await devices[index % 2].send(b"x")
        times = [t for t, _ in socket.sent]
        assert times[2000] >= 10
        for index, (now, _) in enumerate(socket.sent):
            window = [data for t, data in socket.sent[index:] if t < now + 10]
            assert len(window) <= 2000
            assert sum(map(len, window)) <= 25_000_000
        # Byte pacing includes the host's 8-byte mux prefix.
        socket.sent.clear()
        for _ in range(420):
            await devices[0].send(b"x" * 65535)
        for index, (now, _) in enumerate(socket.sent):
            window = [data for t, data in socket.sent[index:] if t < now + 10]
            assert sum(map(len, window)) <= 25_000_000

    asyncio.run(run())


def test_waiting_send_rejects_replaced_socket_and_cancelled_waiter():
    async def run():
        clock = Clock()
        client = CloudflareRelayConnector(
            relay_origin="https://relay.example", installation_id=b"i" * 32
        )
        client._outbound_clock = lambda: clock.now
        entered, release = asyncio.Event(), asyncio.Event()

        async def wait(seconds):
            entered.set()
            await release.wait()
            clock.now += seconds

        client._outbound_sleep = wait
        old = Socket(clock)
        client._socket = old
        device = HostedDeviceConnection(client, b"1" * 8)
        client._connections = {device.connection_id: device}
        await device.send(b"first")
        pending = asyncio.create_task(device.send(b"stale"))
        await entered.wait()
        fresh = Socket(clock)
        client._socket = fresh
        release.set()
        try:
            await pending
            raise AssertionError("stale socket must be fenced")
        except ConnectionError:
            pass
        assert len(old.sent) == 1 and fresh.sent == []
        # Cancel a blocked send; it neither sends nor poisons the lock.
        client._socket = old
        client._outbound_next = clock.now + 1
        entered.clear()
        release.clear()
        pending = asyncio.create_task(device.send(b"cancelled"))
        await entered.wait()
        pending.cancel()
        try:
            await pending
            raise AssertionError("cancellation must propagate")
        except asyncio.CancelledError:
            pass
        release.set()
        await device.send(b"last")
        assert [data[8:] for _, data in old.sent] == [b"first", b"last"]

    asyncio.run(run())


def test_concurrent_mux_producers_share_pacing_and_preserve_per_device_order():
    async def run():
        clock = Clock()
        client = CloudflareRelayConnector(
            relay_origin="https://relay.example", installation_id=b"i" * 32
        )
        client._outbound_clock = lambda: clock.now
        client._outbound_sleep = clock.sleep
        socket = Socket(clock)
        client._socket = socket
        devices = [HostedDeviceConnection(client, bytes([i]) * 8) for i in (1, 2)]
        client._connections = {d.connection_id: d for d in devices}

        async def produce(device):
            for index in range(1100):
                await device.send(index.to_bytes(4, "big"))

        await asyncio.gather(*(produce(d) for d in devices))
        assert socket.sent[2000][0] >= 10
        for device in devices:
            assert [
                int.from_bytes(data[8:], "big")
                for _, data in socket.sent
                if data[:8] == device.connection_id
            ] == list(range(1100))
        clock.now += 1000
        await devices[0].send(b"idle")
        first = socket.sent[-1][0]
        await devices[0].send(b"no credit")
        assert socket.sent[-1][0] > first

    asyncio.run(run())
