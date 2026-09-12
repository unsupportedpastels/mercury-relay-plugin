"""Behavioral regressions for encrypted publication and cleanup ownership."""

import asyncio
from types import SimpleNamespace

import pytest
from test_controller_transport import _channels
from test_relay_client import FakeSocket, _connector

from mercury_relay_plugin.connector import RelayConnectorService
from mercury_relay_plugin.controller_transport import EncryptedControllerTransport
from mercury_relay_plugin.relay_client import HostedDeviceConnection
from mercury_relay_plugin.session_lease import SessionLease, SessionLeaseError, SessionLeaseManager
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("paced", [False, True, "lock"])
def test_invalidation_cancels_unsent_encrypted_batch(replace, paced):
    async def exercise():
        _, host = _channels()
        ws = VirtualWebSocket()

        async def close_controller(_):
            return True

        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="controller",
            websocket=ws,
            close_controller=close_controller,
        )
        lease.start()
        transport = EncryptedControllerTransport(
            channel=host, attachment=lease.attach(), channel_id=host.channel_binding[:16]
        )
        await ws.send_text("private transcript " + "x" * 200000)
        blocked, resume = asyncio.Event(), asyncio.Event()
        socket = FakeSocket()
        connector = _connector([], [])
        connector._socket = socket
        hosted = HostedDeviceConnection(connector, b"12345678")
        connector._connections[hosted.connection_id] = hosted

        async def sleep(_):
            blocked.set()
            await resume.wait()

        connector._outbound_sleep = sleep
        connector._outbound_clock = lambda: 0.0
        if paced == "lock":
            await connector._outbound_lock.acquire()

        class Handshake:
            def read_handshake(self, _):
                return b""

            def write_handshake(self):
                return b"handshake"

        class Admission:
            def new_host_channel(self):
                return Handshake()

            async def open_controller(self, *_):
                return SimpleNamespace(channel=host)

            def bind_controller(self, *_args, **_kwargs):
                return transport

        class Outer:
            receives = 0

            def __init__(self):
                self.sent = []

            async def receive(self):
                self.receives += 1
                if self.receives <= 3:
                    return b"input"
                await asyncio.Event().wait()

            async def send(self, data):
                if len(self.sent) >= 2:
                    if paced:
                        connector._outbound_next = 1.0
                        if paced == "lock":
                            blocked.set()
                        await hosted.send(data)
                    else:
                        blocked.set()
                        await resume.wait()
                self.sent.append(data)

        outer = Outer()
        service = RelayConnectorService.__new__(RelayConnectorService)
        service.admission, service.journal, service.handshake_timeout = Admission(), None, 1
        task = asyncio.create_task(service._session_loop(outer))
        await asyncio.wait_for(blocked.wait(), 1)
        if replace:
            replacement = lease.attach(recovery=True, replace_attached=True)
        else:
            await lease.release("revoked")
        resume.set()
        if paced == "lock":
            connector._outbound_lock.release()
        await asyncio.wait_for(task, 1)
        try:
            assert len(outer.sent) == 2, "unsent ciphertext escaped invalidated attachment"
            assert socket.sent == [], "pacing delay published revoked ciphertext"
            if replace:
                assert not replacement.detached
                assert not lease.released
        finally:
            await lease.release()

    asyncio.run(exercise())


@pytest.mark.parametrize("stage", ["pump", "read", "websocket", "controller"])
@pytest.mark.parametrize("fail", [False, True])
def test_release_survives_repeated_cancellation_and_keeps_registry(stage, fail):
    async def exercise():
        entered, resume = asyncio.Event(), asyncio.Event()
        calls = []

        async def pause():
            entered.set()
            await resume.wait()

        class WS(VirtualWebSocket):
            async def close(self, **kwargs):
                if stage == "websocket":
                    await pause()
                await super().close(**kwargs)

        ws = WS()

        async def close_controller(cid):
            calls.append(cid)
            if stage == "controller":
                await pause()
            if fail:
                raise RuntimeError("private failure")
            return True

        callbacks = []
        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="controller",
            websocket=ws,
            close_controller=close_controller,
            on_release=lambda: callbacks.append(True),
        )
        manager = SessionLeaseManager()
        manager.register(lease)
        lease.attach()
        if stage in {"pump", "read"}:

            async def pending():
                try:
                    await asyncio.Event().wait()
                finally:
                    await pause()

            if stage == "pump":
                lease._pump_task.cancel()
                await asyncio.gather(lease._pump_task, return_exceptions=True)
                lease._pump_task = asyncio.create_task(pending())
            else:
                lease._read_tasks.add(asyncio.create_task(pending()))
            await asyncio.sleep(0)
        task = asyncio.create_task(manager.release_device("device", reason="revoked"))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        owned = manager.get("device") is lease
        unfinished = not lease._release_done.is_set()
        resume.set()
        result = (await asyncio.gather(task, return_exceptions=True))[0]
        assert owned, "registry dropped controller before cleanup settled"
        assert unfinished, "release falsely reported completion on cancellation"
        assert ws.closed
        assert calls == ["controller"]
        if fail:
            assert isinstance(result, SessionLeaseError)
            assert result.reason == "controller_release_failed"
            assert manager.get("device") is lease
            assert callbacks == []
            with pytest.raises(SessionLeaseError, match="controller_release_failed"):
                await lease.release()
        else:
            assert isinstance(result, asyncio.CancelledError)
            assert callbacks == [True]
            assert await lease.release() is False
            assert manager.get("device") is None

    asyncio.run(exercise())


def test_external_release_racing_terminal_pump_does_not_deadlock():
    async def exercise():
        from mercury_relay_plugin.virtual_ws import VirtualWebSocketClosed

        gate = asyncio.Event()

        class WS(VirtualWebSocket):
            async def next_text(self):
                await gate.wait()
                raise VirtualWebSocketClosed

        calls = []

        async def close_controller(cid):
            calls.append(cid)
            return True

        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="controller",
            websocket=WS(),
            close_controller=close_controller,
        )
        lease.start()
        await asyncio.sleep(0)
        # release sets the fence, then the ready pump observes terminal close
        # before the independent cleanup task gets its first turn.
        release = asyncio.create_task(lease.release())
        gate.set()
        done, _ = await asyncio.wait([release], timeout=0.2)
        if not done:
            # Break the known wait cycle only on failure so asyncio.run can exit.
            cleanup = lease._release_task
            completed = asyncio.get_running_loop().create_future()
            completed.set_result(None)
            lease._release_task = completed
            lease._pump_task.cancel()
            await asyncio.gather(release, cleanup, lease._pump_task, return_exceptions=True)
        assert done, "terminal pump joined cleanup which was waiting on that same pump"
        assert calls == ["controller"]

    asyncio.run(exercise())


@pytest.mark.parametrize("replace_first", [False, True])
def test_revocation_joins_sender_cancellation_cleanup_including_replaced_attachment(replace_first):
    async def exercise():
        _, host = _channels()

        async def close_controller(_):
            return True

        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="controller",
            websocket=VirtualWebSocket(),
            close_controller=close_controller,
        )
        transport = EncryptedControllerTransport(
            channel=host, attachment=lease.attach(), channel_id=host.channel_binding[:16]
        )
        entered, cleaning, finish = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def send(_):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await finish.wait()

        sender = asyncio.create_task(transport.pump_outbound(send))
        await entered.wait()
        if replace_first:
            lease.attach(recovery=True, replace_attached=True)
            await cleaning.wait()
        release = asyncio.create_task(lease.release("revoked"))
        await cleaning.wait()
        await asyncio.sleep(0)
        assert not release.done()
        release.cancel()
        await asyncio.sleep(0)
        release.cancel()
        await asyncio.sleep(0)
        assert not release.done()
        assert not sender.done()
        finish.set()
        result = await asyncio.gather(sender, release, return_exceptions=True)
        assert isinstance(result[1], asyncio.CancelledError)
        assert lease._release_done.is_set()
        assert not lease._outbound_tasks

    asyncio.run(exercise())


def test_manager_close_drains_all_leases_after_repeated_cancellation():
    async def exercise():
        entered, resume = asyncio.Event(), asyncio.Event()
        calls = []

        async def close_controller(cid):
            if cid == "first":
                entered.set()
                await resume.wait()
            calls.append(cid)
            return True

        manager = SessionLeaseManager()
        for cid in ("first", "second"):
            manager.register(
                SessionLease(
                    device_id=cid,
                    profile="default",
                    controller_id=cid,
                    websocket=VirtualWebSocket(),
                    close_controller=close_controller,
                )
            )
        task = asyncio.create_task(manager.close())
        await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        resume.set()
        result = (await asyncio.gather(task, return_exceptions=True))[0]
        try:
            assert sorted(calls) == ["first", "second"]
            assert isinstance(result, asyncio.CancelledError)
            assert manager.active_count == 0
        finally:
            await manager.close()

    asyncio.run(exercise())
