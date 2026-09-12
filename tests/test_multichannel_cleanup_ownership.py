"""All channels retain cleanup ownership without exposing sibling sessions."""

import asyncio

import pytest

from mercury_relay_plugin.session_lease import SessionLease, SessionLeaseError, SessionLeaseManager
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


@pytest.mark.parametrize("shutdown", [False, True])
@pytest.mark.parametrize("fail", [False, True])
def test_all_channels_fenced_while_cleanup_waits_and_cancellation_drains(shutdown, fail):
    async def exercise():
        entered, resume = asyncio.Event(), asyncio.Event()
        calls = []

        async def close_controller(cid):
            if cid == "first":
                entered.set()
                await resume.wait()
            calls.append(cid)
            if fail and cid == "first":
                raise RuntimeError("synthetic private failure")
            return True

        manager = SessionLeaseManager()
        leases = []
        for channel in ("first", "second"):
            lease = SessionLease(
                device_id="device", channel=channel, profile="default", controller_id=channel,
                websocket=VirtualWebSocket(), close_controller=close_controller,
            )
            manager.register(lease)
            lease.attach()
            leases.append(lease)
        task = asyncio.create_task(
            manager.close() if shutdown else manager.release_device("device", reason="revoked")
        )
        await asyncio.wait_for(entered.wait(), 1)
        # Never leave another channel publishing while one close call stalls.
        fenced = all(lease.released for lease in leases)
        assert manager.get("device", "first") is leases[0]
        assert leases[0] in manager.leases_for("device")
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        resume.set()
        result = (await asyncio.gather(task, return_exceptions=True))[0]
        assert fenced, "sibling channel remained live during device-wide cleanup"
        assert sorted(calls) == ["first", "second"]
        assert manager.get("device", "second") is None
        if fail:
            assert isinstance(result, SessionLeaseError)
            assert str(result) == "controller_release_failed"
            assert manager.get("device", "first") is leases[0]
            assert manager.active_count == 1
            with pytest.raises(SessionLeaseError, match="controller_release_failed"):
                await manager.release_device("device")
        else:
            assert isinstance(result, asyncio.CancelledError)
            assert manager.leases_for("device") == []
            assert manager.active_count == 0

    asyncio.run(exercise())


def test_single_channel_failure_blocks_replacement_but_preserves_other_channels():
    async def exercise():
        calls = []

        async def close_controller(cid):
            calls.append(cid)
            if cid == "first":
                raise RuntimeError("synthetic private failure")
            return True

        manager = SessionLeaseManager(max_leases=2)

        def make(channel):
            return SessionLease(
                device_id="device", channel=channel, profile="default", controller_id=channel,
                websocket=VirtualWebSocket(), close_controller=close_controller,
            )

        first, second = make("first"), make("second")
        manager.register(first)
        manager.register(second)
        attachment = second.attach()
        with pytest.raises(SessionLeaseError, match="controller_release_failed"):
            await manager.release_lease("device", "first")
        assert manager.get("device", "first") is first
        assert manager.leases_for("device") == [first, second]
        with pytest.raises(SessionLeaseError, match="device_already_leased"):
            manager.register(make("first"))
        with pytest.raises(SessionLeaseError, match="lease_limit_reached"):
            manager.register(make("third"))
        assert not second.released and not attachment.detached
        assert calls == ["first"]
        assert await manager.release_lease("device", "second")
        assert not await manager.release_lease("device", "second")
        assert calls == ["first", "second"]
        assert manager.active_count == 1

    asyncio.run(exercise())
