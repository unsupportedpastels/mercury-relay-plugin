import asyncio

import pytest
from test_session_lease import Controllers

from mercury_relay_plugin.session_lease import LeaseLimits, LeaseReleased, SessionLease
from mercury_relay_plugin.virtual_ws import VirtualWebSocket


def test_revocation_erases_queued_snapshot_and_replay_before_delivery():
    async def run():
        ws = VirtualWebSocket()
        await ws.accept()
        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="c",
            websocket=ws,
            close_controller=Controllers().close,
        )
        lease._retain('{"private":"frame"}')
        attachment = lease.attach(recovery=True)
        await lease.release("revoked")
        with pytest.raises(LeaseReleased):
            await attachment.next_text(timeout=1)

    asyncio.run(run())


def test_v1_detached_expiry_still_releases_controller_after_gap():
    async def run():
        ws = VirtualWebSocket()
        await ws.accept()
        lease = SessionLease(
            device_id="device",
            profile="default",
            controller_id="c",
            websocket=ws,
            close_controller=Controllers().close,
            limits=LeaseLimits(max_events=1, detach_ttl_seconds=0.02),
        )
        lease.start()
        attachment = lease.attach(recovery=True)
        attachment.detach()
        lease._retain('{"id":1}')
        lease._retain('{"id":2}')
        assert not lease.released
        await asyncio.wait_for(lease._release_done.wait(), 2)
        assert lease.release_reason == "expired"
        assert lease.last_seq == 2

    asyncio.run(run())
