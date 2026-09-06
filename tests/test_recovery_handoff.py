"""Authenticated reattach while the previous outer disconnect is delayed."""

import asyncio
import hashlib
import json
import secrets

import pytest
from test_admission import _handshake, _runtime

from mercury_relay_plugin.admission import (
    AdmissionRejected,
    DeviceAdmissionService,
    controller_auth_payload,
)
from mercury_relay_plugin.authorization import AuthorizationRepository
from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.controller_transport import ControllerTransportError
from mercury_relay_plugin.secure_channel import NoiseChannel
from mercury_relay_plugin.session_lease import LeaseLimits, SessionLeaseError


@pytest.mark.parametrize("gap", [False, True])
def test_authenticated_handoff_fences_delayed_disconnect_and_preserves_replay(tmp_path, gap):
    async def run():
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(
            repository,
            runtime,
            profile="default",
            lease_limits=LeaseLimits(max_events=2 if gap else 256),
        )
        offer = repository.create_offer()
        private = secrets.token_bytes(32)

        def channels(key=private):
            mobile = NoiseChannel.initiator(
                static_private_key=key,
                installation_id=offer.installation_id,
                remote_static_public_key=offer.host_public_key,
            )
            return mobile, service.new_host_channel()

        mobile, host = channels()
        paired = service.complete_pairing(
            host, _handshake(mobile, host, final_payload=offer.capability)
        )
        device = paired.device_id
        repository.approve(device, hashlib.sha256(host.channel_binding).digest())

        async def open_channel(
            *, profile="default", cursor=0, version=1, key=private, claimed_device=device
        ):
            mobile, host = channels(key)
            _handshake(mobile, host, final_payload=b"")
            return await service.open_controller(
                host,
                mobile.encrypt(
                    controller_auth_payload(
                        device_id=claimed_device,
                        profile=profile,
                        resume_cursor=cursor,
                        recovery_version=version,
                    )
                ),
            )

        try:
            first = await open_channel()
            lease = first.lease
            old_transport = service.bind_controller(first, channel_id=secrets.token_bytes(16))
            # Keep the original attachment live; no simulated disconnect before reattach.
            await first.attachment.next_text(timeout=1)  # attached
            await first.attachment.next_text(timeout=1)  # replay_complete
            lease._retain('{"id":1,"result":{"value":"one"}}')
            await first.attachment.next_text(timeout=1)
            lease._retain('{"id":2,"result":{"value":"two"}}')
            lease._retain('{"id":3,"result":{"value":"three"}}')
            projection = lease.recovery_projection
            projection.request(
                {"id": 10, "method": "session.create", "params": {"profile": "default"}}
            )
            projection.observe(
                '{"id":10,"result":{"session_id":"runtime","stored_session_id":"durable"}}'
            )
            projection.observe(
                '{"method":"event","params":{"session_id":"runtime",'
                '"type":"subagent.complete","payload":'
                '{"subagent_id":"unit-child","status":"completed"}}}'
            )
            snapshot = projection.snapshot()
            assert snapshot["task_snapshot"] and snapshot["bindings"]
            for kwargs, reason in [
                ({"key": secrets.token_bytes(32)}, "device_not_authorized"),
                ({"claimed_device": "another-device"}, "device_not_authorized"),
                ({"profile": "researcher"}, "lease_not_available"),
                ({"cursor": 4}, "lease_not_available"),
                ({"version": None}, "lease_not_available"),
                ({"cursor": None}, "lease_not_available"),
            ]:
                with pytest.raises(AdmissionRejected, match=reason):
                    await open_channel(**kwargs)
                assert not first.attachment.detached
                assert not lease.released

            second = await open_channel()
            assert second.lease is lease
            assert first.attachment.detached
            assert not second.attachment.detached
            assert runtime.snapshot()["active_controllers"] == 1
            # No draining even queued preamble/live data from the superseded outer socket.
            with pytest.raises(SessionLeaseError, match="attachment_replaced"):
                await first.attachment.next_text(timeout=1)
            with pytest.raises(SessionLeaseError, match="attachment_detached"):
                await first.attachment.feed_text('{"id":9,"method":"session.list","params":{}}')
            # Delayed old connection finally closes AFTER successful admission.
            old_transport.close(reason="connection_closed")
            first.attachment.detach(reason="late_cleanup")
            assert not second.attachment.detached
            assert not lease.released
            assert lease._expiry_task is None
            attached = json.loads(await second.attachment.next_text(timeout=1))["params"]
            assert attached["lease_id"] == lease.lease_id
            assert attached["replay_gap"] is gap
            assert attached["snapshot_through"] == 3
            assert attached["task_snapshot"] == snapshot["task_snapshot"]
            assert attached["bindings"] == snapshot["bindings"]
            seqs = []
            while True:
                frame = json.loads(await second.attachment.next_text(timeout=1))
                if frame["method"] == "relay.lease.replay_complete":
                    assert frame["params"]["last_seq"] == 3
                    break
                assert frame["params"]["replay"]
                seqs.append(frame["params"]["seq"])
            assert seqs == ([2, 3] if gap else [1, 2, 3])
            lease._retain('{"id":4,"result":{}}')
            live = json.loads(await second.attachment.next_text(timeout=1))["params"]
            assert live["seq"] == 4 and not live["replay"]
            with pytest.raises(ControllerTransportError, match="channel_closed"):
                await old_transport.next_ciphertexts()
            # A blocked old reader is woken by handoff, without old socket death.
            pending = asyncio.create_task(second.attachment.next_text())
            await asyncio.sleep(0)
            third = await open_channel(cursor=4)
            with pytest.raises(SessionLeaseError, match="attachment_replaced"):
                await asyncio.wait_for(pending, 1)
            second.attachment.detach(reason="late_cleanup")
            assert not third.attachment.detached
            # A retained controller from another authorization epoch is never adopted.
            lease.authorization_epoch -= 1
            reset = await open_channel(cursor=4)
            assert lease.released and lease.release_reason == "authorization_changed"
            assert reset.lease is not lease
            assert reset.lease.authorization_epoch == repository.list_devices()[0].epoch
            status = json.loads(await reset.attachment.next_text(timeout=1))["params"]
            assert status["recovery_reset"] and status["lease_id"] != lease.lease_id
            # Repository-only revocation also denies a fresh handshake before it can handoff.
            repository.revoke(device)
            with pytest.raises(AdmissionRejected, match="device_not_authorized"):
                await open_channel()
            assert not reset.attachment.detached
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())
