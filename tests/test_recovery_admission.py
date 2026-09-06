import asyncio
import hashlib
import json
import secrets

import pytest
from test_admission import _handshake, _runtime

from mercury_relay_plugin.admission import (
    AdmissionRejected,
    DeviceAdmissionService,
    _parse_controller_auth,
    controller_auth_payload,
)
from mercury_relay_plugin.authorization import AuthorizationRepository
from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.secure_channel import NoiseChannel


@pytest.mark.parametrize("version", [True, False, 0, 2, "1", None])
def test_recovery_version_rejects_unknown_or_ambiguous_values(version):
    with pytest.raises(AdmissionRejected):
        _parse_controller_auth(
            json.dumps(
                {
                    "type": "controller.open",
                    "device_id": "d",
                    "profile": "default",
                    "recovery_version": version,
                }
            ).encode()
        )


def test_real_noise_admission_recovery_revalidates_scope_and_restarts(tmp_path):
    async def run():
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()
        private = secrets.token_bytes(32)

        def channels(service):
            mobile = NoiseChannel.initiator(
                static_private_key=private,
                installation_id=offer.installation_id,
                remote_static_public_key=offer.host_public_key,
            )
            return mobile, service.new_host_channel()

        mobile, host = channels(service)
        service.complete_pairing(host, _handshake(mobile, host, final_payload=offer.capability))
        device = repository.list_devices()[0].device_id
        repository.approve(device, hashlib.sha256(host.channel_binding).digest())

        async def open_v1(service, profile="default", cursor=0):
            mobile, host = channels(service)
            _handshake(mobile, host, final_payload=b"")
            admitted = await service.open_controller(
                host,
                mobile.encrypt(
                    controller_auth_payload(
                        device_id=device, profile=profile, resume_cursor=cursor, recovery_version=1
                    )
                ),
            )
            return admitted, json.loads(await admitted.attachment.next_text())["params"]

        first, status = await open_v1(service)
        assert status["recovery_reset"] and status["recovery_version"] == 1
        replacement, _ = await open_v1(service)
        assert replacement.lease is first.lease
        assert first.attachment.detached
        first.attachment.detach()
        assert not replacement.attachment.detached
        replacement.attachment.detach()
        with pytest.raises(AdmissionRejected, match="lease_not_available"):
            await open_v1(service, profile="researcher")
        second, status2 = await open_v1(service)
        assert second.lease is first.lease
        assert status2["lease_id"] == status["lease_id"]
        assert not status2["recovery_reset"]
        second.attachment.detach()
        original = runtime._profile_authorizer
        runtime._profile_authorizer = lambda p: False
        with pytest.raises(AdmissionRejected, match="profile_not_available"):
            await open_v1(service)
        runtime._profile_authorizer = original
        projection = second.lease.recovery_projection
        projection.request({"id": 1, "method": "session.create", "params": {"profile": "default"}})
        projection.observe(
            '{"id":1,"result":{"session_id":"runtime","stored_session_id":"durable"}}'
        )
        projection.observe(
            '{"method":"event","params":{"session_id":"runtime","type":"subagent.complete","payload":{"subagent_id":"child","status":"completed"}}}'
        )
        await service.close()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        restarted, recovered = await open_v1(service)
        assert recovered["recovery_reset"]
        assert recovered["lease_id"] != status["lease_id"]
        assert recovered["task_snapshot"][0]["params"]["payload"]["status"] == "completed"
        assert recovered["task_snapshot"][0]["params"]["durable_session_id"] == "durable"
        assert recovered["task_snapshot"][0]["params"]["profile"] == "default"
        assert recovered["task_snapshot"][0]["params"]["relay_event_id"].startswith("projection:")
        assert not recovered["bindings"][0]["live"]
        durable_scope = (offer.installation_id.hex(), device, restarted.lease.authorization_epoch)
        assert service._store().snapshot(durable_scope, lambda p: True)[0]
        await service.revoke_device(device)
        assert restarted.lease.released
        with pytest.raises(AdmissionRejected, match="device_not_authorized"):
            await open_v1(service)
        assert service._store().snapshot(durable_scope, lambda p: True)[0] == []
        await service.close()
        await runtime.close()

    asyncio.run(run())
