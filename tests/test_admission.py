from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import secrets
import sys
from pathlib import Path

import pytest
from conftest import contract_import

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.admission import (  # noqa: E402
    AdmissionRejected,
    DeviceAdmissionService,
    controller_auth_payload,
)
from mercury_relay_plugin.authorization import (  # noqa: E402
    AuthorizationRepository,
    PairingRejected,
)
from mercury_relay_plugin.config import profile_paths  # noqa: E402
from mercury_relay_plugin.framing import Reassembler, encode_message  # noqa: E402
from mercury_relay_plugin.method_policy import MethodPolicyRejected  # noqa: E402
from mercury_relay_plugin.runtime import RelayRuntime  # noqa: E402
from mercury_relay_plugin.secure_channel import NoiseChannel  # noqa: E402


async def compatible_handle_ws(ws, *, auth_identity=None) -> None:
    del ws, auth_identity


class FakeBridge:
    def __init__(self, websocket) -> None:
        self.websocket = websocket
        self.started = 0
        self.closed = 0

    async def start(self) -> None:
        self.started += 1

    async def close(self) -> None:
        self.closed += 1


def _handshake(
    mobile: NoiseChannel,
    host: NoiseChannel,
    *,
    final_payload: bytes,
) -> bytes:
    assert host.read_handshake(mobile.write_handshake()) == b""
    assert mobile.read_handshake(host.write_handshake()) == b""
    delivered = host.read_handshake(mobile.write_handshake(final_payload))
    assert delivered == final_payload
    return delivered


def _runtime() -> RelayRuntime:
    return RelayRuntime(
        loader=lambda: compatible_handle_ws,
        bridge_factory=lambda websocket: FakeBridge(websocket),
        id_factory=lambda: "synthetic-controller",
        profile_authorizer=lambda profile: profile in {"default", "researcher"},
    )


def test_approved_noise_identity_obtains_one_policy_gated_controller(tmp_path: Path) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")

        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)
        pairing_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        pairing_host = service.new_host_channel()
        capability = _handshake(
            pairing_mobile,
            pairing_host,
            final_payload=offer.capability,
        )
        pending = service.complete_pairing(pairing_host, capability)
        assert pending.status == "pending"
        repository.approve(
            pending.device_id,
            hashlib.sha256(pairing_host.channel_binding).digest(),
        )

        reconnect_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        reconnect_host = service.new_host_channel()
        assert _handshake(reconnect_mobile, reconnect_host, final_payload=b"") == b""
        encrypted_auth = reconnect_mobile.encrypt(
            controller_auth_payload(device_id=pending.device_id, profile="default")
        )
        admitted = await service.open_controller(reconnect_host, encrypted_auth)
        assert admitted.device_id == pending.device_id
        assert admitted.lease.profile == "default"
        assert admitted.lease.websocket.max_queue_bytes > 0
        assert runtime.snapshot()["active_controllers"] == 1
        with pytest.raises(MethodPolicyRejected, match="method_not_allowed"):
            await admitted.lease.websocket.feed_json(
                {"jsonrpc": "2.0", "id": "x", "method": "config.get", "params": {}}
            )

        with pytest.raises(AdmissionRejected, match="channel_already_admitted"):
            await service.open_controller(reconnect_host, encrypted_auth)

        await service.close()
        await runtime.close()
        assert runtime.snapshot()["active_controllers"] == 0

    asyncio.run(exercise())


def test_unapproved_or_wrong_pairing_capability_cannot_open_controller(tmp_path: Path) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")

        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)
        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        wrong = bytes([offer.capability[0] ^ 1]) + offer.capability[1:]
        delivered = _handshake(mobile, host, final_payload=wrong)
        with pytest.raises(PairingRejected, match="pairing rejected"):
            service.complete_pairing(host, delivered)
        assert host.closed
        assert repository.list_devices() == []

        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        pending = service.complete_pairing(
            host,
            _handshake(mobile, host, final_payload=offer.capability),
        )

        reconnect_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        reconnect_host = service.new_host_channel()
        _handshake(reconnect_mobile, reconnect_host, final_payload=b"")
        encrypted_auth = reconnect_mobile.encrypt(
            controller_auth_payload(device_id=pending.device_id, profile="default")
        )
        with pytest.raises(AdmissionRejected, match="device_not_authorized"):
            await service.open_controller(reconnect_host, encrypted_auth)
        assert reconnect_host.closed
        assert runtime.snapshot()["active_controllers"] == 0
        await runtime.close()

    asyncio.run(exercise())


def test_controller_auth_envelope_can_select_an_authorized_bot_profile(tmp_path: Path) -> None:
    payload = controller_auth_payload(device_id="fixture-device", profile="default")
    assert b"fixture-device" in payload

    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)
        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        pending = service.complete_pairing(
            host,
            _handshake(mobile, host, final_payload=offer.capability),
        )
        repository.approve(pending.device_id, hashlib.sha256(host.channel_binding).digest())

        reconnect_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        reconnect_host = service.new_host_channel()
        _handshake(reconnect_mobile, reconnect_host, final_payload=b"")
        bot_profile = reconnect_mobile.encrypt(
            controller_auth_payload(device_id=pending.device_id, profile="researcher")
        )
        admitted = await service.open_controller(reconnect_host, bot_profile)
        assert admitted.lease.profile == "researcher"
        raw = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "default-chat",
                "method": "session.create",
                "params": {"profile": "default"},
            }
        )
        await admitted.lease.websocket.feed_text(raw)
        assert await admitted.lease.websocket.receive_text() == raw
        assert runtime.snapshot()["active_controllers"] == 1
        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_stolen_device_id_cannot_replace_the_approved_noise_identity(tmp_path: Path) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()

        approved_private = secrets.token_bytes(32)
        mobile = NoiseChannel.initiator(
            static_private_key=approved_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        pending = service.complete_pairing(
            host,
            _handshake(mobile, host, final_payload=offer.capability),
        )
        repository.approve(pending.device_id, hashlib.sha256(host.channel_binding).digest())

        attacker = NoiseChannel.initiator(
            static_private_key=secrets.token_bytes(32),
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        attacker_host = service.new_host_channel()
        _handshake(attacker, attacker_host, final_payload=b"")
        stolen_id = attacker.encrypt(
            controller_auth_payload(device_id=pending.device_id, profile="default")
        )
        with pytest.raises(AdmissionRejected, match="device_not_authorized"):
            await service.open_controller(attacker_host, stolen_id)
        assert attacker_host.closed
        assert runtime.snapshot()["active_controllers"] == 0
        await runtime.close()

    asyncio.run(exercise())


def test_concurrent_admission_publishes_one_controller_without_closing_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)

        pairing_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        pairing_host = service.new_host_channel()
        pending = service.complete_pairing(
            pairing_host,
            _handshake(pairing_mobile, pairing_host, final_payload=offer.capability),
        )
        repository.approve(
            pending.device_id,
            hashlib.sha256(pairing_host.channel_binding).digest(),
        )

        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        _handshake(mobile, host, final_payload=b"")
        first_envelope = mobile.encrypt(
            controller_auth_payload(device_id=pending.device_id, profile="default")
        )
        second_envelope = mobile.encrypt(
            controller_auth_payload(device_id=pending.device_id, profile="default")
        )

        original_open = runtime.open_controller
        entered = 0
        first_entered = asyncio.Event()
        release = asyncio.Event()

        async def delayed_open(*, profile):
            nonlocal entered
            entered += 1
            first_entered.set()
            await release.wait()
            return await original_open(profile=profile)

        monkeypatch.setattr(runtime, "open_controller", delayed_open)
        first = asyncio.create_task(service.open_controller(host, first_envelope))
        await first_entered.wait()
        second = asyncio.create_task(service.open_controller(host, second_envelope))
        await asyncio.sleep(0)
        assert entered == 1
        release.set()
        admitted = await first
        with pytest.raises(AdmissionRejected, match="channel_already_admitted"):
            await second
        assert admitted.channel is host
        assert not host.closed
        assert runtime.snapshot()["active_controllers"] == 1
        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_authenticated_device_gets_a_real_hermes_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract_import("tui_gateway.ws")

    async def exercise() -> None:
        root = tmp_path / "hermes"
        (root / "profiles" / "researcher").mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(root))
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = RelayRuntime(max_controllers=1, id_factory=lambda: "real-controller")
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)

        pairing_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        pairing_host = service.new_host_channel()
        pending = service.complete_pairing(
            pairing_host,
            _handshake(pairing_mobile, pairing_host, final_payload=offer.capability),
        )
        repository.approve(
            pending.device_id,
            hashlib.sha256(pairing_host.channel_binding).digest(),
        )

        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        _handshake(mobile, host, final_payload=b"")
        admitted = await service.open_controller(
            host,
            mobile.encrypt(controller_auth_payload(device_id=pending.device_id, profile="default")),
        )
        channel_id = bytes.fromhex("a1" * 16)
        transport = service.bind_controller(admitted, channel_id=channel_id)

        async def send_json(value: dict, message_byte: int) -> None:
            raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
            for record in encode_message(channel_id, bytes([message_byte]) * 16, raw):
                await transport.feed_ciphertext(mobile.encrypt(record))

        async def next_json(request_id: str | None = None) -> dict:
            for _ in range(20):
                reassembler = Reassembler(channel_id=channel_id)
                payload = None
                for ciphertext in await transport.next_ciphertexts(timeout=2.0):
                    payload = reassembler.push(mobile.decrypt(ciphertext))
                assert payload is not None
                frame = json.loads(payload.decode())
                if request_id is None or frame.get("id") == request_id:
                    return frame
            raise AssertionError("expected encrypted Hermes response not received")

        try:
            status = await next_json()
            assert status["method"] == "relay.lease.attached"
            assert status["params"]["replay_gap"] is False
            ready = await next_json()
            assert ready["params"]["type"] == "gateway.ready"
            await send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "create-authenticated",
                    "method": "session.create",
                    "params": {"profile": "researcher", "source": "mercury"},
                },
                1,
            )
            frame = await next_json("create-authenticated")
            assert frame["result"]["session_id"]
            assert frame["result"]["stored_session_id"]
            assert frame["result"]["info"]["profile_name"] == "researcher"

            from tui_gateway import server

            def emit_prompt_delta(request_id, params):
                server._emit(
                    "message.delta",
                    params["session_id"],
                    {"text": " leading encrypted delta"},
                )
                return server._ok(request_id, {"accepted": True})

            monkeypatch.setitem(server._methods, "prompt.submit", emit_prompt_delta)
            await send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "prompt-authenticated",
                    "method": "prompt.submit",
                    "params": {
                        "session_id": frame["result"]["session_id"],
                        "text": "fixture",
                    },
                },
                2,
            )
            delta = await next_json()
            assert delta["params"]["type"] == "message.delta"
            assert delta["params"]["payload"]["text"] == " leading encrypted delta"
            accepted = await next_json("prompt-authenticated")
            assert accepted["result"]["accepted"] is True

            await send_json(
                {
                    "jsonrpc": "2.0",
                    "id": "close-authenticated",
                    "method": "session.close",
                    "params": {"session_id": frame["result"]["session_id"]},
                },
                3,
            )
            closed = await next_json("close-authenticated")
            assert closed["result"]["closed"] is True
        finally:
            transport.close()
            await service.close()
            await runtime.close()

    asyncio.run(exercise())


def _paired_and_approved(service, repository):
    offer = repository.create_offer()
    mobile_private = secrets.token_bytes(32)
    pairing_mobile = NoiseChannel.initiator(
        static_private_key=mobile_private,
        installation_id=offer.installation_id,
        remote_static_public_key=offer.host_public_key,
    )
    pairing_host = service.new_host_channel()
    pending = service.complete_pairing(
        pairing_host,
        _handshake(pairing_mobile, pairing_host, final_payload=offer.capability),
    )
    repository.approve(
        pending.device_id,
        hashlib.sha256(pairing_host.channel_binding).digest(),
    )
    return offer, mobile_private, pending


async def _admit(service, offer, mobile_private, device_id, *, resume_cursor=None):
    mobile = NoiseChannel.initiator(
        static_private_key=mobile_private,
        installation_id=offer.installation_id,
        remote_static_public_key=offer.host_public_key,
    )
    host = service.new_host_channel()
    _handshake(mobile, host, final_payload=b"")
    envelope = mobile.encrypt(
        controller_auth_payload(device_id=device_id, profile="default", resume_cursor=resume_cursor)
    )
    return mobile, host, await service.open_controller(host, envelope)


def test_fresh_reconnect_reattaches_the_retained_lease_after_a_cursor(tmp_path: Path) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer, mobile_private, pending = _paired_and_approved(service, repository)

        _mobile, _host, admitted = await _admit(service, offer, mobile_private, pending.device_id)
        assert runtime.snapshot()["active_controllers"] == 1
        event = '{"jsonrpc":"2.0","method":"event","params":{"n":1}}'
        await admitted.lease.websocket.send_text(event)
        await asyncio.sleep(0.01)

        # Outer transport loss: detach only; the running controller survives.
        admitted.attachment.detach()
        assert runtime.snapshot()["active_controllers"] == 1

        _mobile2, _host2, resumed = await _admit(
            service, offer, mobile_private, pending.device_id, resume_cursor=0
        )
        assert resumed.lease is admitted.lease
        assert runtime.snapshot()["active_controllers"] == 1
        status = json.loads(await resumed.attachment.next_text(timeout=0.5))
        assert status["method"] == "relay.lease.attached"
        assert status["params"]["replay_gap"] is False
        assert await resumed.attachment.next_text(timeout=0.5) == event

        # A fresh open without a cursor supersedes the retained lease.
        resumed.attachment.detach()
        _mobile3, _host3, fresh = await _admit(service, offer, mobile_private, pending.device_id)
        assert fresh.lease is not admitted.lease
        assert admitted.lease.released
        assert admitted.lease.release_reason == "superseded"
        assert runtime.snapshot()["active_controllers"] == 1

        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_reattach_without_a_retained_lease_is_rejected(tmp_path: Path) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer, mobile_private, pending = _paired_and_approved(service, repository)

        with pytest.raises(AdmissionRejected, match="lease_not_available"):
            await _admit(service, offer, mobile_private, pending.device_id, resume_cursor=0)
        assert runtime.snapshot()["active_controllers"] == 0
        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_revoked_device_loses_its_live_lease_and_cannot_readmit(tmp_path: Path) -> None:
    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer, mobile_private, pending = _paired_and_approved(service, repository)

        _mobile, _host, admitted = await _admit(service, offer, mobile_private, pending.device_id)
        assert runtime.snapshot()["active_controllers"] == 1

        summary = await service.revoke_device(pending.device_id)
        assert summary is not None
        assert summary.status == "revoked"
        assert admitted.lease.released
        assert admitted.lease.release_reason == "revoked"
        assert runtime.snapshot()["active_controllers"] == 0

        # Neither a reattach nor a fresh admission survives the revoke.
        with pytest.raises(AdmissionRejected, match="device_not_authorized"):
            await _admit(service, offer, mobile_private, pending.device_id, resume_cursor=0)
        with pytest.raises(AdmissionRejected, match="device_not_authorized"):
            await _admit(service, offer, mobile_private, pending.device_id)
        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_runtime_failure_or_cancellation_closes_authenticated_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def channel_for(service, identity, mobile_private):
        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=identity.installation_id,
            remote_static_public_key=identity.public_key,
        )
        host = service.new_host_channel()
        _handshake(mobile, host, final_payload=b"")
        envelope = mobile.encrypt(
            controller_auth_payload(device_id="fixture-device", profile="default")
        )
        return host, envelope

    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        identity = repository.identity_store.load_or_create()
        monkeypatch.setattr(repository, "is_authorized", lambda *_args: True)
        # Admission now binds retained recovery to an authorization generation.
        from types import SimpleNamespace

        monkeypatch.setattr(
            repository,
            "list_devices",
            lambda: [SimpleNamespace(device_id="fixture-device", status="authorized", epoch=0)],
        )

        async def fail_open(*, profile):
            del profile
            raise RuntimeError("private runtime detail")

        monkeypatch.setattr(runtime, "open_controller", fail_open)
        host, envelope = await channel_for(service, identity, secrets.token_bytes(32))
        with pytest.raises(AdmissionRejected, match="runtime_unavailable") as caught:
            await service.open_controller(host, envelope)
        assert "private" not in str(caught.value)
        assert host.closed

        async def cancel_open(*, profile):
            del profile
            raise asyncio.CancelledError

        monkeypatch.setattr(runtime, "open_controller", cancel_open)
        host, envelope = await channel_for(service, identity, secrets.token_bytes(32))
        with pytest.raises(asyncio.CancelledError):
            await service.open_controller(host, envelope)
        assert host.closed
        await runtime.close()

    asyncio.run(exercise())


def test_one_device_holds_one_lease_per_channel(tmp_path: Path) -> None:
    """A phone opens several sessions at once: one lease per named channel.

    Re-opening a channel supersedes only that channel; the legacy envelope with
    no channel supersedes only the default channel; revocation releases all.
    """

    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        controllers = iter(f"controller-{index}" for index in range(10))
        runtime = RelayRuntime(
            loader=lambda: compatible_handle_ws,
            bridge_factory=lambda websocket: FakeBridge(websocket),
            id_factory=lambda: next(controllers),
            profile_authorizer=lambda profile: profile == "default",
        )
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")

        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)
        pairing_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        pairing_host = service.new_host_channel()
        capability = _handshake(pairing_mobile, pairing_host, final_payload=offer.capability)
        pending = service.complete_pairing(pairing_host, capability)
        repository.approve(pending.device_id, hashlib.sha256(pairing_host.channel_binding).digest())

        async def admit(channel: str | None):
            mobile = NoiseChannel.initiator(
                static_private_key=mobile_private,
                installation_id=offer.installation_id,
                remote_static_public_key=offer.host_public_key,
            )
            host = service.new_host_channel()
            _handshake(mobile, host, final_payload=b"")
            envelope = mobile.encrypt(
                controller_auth_payload(
                    device_id=pending.device_id, profile="default", channel=channel
                )
            )
            return await service.open_controller(host, envelope)

        first = await admit("sess-a")
        second = await admit("sess-b")
        legacy = await admit(None)
        assert first.lease is not second.lease is not legacy.lease
        assert first.lease_channel == "sess-a"
        assert legacy.lease_channel == ""
        assert runtime.snapshot()["active_controllers"] == 3
        assert {lease.channel for lease in service.leases.leases_for(pending.device_id)} == {
            "sess-a",
            "sess-b",
            "",
        }

        # Re-opening one channel supersedes only that channel.
        replacement = await admit("sess-a")
        assert first.lease.released and first.lease.release_reason == "superseded"
        assert not second.lease.released and not legacy.lease.released
        assert replacement.lease.channel == "sess-a"
        assert runtime.snapshot()["active_controllers"] == 3

        # A legacy open supersedes only the default channel.
        legacy_again = await admit(None)
        assert legacy.lease.released and legacy.lease.release_reason == "superseded"
        assert not second.lease.released and not replacement.lease.released
        assert runtime.snapshot()["active_controllers"] == 3

        # Revocation releases every channel the device holds.
        await service.revoke_device(pending.device_id)
        assert second.lease.released and replacement.lease.released and legacy_again.lease.released
        assert service.leases.leases_for(pending.device_id) == []
        assert runtime.snapshot()["active_controllers"] == 0

        await service.close()
        await runtime.close()

    asyncio.run(exercise())


def test_channel_envelope_validation(tmp_path: Path) -> None:
    assert controller_auth_payload(device_id="d", profile="default") == (
        b'{"device_id":"d","profile":"default","type":"controller.open"}'
    )
    assert controller_auth_payload(device_id="d", profile="default", channel="s_1-A") == (
        b'{"channel":"s_1-A","device_id":"d","profile":"default","type":"controller.open"}'
    )
    for bad in ("", "has space", "x" * 65, "a/b", "ü"):
        with pytest.raises(ValueError):
            controller_auth_payload(device_id="d", profile="default", channel=bad)

    async def rejects(plaintext: bytes) -> None:
        root = tmp_path / f"hermes-{secrets.token_hex(2)}"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)
        pairing_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        pairing_host = service.new_host_channel()
        capability = _handshake(pairing_mobile, pairing_host, final_payload=offer.capability)
        pending = service.complete_pairing(pairing_host, capability)
        repository.approve(pending.device_id, hashlib.sha256(pairing_host.channel_binding).digest())
        mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        host = service.new_host_channel()
        _handshake(mobile, host, final_payload=b"")
        body = plaintext.replace(b"DEVICE", pending.device_id.encode())
        with pytest.raises(AdmissionRejected, match="invalid_auth_envelope"):
            await service.open_controller(host, mobile.encrypt(body))
        assert runtime.snapshot()["active_controllers"] == 0
        await service.close()
        await runtime.close()

    asyncio.run(
        rejects(b'{"channel":"","device_id":"DEVICE","profile":"default","type":"controller.open"}')
    )
    asyncio.run(
        rejects(
            b'{"channel":"a/b","device_id":"DEVICE","profile":"default","type":"controller.open"}'
        )
    )
    asyncio.run(
        rejects(b'{"channel":7,"device_id":"DEVICE","profile":"default","type":"controller.open"}')
    )


def test_device_names_itself_in_the_admission_envelope_even_while_pending(tmp_path: Path) -> None:
    """The approval probe carries the phone's name, so the dashboard shows it before approval."""

    async def exercise() -> None:
        root = tmp_path / "hermes"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(repository, runtime, profile="default")
        offer = repository.create_offer()
        mobile_private = secrets.token_bytes(32)
        pairing_mobile = NoiseChannel.initiator(
            static_private_key=mobile_private,
            installation_id=offer.installation_id,
            remote_static_public_key=offer.host_public_key,
        )
        pairing_host = service.new_host_channel()
        capability = _handshake(pairing_mobile, pairing_host, final_payload=offer.capability)
        pending = service.complete_pairing(pairing_host, capability)

        async def probe(name: str | None, key: bytes = mobile_private):
            mobile = NoiseChannel.initiator(
                static_private_key=key,
                installation_id=offer.installation_id,
                remote_static_public_key=offer.host_public_key,
            )
            host = service.new_host_channel()
            _handshake(mobile, host, final_payload=b"")
            envelope = controller_auth_payload(
                device_id=pending.device_id, profile="default", device_name=name
            )
            with contextlib.suppress(AdmissionRejected):
                await service.open_controller(host, mobile.encrypt(envelope))

        # Pending: admission is refused, but the self-reported name is kept.
        await probe("Mark's Fold")
        listed = {d.device_id: d for d in repository.list_devices()}
        assert listed[pending.device_id].device_name == "Mark's Fold"
        assert listed[pending.device_id].display_name == "Mark's Fold"
        assert listed[pending.device_id].status == "pending"

        # A stranger with the right device id but the wrong key cannot rename it.
        await probe("Attacker", key=secrets.token_bytes(32))
        assert {d.device_id: d for d in repository.list_devices()}[
            pending.device_id
        ].device_name == "Mark's Fold"

        # Owner nickname wins over the reported name; clearing it falls back.
        repository.set_label(pending.device_id, "  Kitchen  phone ")
        summary = {d.device_id: d for d in repository.list_devices()}[pending.device_id]
        assert summary.label == "Kitchen phone" and summary.display_name == "Kitchen phone"
        repository.set_label(pending.device_id, "")
        assert {d.device_id: d for d in repository.list_devices()}[
            pending.device_id
        ].display_name == "Mark's Fold"

        # Control characters and empty names are ignored, not stored.
        await probe("bad\x01name")
        await probe("   ")
        assert {d.device_id: d for d in repository.list_devices()}[
            pending.device_id
        ].device_name == "Mark's Fold"

        await service.close()
        await runtime.close()

    asyncio.run(exercise())
