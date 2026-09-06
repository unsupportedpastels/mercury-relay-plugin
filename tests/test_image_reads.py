from __future__ import annotations

import asyncio
import base64
import json
import os

import pytest
from conftest import contract_import

from mercury_relay_plugin.session_reads import SessionReads, SessionReadsError

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="image reads require POSIX descriptor-relative opens"
)

PNG = b"\x89PNG\r\n\x1a\n" + b"synthetic image fixture"


@pytest.fixture
def image_host(tmp_path, monkeypatch):
    profiles = contract_import("hermes_cli.profiles")
    contract_import("hermes_cli.web_routers.files")
    root = tmp_path / "managed"
    root.mkdir()
    home = tmp_path / "profile"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(root))
    monkeypatch.setattr(profiles, "get_profile_dir", lambda profile: home / profile)
    (home / "default").mkdir()
    path = root / "image.png"
    path.write_bytes(PNG)
    reads = SessionReads(
        profile_authorizer=lambda profile: profile in {"default", "deleted"},
        status_snapshot=lambda: {"runtime": "ready"},
    )
    return reads, path


def dispatch(reads, params):
    return asyncio.run(reads.dispatch("relay.image.read", params))


def test_image_read_and_advertised_byte_bound(image_host):
    reads, path = image_host
    status = asyncio.run(reads.dispatch("relay.status", {}))
    capability = status["capabilities"]["image_read"]
    assert capability["method"] == "relay.image.read"
    result = dispatch(reads, {"profile": "default", "path": str(path)})
    assert result == {"mime_type": "image/png", "size": len(PNG),
                      "base64": base64.b64encode(PNG).decode()}
    cap = capability["max_bytes"]
    path.write_bytes(PNG + b"x" * (cap - len(PNG)))
    result = dispatch(reads, {"profile": "default", "path": str(path)})
    assert result["size"] == cap
    response = json.dumps({"jsonrpc": "2.0", "id": "\x01" * 128, "result": result},
                          separators=(",", ":")).encode()
    from mercury_relay_plugin.framing import Reassembler, encode_message
    from mercury_relay_plugin.session_lease import LeaseLimits
    assert len(response) < LeaseLimits().max_event_bytes
    frames = encode_message(b"c" * 16, b"m" * 16, response)
    decoder = Reassembler(channel_id=b"c" * 16)
    assert [decoded for frame in frames if (decoded := decoder.push(frame))] == [response]
    path.write_bytes(PNG + b"x" * (cap + 1 - len(PNG)))
    with pytest.raises(SessionReadsError, match="^response_too_large$"):
        dispatch(reads, {"profile": "default", "path": str(path)})


@pytest.mark.parametrize("changes,reason", [
    ({"profile": "../outside"}, "profile_not_available"),
    ({"profile": "unauthorized"}, "profile_not_available"),
    ({"profile": "deleted"}, "profile_not_available"),
    ({"profile": None}, "profile_not_available"),
    ({"profile": []}, "profile_not_available"),
    ({"path": None}, "invalid_params"),
    ({"path": []}, "invalid_params"),
    ({"path": ""}, "invalid_params"),
    ({"path": "relative.png"}, "invalid_params"),
    ({"path": "/tmp/../image.png"}, "invalid_params"),
    ({"path": "https://example.com/image.png"}, "invalid_params"),
    ({"path": "file:///tmp/image.png"}, "invalid_params"),
    ({"path": "//server/image.png"}, "invalid_params"),
    ({"path": "/tmp/\x00image.png"}, "invalid_params"),
    ({"path": "/tmp/\ud800.png"}, "invalid_params"),
    ({"path": "/" + "x" * 4096}, "invalid_params"),
    ({"max_bytes": 9999999}, "invalid_params"),
    ({"auth_identity": "owner"}, "invalid_params"),
])
def test_invalid_image_params(image_host, changes, reason):
    reads, path = image_host
    params = {"profile": "default", "path": str(path), **changes}
    with pytest.raises(SessionReadsError, match=f"^{reason}$"):
        dispatch(reads, params)


@pytest.mark.parametrize("name", [
    ".env.png", ".ENV.png", "mcp-tokens/image.png", "PAIRING/image.png",
    "auth.json", "config.yaml", "bad.png", "image.svg", "directory.png", "pipe.png",
])
def test_sensitive_nonimage_and_nonregular_paths(image_host, name):
    import os

    reads, path = image_host
    target = path.parent / name
    target.parent.mkdir(exist_ok=True)
    if name == "directory.png":
        target.mkdir()
    elif name == "pipe.png":
        os.mkfifo(target)
    else:
        target.write_bytes(b"not an image" if name == "bad.png" else PNG)
    with pytest.raises(SessionReadsError, match="^image_not_available$"):
        dispatch(reads, {"profile": "default", "path": str(target)})


def test_root_containment_aliases_and_unlocked_tmp(image_host, monkeypatch):
    reads, path = image_host
    outside = path.parent.parent / "outside.png"
    outside.write_bytes(PNG)
    alias = path.parent / "alias.png"
    alias.symlink_to(outside)
    sensitive = path.parent / ".env.png"
    sensitive.symlink_to(path)
    secret = path.parent / "auth.json"
    secret.write_bytes(PNG)
    disguised = path.parent / "disguised.png"
    disguised.symlink_to(secret)
    for denied in (outside, alias, sensitive, disguised, path.parent / "missing.png"):
        with pytest.raises(SessionReadsError, match="^image_not_available$"):
            dispatch(reads, {"profile": "default", "path": str(denied)})
    monkeypatch.delenv("HERMES_DASHBOARD_FILES_ROOT")
    assert dispatch(reads, {"profile": "default", "path": str(outside)})["size"] == len(PNG)


def test_missing_policy_hides_capability_and_denies_reads(image_host, monkeypatch):
    import hermes_cli.web_server_files as policy

    reads, path = image_host
    monkeypatch.delattr(policy, "_managed_files_policy")
    status = asyncio.run(reads.dispatch("relay.status", {}))
    assert "image_read" not in status.get("capabilities", {})
    with pytest.raises(SessionReadsError, match="^reads_unavailable$"):
        dispatch(reads, {"profile": "default", "path": str(path)})


def test_read_does_not_create_managed_root(image_host, monkeypatch):
    reads, path = image_host
    missing = path.parent / "not-created"
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(missing))
    with pytest.raises(SessionReadsError, match="^image_not_available$"):
        dispatch(reads, {"profile": "default", "path": str(path)})
    assert not missing.exists()


def test_encrypted_image_read_and_current_device_authorization(image_host, tmp_path):
    import hashlib
    import secrets

    from test_admission import _handshake, _runtime

    from mercury_relay_plugin.admission import (
        AdmissionRejected,
        DeviceAdmissionService,
        controller_auth_payload,
    )
    from mercury_relay_plugin.authorization import AuthorizationRepository
    from mercury_relay_plugin.config import profile_paths
    from mercury_relay_plugin.framing import Reassembler, encode_message
    from mercury_relay_plugin.secure_channel import NoiseChannel

    async def exercise():
        reads, path = image_host
        root = tmp_path / "relay"
        root.mkdir()
        repository = AuthorizationRepository(profile_paths(explicit_path=root))
        runtime = _runtime()
        await runtime.start()
        service = DeviceAdmissionService(
            repository, runtime, profile="default", session_reads=reads
        )
        offer = repository.create_offer()
        key = secrets.token_bytes(32)

        def channels(payload=b""):
            mobile = NoiseChannel.initiator(
                static_private_key=key, installation_id=offer.installation_id,
                remote_static_public_key=offer.host_public_key,
            )
            host = service.new_host_channel()
            _handshake(mobile, host, final_payload=payload)
            return mobile, host

        mobile, host = channels(offer.capability)
        pending = service.complete_pairing(host, offer.capability)
        mobile2, host2 = channels()
        auth = controller_auth_payload(device_id=pending.device_id, profile="default")
        with pytest.raises(AdmissionRejected, match="device_not_authorized"):
            await service.open_controller(host2, mobile2.encrypt(auth))
        repository.approve(pending.device_id, hashlib.sha256(host.channel_binding).digest())
        mobile, host = channels()
        admitted = await service.open_controller(host, mobile.encrypt(auth))
        channel_id = host.channel_binding[:16]
        transport = service.bind_controller(admitted, channel_id=channel_id)

        async def receive():
            decoder = Reassembler(channel_id=channel_id)
            result = None
            for ciphertext in await transport.next_ciphertexts(timeout=2):
                result = decoder.push(mobile.decrypt(ciphertext))
            return json.loads(result)

        async def send(params, request_id="img-1"):
            request = {"jsonrpc": "2.0", "id": request_id, "method": "relay.image.read",
                       "params": params}
            for frame in encode_message(channel_id, secrets.token_bytes(16),
                                        json.dumps(request).encode()):
                await transport.feed_ciphertext(mobile.encrypt(frame))
            return await receive()

        assert (await receive())["method"] == "relay.lease.attached"
        response = await send({"profile": "default", "path": str(path)})
        assert base64.b64decode(response["result"]["base64"], validate=True) == PNG
        from mercury_relay_plugin.image_reads import MAX_IMAGE_BYTES

        at_cap = PNG + b"x" * (MAX_IMAGE_BYTES - len(PNG))
        path.write_bytes(at_cap)
        response = await send({"profile": "default", "path": str(path)}, "\x01" * 128)
        assert base64.b64decode(response["result"]["base64"], validate=True) == at_cap
        assert admitted.lease.last_seq == 0
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(admitted.lease.websocket.receive_text(), timeout=0.05)
        failure = await send({"profile": "unauthorized", "path": str(path)})
        assert failure["error"]["message"] == "profile_not_available"
        # Revoke during the awaited read, without relying on service teardown.
        real_dispatch = reads.dispatch
        calls = []

        async def revoke_during_read(method, params):
            calls.append(method)
            result = await real_dispatch(method, params)
            repository.revoke(pending.device_id)
            return result

        reads.dispatch = revoke_during_read
        denied = await send({"profile": "default", "path": str(path)})
        assert denied["error"] == {"code": -32000, "message": "device_not_authorized"}
        # Subsequent unauthorized requests cannot reach the file reader at all.
        denied = await send({"profile": "default", "path": str(path)})
        assert denied["error"] == {"code": -32000, "message": "device_not_authorized"}
        assert calls == ["relay.image.read"]
        transport.close()
        await service.leases.release_device(pending.device_id, reason="test_done")
        await runtime.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("fields", [
    {"id": None}, {"id": True}, {"id": ""}, {"id": "x" * 129},
    {"id": 2**63}, {"id": -(2**63) - 1}, {"id": "\ud800"},
    {"jsonrpc": "1.0"}, {"extra": "no"}, {"params": []},
])
def test_image_request_envelope_is_bounded_before_dispatch(fields):
    from mercury_relay_plugin.session_lease import SessionLease, SessionLeaseError
    from mercury_relay_plugin.virtual_ws import VirtualWebSocket

    async def exercise():
        called = []

        async def read(method, params):
            called.append((method, params))
            return {}

        async def close(_):
            return True

        ws = VirtualWebSocket()
        await ws.accept()
        lease = SessionLease(device_id="d", profile="default", controller_id="c", websocket=ws,
                             close_controller=close, read_dispatcher=read)
        lease.start()
        attachment = lease.attach(0)
        request = {"jsonrpc": "2.0", "id": "i", "method": "relay.image.read", "params": {},
                   **fields}
        with pytest.raises(SessionLeaseError, match="^invalid_read_request$"):
            await attachment.feed_text(json.dumps(request))
        assert called == []
        await lease.release("test_done")

    asyncio.run(exercise())


@pytest.mark.parametrize("params", [{}, {"path": "/tmp/x.png"}, {"profile": "default"}, []])
def test_required_image_params(image_host, params):
    with pytest.raises(SessionReadsError, match="^invalid_params$"):
        dispatch(image_host[0], params)


@pytest.mark.parametrize("suffix,data,mime", [
    (".jpeg", b"\xff\xd8\xff" + b"fixture", "image/jpeg"),
    (".gif", b"GIF89a" + b"fixture", "image/gif"),
    (".webp", b"RIFF1234WEBPfixture", "image/webp"),
    (".bmp", b"BMfixture", "image/bmp"),
])
def test_advertised_raster_types_require_matching_signature(image_host, suffix, data, mime):
    reads, path = image_host
    target = path.with_suffix(suffix)
    target.write_bytes(data)
    assert dispatch(reads, {"profile": "default", "path": str(target)})["mime_type"] == mime
    target.write_bytes(PNG)
    with pytest.raises(SessionReadsError, match="^image_not_available$"):
        dispatch(reads, {"profile": "default", "path": str(target)})


def test_real_profile_directory_resolution(tmp_path, monkeypatch):
    profiles = contract_import("hermes_cli.profiles")
    contract_import("hermes_cli.web_routers.files")
    root = tmp_path / "hermes"
    profile = root / "profiles" / "researcher"
    profile.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(root))
    assert profiles.get_profile_dir("researcher") == profile
    image = profile / "sample.png"
    image.write_bytes(PNG)
    reads = SessionReads(profile_authorizer=lambda p: p == "researcher")
    assert dispatch(reads, {"profile": "researcher", "path": str(image)})["size"] == len(PNG)
    image.unlink()
    profile.rmdir()
    with pytest.raises(SessionReadsError, match="^profile_not_available$"):
        dispatch(reads, {"profile": "researcher", "path": str(image)})


def test_symlink_swap_after_policy_resolution_is_denied(image_host, monkeypatch):
    from mercury_relay_plugin import image_reads

    reads, path = image_host
    real_read = image_reads._read_regular
    outside = path.parent.parent / "outside.png"
    outside.write_bytes(PNG)

    def swap(target):
        target.unlink()
        target.symlink_to(outside)
        return real_read(target)

    monkeypatch.setattr(image_reads, "_read_regular", swap)
    with pytest.raises(SessionReadsError, match="^image_not_available$"):
        dispatch(reads, {"profile": "default", "path": str(path)})