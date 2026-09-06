from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import secrets
import sys
from pathlib import Path

import pytest
from conftest import contract_import

contract_import("fastapi")

from fastapi import Depends, FastAPI, HTTPException, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PLUGIN_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

PREFIX = "/api/plugins/mercury-relay"
ALL_ROUTES = [
    ("GET", f"{PREFIX}/status"),
    ("POST", f"{PREFIX}/pairing-offers"),
    ("GET", f"{PREFIX}/pairing-offers/some-offer"),
    ("GET", f"{PREFIX}/devices"),
    ("GET", f"{PREFIX}/devices/pending"),
    ("POST", f"{PREFIX}/devices/some-device/approve"),
    ("POST", f"{PREFIX}/devices/some-device/deny"),
    ("POST", f"{PREFIX}/devices/some-device/revoke"),
    ("GET", f"{PREFIX}/diagnostics"),
]


def _load_plugin_api():
    path = PLUGIN_ROOT / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("mercury_relay_test_management_api", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _compatible_handle_ws(ws, *, auth_identity=None) -> None:
    del ws, auth_identity


def _app(module) -> FastAPI:
    """Mount the router exactly as Hermes does: behind dashboard auth."""

    def require_dashboard_auth(request: Request) -> None:
        if request.headers.get("x-test-dashboard-auth") != "ok":
            raise HTTPException(status_code=401, detail="unauthenticated")

    app = FastAPI()
    app.include_router(
        module.router, prefix=PREFIX, dependencies=[Depends(require_dashboard_auth)]
    )
    return app


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "hermes"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    module = _load_plugin_api()
    module._runtime = module.RelayRuntime(loader=lambda: _compatible_handle_ws)
    return module, TestClient(_app(module))


AUTH = {"x-test-dashboard-auth": "ok"}


def test_every_route_requires_dashboard_auth_before_plugin_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _module, client = _client(tmp_path, monkeypatch)
    with client:
        for method, route in ALL_ROUTES:
            response = client.request(method, route)
            assert response.status_code == 401, route
        # Nothing executed: no pairing offer state was created.
        diagnostics = client.get(f"{PREFIX}/diagnostics", headers=AUTH).json()
        assert diagnostics["pairing_offer_status"] == "none"
        assert diagnostics["devices"]["total"] == 0


def test_pairing_offer_lifecycle_returns_capability_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _module, client = _client(tmp_path, monkeypatch)
    with client:
        created = client.post(
            f"{PREFIX}/pairing-offers", headers=AUTH, content=json.dumps({"ttl_seconds": 60})
        )
        assert created.status_code == 200
        offer = created.json()
        assert set(offer) == {
            "offer_id",
            "installation_id",
            "host_public_key",
            "expires_at",
            "capability",
            "relay_origin",
            "protocol_major",
            "pairing_payload",
            "pairing_token",
            "qr_svg",
        }
        assert offer["protocol_major"] == 1
        # MR-01: the QR carries a pairing-device routing token.
        assert isinstance(offer["pairing_token"], str)
        assert offer["pairing_token"].count(".") == 2
        assert json.loads(offer["pairing_payload"])["t"] == offer["pairing_token"]
        assert offer["qr_svg"] and "<svg" in offer["qr_svg"]
        assert offer["capability"] not in offer["qr_svg"]  # QR encodes it, not as text

        redacted = client.get(f"{PREFIX}/pairing-offers/{offer['offer_id']}", headers=AUTH)
        assert redacted.status_code == 200
        status = redacted.json()
        assert status["status"] == "active"
        assert "capability" not in status
        assert "capability_digest" not in status
        assert "host_public_key" not in status
        assert offer["capability"] not in redacted.text

        assert (
            client.get(f"{PREFIX}/pairing-offers/unknown-offer", headers=AUTH).status_code
            == 404
        )
        second = client.post(f"{PREFIX}/pairing-offers", headers=AUTH, content="{}")
        assert second.status_code == 409
        bad_body = client.post(
            f"{PREFIX}/pairing-offers", headers=AUTH, content=json.dumps({"surprise": 1})
        )
        assert bad_body.status_code == 400


def test_device_lifecycle_requires_full_sas_digest_and_redacts_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, client = _client(tmp_path, monkeypatch)
    with client:
        repository = module._admission.repository
        offer = repository.create_offer()
        device_key = secrets.token_bytes(32)
        binding = secrets.token_bytes(32)
        pending = repository.consume_offer(offer.capability, device_key, binding)

        listed = client.get(f"{PREFIX}/devices/pending", headers=AUTH).json()
        assert [d["device_id"] for d in listed["devices"]] == [pending.device_id]

        approve_url = f"{PREFIX}/devices/{pending.device_id}/approve"
        assert client.post(approve_url, headers=AUTH).status_code == 400
        wrong = base64.b64encode(secrets.token_bytes(32)).decode()
        rejected = client.post(
            approve_url, headers=AUTH, content=json.dumps({"channel_binding_digest": wrong})
        )
        assert rejected.status_code == 403

        digest = base64.b64encode(hashlib.sha256(binding).digest()).decode()
        approved = client.post(
            approve_url, headers=AUTH, content=json.dumps({"channel_binding_digest": digest})
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "authorized"
        assert approved.json()["capabilities"] == ["client"]
        assert module._admission.metrics.snapshot()["registered_devices"] == 1
        # Idempotent, verified by readback.
        again = client.post(
            approve_url, headers=AUTH, content=json.dumps({"channel_binding_digest": digest})
        )
        assert again.status_code == 200
        devices = client.get(f"{PREFIX}/devices", headers=AUTH).json()["devices"]
        assert devices[0]["status"] == "authorized"

        assert (
            client.post(f"{PREFIX}/devices/{pending.device_id}/deny", headers=AUTH).status_code
            == 409
        )
        revoked = client.post(f"{PREFIX}/devices/{pending.device_id}/revoke", headers=AUTH)
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"
        assert module._admission.metrics.snapshot()["registered_devices"] == 0
        assert (
            client.post(
                f"{PREFIX}/devices/{pending.device_id}/revoke", headers=AUTH
            ).status_code
            == 200
        )
        readback = client.get(f"{PREFIX}/devices", headers=AUTH).json()["devices"]
        assert readback[0]["status"] == "revoked"
        assert readback[0]["capabilities"] == []
        assert (
            client.post(f"{PREFIX}/devices/unknown-id/revoke", headers=AUTH).status_code == 404
        )

        # No key, binding, or capability material leaves the management plane.
        for response in (listed, devices, readback):
            text = json.dumps(response)
            assert base64.b64encode(device_key).decode() not in text
            assert base64.b64encode(binding).decode() not in text
            assert base64.b64encode(offer.capability).decode() not in text
            assert "channel_binding" not in text.replace("channel_binding_digest", "")

        diagnostics = client.get(f"{PREFIX}/diagnostics", headers=AUTH).json()
        assert diagnostics["devices"] == {
            "total": 1,
            "pending": 0,
            "authorized": 0,
            "revoked": 1,
            "denied": 0,
        }
        assert diagnostics["active_leases"] == 0
        assert diagnostics["pairing_offer_status"] == "consumed"


def test_fingerprint_confirmation_approval_for_the_dashboard_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, client = _client(tmp_path, monkeypatch)
    with client:
        repository = module._admission.repository
        offer = repository.create_offer()
        binding = secrets.token_bytes(32)
        pending = repository.consume_offer(offer.capability, secrets.token_bytes(32), binding)

        approve_url = f"{PREFIX}/devices/{pending.device_id}/approve"
        # A wrong confirmed fingerprint (operator approved the wrong row) fails.
        bad = client.post(
            approve_url, headers=AUTH, content=json.dumps({"confirmed_fingerprint": "0" * 16})
        )
        assert bad.status_code == 403
        # The fingerprint the operator actually compared is accepted...
        good = client.post(
            approve_url,
            headers=AUTH,
            content=json.dumps({"confirmed_fingerprint": pending.fingerprint}),
        )
        assert good.status_code == 200
        assert good.json()["status"] == "authorized"
        assert good.json()["capabilities"] == ["client"]
        # ...and it is idempotent.
        again = client.post(
            approve_url,
            headers=AUTH,
            content=json.dumps({"confirmed_fingerprint": pending.fingerprint}),
        )
        assert again.status_code == 200
        # An unknown key shape is rejected.
        assert (
            client.post(approve_url, headers=AUTH, content=json.dumps({"nonsense": 1})).status_code
            == 400
        )


def test_oversized_and_malformed_bodies_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _module, client = _client(tmp_path, monkeypatch)
    with client:
        huge = json.dumps({"channel_binding_digest": "x" * 5000})
        response = client.post(
            f"{PREFIX}/devices/any/approve", headers=AUTH, content=huge
        )
        assert response.status_code == 413
        malformed = client.post(
            f"{PREFIX}/pairing-offers", headers=AUTH, content='{"ttl_seconds": NaN}'
        )
        assert malformed.status_code == 400
        duplicate_keys = client.post(
            f"{PREFIX}/pairing-offers",
            headers=AUTH,
            content='{"ttl_seconds": 1, "ttl_seconds": 2}',
        )
        assert duplicate_keys.status_code == 400


def test_body_reading_stops_streaming_at_the_cap() -> None:
    """MR-03: the cap bounds allocation while streaming, not after buffering."""

    import asyncio

    module = _load_plugin_api()
    chunk = b"x" * 1024
    consumed = 0

    class StreamingRequest:
        async def stream(self):
            nonlocal consumed
            for _ in range(1024):  # 1 MiB on offer; only ~4 KiB may be read.
                consumed += 1
                yield chunk

    async def exercise() -> None:
        with pytest.raises(HTTPException) as excinfo:
            await module._bounded_json_body(StreamingRequest())
        assert excinfo.value.status_code == 413

    asyncio.run(exercise())
    # The helper must stop as soon as the cap is exceeded: at 1 KiB chunks and
    # a 4 KiB cap it may consume at most 5 chunks, never the whole stream.
    assert consumed <= module.MAX_BODY_BYTES // len(chunk) + 1


def test_management_failure_keeps_status_responsive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module, client = _client(tmp_path, monkeypatch)

    def broken(_runtime):
        raise RuntimeError("private construction detail")

    module._build_admission = broken
    with client:
        status = client.get(f"{PREFIX}/status", headers=AUTH)
        assert status.status_code == 200
        assert status.json()["runtime"] == "ready"
        for method, route in ALL_ROUTES:
            if route.endswith("/status"):
                continue
            response = client.request(method, route, headers=AUTH)
            assert response.status_code == 503, route
            assert response.json()["detail"] == "management_unavailable"
            assert "private" not in response.text


def test_qr_render_failure_fails_the_create_and_frees_the_offer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BR-07: a QR failure must not return a successful, unusable offer."""

    import mercury_relay_plugin.pairing_qr as pairing_qr

    _module, client = _client(tmp_path, monkeypatch)
    with client:
        def broken_qr(_offer, **_kwargs):
            raise RuntimeError("sensitive encoder detail")

        monkeypatch.setattr(pairing_qr, "pairing_qr_svg", broken_qr)
        failed = client.post(f"{PREFIX}/pairing-offers", headers=AUTH, content="{}")
        assert failed.status_code == 500
        assert failed.json()["detail"] == "qr_render_failed"
        assert "sensitive" not in failed.text

        # The failed offer does not linger: creating a fresh one succeeds
        # immediately instead of returning the active-offer conflict.
        monkeypatch.undo()
        created = client.post(f"{PREFIX}/pairing-offers", headers=AUTH, content="{}")
        assert created.status_code == 200
        assert created.json()["qr_svg"]
