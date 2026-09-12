"""Encrypted push-preview contract, crypto, policy, and lifecycle tests."""

import asyncio
import base64
import json
import os
from pathlib import Path

import httpx
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from test_push import admitted_peer, emit_and_drain, event

from mercury_relay_plugin.config import profile_paths
from mercury_relay_plugin.push import PushBridge, PushObserver
from mercury_relay_plugin.push_preview import (
    PREVIEW_CAPABILITY,
    aad_for_preview,
    build_preview_plaintext,
    canonical_b64url,
    completion_excerpt,
    encrypt_preview,
    normalize_title,
)
from mercury_relay_plugin.session_reads import SessionReadsError

KEY = bytes(range(32))
KEY_TEXT = base64.urlsafe_b64encode(KEY).decode().rstrip("=")
KID = base64.urlsafe_b64encode(bytes(range(16))).decode().rstrip("=")
PREVIEW = {
    "version": 1,
    "key_id": KID,
    "key": KEY_TEXT,
    "completion": True,
    "attention": True,
    "include_title": True,
    "include_response_excerpt": True,
}
PARAMS = {"device_token": "ab" * 32, "environment": "sandbox", "preview": PREVIEW}


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def preview_bridge(
    tmp_path, calls, *, authorized=lambda _d, _e: True, wall_clock=lambda: 2_000_000_000
):
    def peer(request):
        calls.append(request)
        return httpx.Response(200)

    return PushBridge(
        paths=profile_paths(explicit_path=tmp_path),
        relay_origin="https://relay.example",
        installation_id=b"i" * 32,
        token_provider=lambda: "host-token",
        authorized=authorized,
        transport=httpx.MockTransport(peer),
        preview_enabled=True,
        wall_clock=wall_clock,
    )


def test_frozen_aad_and_chacha20poly1305_vector():
    corpus_path = (
        Path(__file__).parents[1] / "protocol" / "vectors" / "push-preview" / "corpus.json"
    )
    vector = json.loads(corpus_path.read_text())["vectors"][0]
    wake = vector["wake_handle"]
    event_id = vector["event_id"]
    aad = aad_for_preview(vector["environment"], wake, event_id, vector["key_id"])
    assert aad.hex() == vector["aad_hex"]
    plaintext = vector["plaintext_utf8"].encode("utf-8")
    ciphertext = encrypt_preview(
        key=decode(vector["key_base64url"]),
        nonce=decode(vector["nonce_base64url"]),
        plaintext=plaintext,
        environment=vector["environment"],
        wake_handle=wake,
        event_id=event_id,
        key_id=vector["key_id"],
    )
    assert ciphertext == vector["ciphertext_base64url"]
    assert (
        ChaCha20Poly1305(KEY).decrypt(decode(vector["nonce_base64url"]), decode(ciphertext), aad)
        == plaintext
    )
    with pytest.raises(InvalidTag):
        ChaCha20Poly1305(KEY).decrypt(
            decode(vector["nonce_base64url"]), decode(ciphertext), aad + b"x"
        )


def test_preview_text_policy_bounds_and_attention_has_no_source_text():
    assert completion_excerpt("# Heading\r\n\r\n**one**\n`two`\nthree\nfour") == "one\ntwo\nthree"
    assert (
        completion_excerpt("Operation interrupted: waiting for model response (id)")
        == "Response completed"
    )
    assert len(completion_excerpt("😀" * 500).encode()) <= 640
    assert len(completion_excerpt("x" * 500)) == 240
    assert normalize_title("\x00  First title\nprivate prompt " + "😀" * 100) == "First title"
    assert len(normalize_title("😀" * 120).encode()) <= 160
    raw = build_preview_plaintext(
        kind="attention",
        attention_kind="secret.request",
        response_text="PRIVATE secret prompt",
        title="PRIVATE title",
        include_title=True,
        include_response_excerpt=True,
        route={"durable_session_id": "durable", "profile": "default"},
        now=2_000_000_000,
    )
    value = json.loads(raw)
    assert value["title"] == "Hermes needs secure input"
    assert value["body"] == "Secure input is required to continue"
    assert value["route"] == {"sid": "durable", "profile": "default"}
    assert value["exp"] - value["iat"] == 120
    assert "PRIVATE" not in raw.decode()
    assert len(raw) <= 1280


def test_route_limits_are_utf8_bytes_and_shared_profile_bound():
    valid = {"durable_session_id": "é" * 64, "profile": "é" * 32}
    value = json.loads(
        build_preview_plaintext(
            kind="completion", response_text=None, title=None,
            include_title=False, include_response_excerpt=False,
            route=valid, now=2_000_000_000,
        )
    )
    assert value["route"] == {"sid": valid["durable_session_id"], "profile": valid["profile"]}
    for invalid in (
        {"durable_session_id": "é" * 65, "profile": "default"},
        {"durable_session_id": "durable", "profile": "é" * 33},
        {"durable_session_id": "bad\n", "profile": "default"},
    ):
        value = json.loads(
            build_preview_plaintext(
                kind="completion", response_text=None, title=None,
                include_title=False, include_response_excerpt=False,
                route=invalid, now=2_000_000_000,
            )
        )
        assert "route" not in value


def test_shared_policy_corpus_is_byte_identical_and_semantically_enforced():
    host_path = (
        Path(__file__).parents[1]
        / "protocol"
        / "vectors"
        / "push-preview"
        / "policy-corpus.json"
    )
    shared_path = os.environ.get("MERCURY_SHARED_PUSH_PREVIEW_POLICY")
    if shared_path:
        assert host_path.read_bytes() == Path(shared_path).read_bytes()
    corpus = json.loads(host_path.read_text(encoding="utf-8"))
    for case in corpus["cases"]:
        if case["kind"] == "completion":
            title = normalize_title(case.get("title")) if case.get("include_title") else None
            body = completion_excerpt(case["text"]) if case.get("include_excerpt") else None
        else:
            attention_kind = {
                "approval": "approval.request",
                "clarification": "clarify.request",
                "secure": "secret.request",
            }[case["kind"]]
            plaintext = json.loads(
                build_preview_plaintext(
                    kind="attention",
                    attention_kind=attention_kind,
                    response_text=case["text"],
                    title=None,
                    include_title=True,
                    include_response_excerpt=True,
                    route=None,
                    now=2_000_000_000,
                )
            )
            title, body = plaintext.get("title"), plaintext.get("body")
            assert case["text"] not in json.dumps(plaintext)
        assert title == case.get("expected_title"), case["name"]
        assert body == case.get("expected_body"), case["name"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: {**p, "extra": True},
        lambda p: {**p, "environment": "development"},
        lambda p: {**p, "preview": {**p["preview"], "extra": True}},
        lambda p: {**p, "preview": {**p["preview"], "version": True}},
        lambda p: {**p, "preview": {**p["preview"], "key_id": "a" * 22}},
        lambda p: {**p, "preview": {**p["preview"], "key": "a" * 43}},
        lambda p: {**p, "preview": {**p["preview"], "completion": 1}},
    ],
)
def test_preview_registration_strictly_rejects_invalid_fields(tmp_path, mutate):
    async def run():
        calls = []
        bridge = preview_bridge(tmp_path, calls)
        try:
            with pytest.raises(SessionReadsError, match="invalid_params"):
                await bridge.dispatch("device", 4, "relay.push.preview.register", mutate(PARAMS))
            assert calls == []
        finally:
            await bridge.close()

    asyncio.run(run())


def test_authenticated_preview_registration_capability_and_worker_key_opacity(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, attached, _ = await admitted_peer(
            tmp_path, preview_enabled=True
        )
        try:
            assert attached["params"]["capabilities"]["push_previews"] == PREVIEW_CAPABILITY
            status = await rpc("relay.status", {})
            assert status["result"]["capabilities"]["push_previews"] == PREVIEW_CAPABILITY
            result = (await rpc("relay.push.preview.register", PARAMS))["result"]
            assert result["preview"] == {"version": 1, "key_id": KID}
            body = json.loads(requests[0].content)
            assert body["preview"] == {"version": 1, "key_id": KID}
            assert KEY_TEXT not in requests[0].content.decode()
            state = service.push.path.read_text()
            assert json.loads(state)["version"] == 3
            assert KEY_TEXT in state
            if os.name == "posix":
                assert service.push.path.stat().st_mode & 0o777 == 0o600
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_live_completion_encrypts_bounded_preview_and_fixed_attention(tmp_path):
    async def run():
        service, runtime, admitted, rpc, requests, _, _ = await admitted_peer(
            tmp_path, preview_enabled=True, wall_clock=lambda: 2_000_000_000
        )
        try:
            registered = (await rpc("relay.push.preview.register", PARAMS))["result"]
            handle = registered["wake_handle"]
            # The title is authoritative live output. It is used only alongside a proven route.
            await emit_and_drain(
                admitted,
                service.push,
                event("session.title", {"session_id": "durable-1", "title": "  My chat\nignored"}),
            )
            service.push.requests = requests
            admitted.lease.recovery_projection.binding_for_runtime = lambda sid: {
                "durable_session_id": "durable-1",
                "profile": "default",
            }
            await emit_and_drain(
                admitted,
                service.push,
                event("message.start", seq=2),
                event(
                    "message.complete", {"text": "# Answer\n**safe**", "status": "complete"}, seq=3
                ),
                event(
                    "approval.request",
                    {"request_id": "approval-1", "command": "PRIVATE command"},
                    seq=4,
                ),
            )
            for request in requests:
                assert KEY_TEXT not in request.content.decode()
                assert "PRIVATE" not in request.content.decode()
                assert len(request.content) <= 3072
            wakes = [json.loads(r.content) for r in requests if r.url.path.endswith("/wake")]
            assert len(wakes) == 2
            for wake in wakes:
                envelope = wake["preview"]
                assert set(envelope) == {"version", "alg", "key_id", "nonce", "ciphertext"}
                assert envelope["version"] == 1 and envelope["alg"] == "C20P"
                plaintext = ChaCha20Poly1305(KEY).decrypt(
                    decode(envelope["nonce"]),
                    decode(envelope["ciphertext"]),
                    aad_for_preview("sandbox", handle, wake["event_id"], KID),
                )
                assert len(plaintext) <= 1280
                wake["plaintext"] = json.loads(plaintext)
            completion, attention = wakes
            assert completion["plaintext"] == {
                "v": 1,
                "kind": "completion",
                "title": "My chat",
                "body": "safe",
                "route": {"sid": "durable-1", "profile": "default"},
                "iat": 2_000_000_000,
                "exp": 2_000_000_120,
            }
            assert attention["plaintext"]["title"] == "Hermes needs approval"
            assert attention["plaintext"]["body"] == "Authorization is required to continue"
            assert "PRIVATE" not in json.dumps(attention["plaintext"])
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())


def test_preferences_filter_categories_and_omit_completion_content(tmp_path):
    async def run():
        calls = []
        bridge = preview_bridge(tmp_path, calls)
        prefs = {
            **PREVIEW,
            "completion": True,
            "attention": False,
            "include_title": False,
            "include_response_excerpt": False,
        }
        try:
            result = await bridge.dispatch(
                "device", 1, "relay.push.preview.register", {**PARAMS, "preview": prefs}
            )
            observer = PushObserver(
                bridge, "device", 1, type("P", (), {"binding_for_runtime": lambda _s, _i: None})()
            )
            observer.observe(json.dumps(event("message.complete", {"text": "PRIVATE answer"})))
            observer.observe(
                json.dumps(event("approval.request", {"request_id": "r", "text": "PRIVATE"}))
            )
            await bridge.drain()
            wakes = [json.loads(r.content) for r in calls if r.url.path.endswith("/wake")]
            assert len(wakes) == 1
            plain = ChaCha20Poly1305(KEY).decrypt(
                decode(wakes[0]["preview"]["nonce"]),
                decode(wakes[0]["preview"]["ciphertext"]),
                aad_for_preview("sandbox", result["wake_handle"], wakes[0]["event_id"], KID),
            )
            assert json.loads(plain) == {
                "v": 1,
                "kind": "completion",
                "iat": 2_000_000_000,
                "exp": 2_000_000_120,
            }
        finally:
            await bridge.close()

    asyncio.run(run())


def test_retry_rotation_failure_and_revocation_preserve_then_delete_keys(tmp_path):
    async def run():
        calls = []
        fail_new = False
        fail_register = False

        def peer(request):
            calls.append(request)
            body = json.loads(request.content)
            if (
                (fail_register or fail_new)
                and request.url.path.endswith("/register")
                and (fail_register or body.get("preview", {}).get("key_id") != KID)
            ):
                return httpx.Response(503)
            return httpx.Response(200)

        bridge = PushBridge(
            paths=profile_paths(explicit_path=tmp_path),
            relay_origin="https://relay.example",
            installation_id=b"i" * 32,
            token_provider=lambda: "host-token",
            authorized=lambda _d, _e: True,
            transport=httpx.MockTransport(peer),
            preview_enabled=True,
        )
        try:
            first = await bridge.dispatch("device", 7, "relay.push.preview.register", PARAMS)
            retry = await bridge.dispatch("device", 7, "relay.push.preview.register", PARAMS)
            assert retry == first
            changed_preferences = {**PREVIEW, "attention": False}
            preference_update = await bridge.dispatch(
                "device",
                7,
                "relay.push.preview.register",
                {**PARAMS, "preview": changed_preferences},
            )
            assert preference_update == first
            assert bridge.rows[first["wake_handle"]]["preview"] == changed_preferences
            assert len(bridge.rows) == 1
            failed_preferences = {**changed_preferences, "completion": False}
            fail_register = True
            with pytest.raises(SessionReadsError, match="push_unavailable"):
                await bridge.dispatch(
                    "device", 7, "relay.push.preview.register",
                    {**PARAMS, "preview": failed_preferences},
                )
            assert bridge.rows[first["wake_handle"]]["preview"] == changed_preferences
            assert bridge._valid(first["wake_handle"])
            fail_register = False
            other_key = bytes(reversed(range(32)))
            other_kid = canonical_b64url(bytes(reversed(range(16))))
            fail_new = True
            with pytest.raises(SessionReadsError, match="push_unavailable"):
                await bridge.dispatch(
                    "device",
                    7,
                    "relay.push.preview.register",
                    {
                        **PARAMS,
                        "preview": {
                            **PREVIEW,
                            "key_id": other_kid,
                            "key": canonical_b64url(other_key),
                        },
                    },
                )
            assert bridge._valid(first["wake_handle"])
            fail_new = False
            rotated = await bridge.dispatch(
                "device",
                7,
                "relay.push.preview.register",
                {
                    **PARAMS,
                    "preview": {
                        **PREVIEW,
                        "key_id": other_kid,
                        "key": canonical_b64url(other_key),
                    },
                },
            )
            await bridge.drain()
            assert rotated["wake_handle"] != first["wake_handle"]
            assert set(bridge.rows) == {rotated["wake_handle"]}
            assert KEY_TEXT not in bridge.path.read_text()
            bridge.revoke("device", 7)
            persisted = bridge.path.read_text()
            assert KEY_TEXT not in persisted
            assert canonical_b64url(other_key) not in persisted
            assert not any(row["status"] == "active" for row in bridge.rows.values())
            await bridge.drain()
        finally:
            await bridge.close()

    asyncio.run(run())


def test_v2_to_v3_migration_preserves_generic_and_fences_bad_preview_state(tmp_path):
    paths = profile_paths(explicit_path=tmp_path).ensure()
    handle = canonical_b64url(b"h" * 32)
    route = canonical_b64url(b"i" * 32)
    paths.agent_dir.joinpath("push.json").write_text(
        json.dumps(
            {
                "version": 2,
                "rows": {
                    handle: {
                        "device": "device",
                        "epoch": 2,
                        "active": True,
                        "origin": "https://relay.example",
                        "route": route,
                    }
                },
            }
        )
    )
    paths.agent_dir.joinpath("push.json").chmod(0o600)
    bridge = PushBridge(
        paths=paths,
        relay_origin="https://relay.example",
        installation_id=b"i" * 32,
        token_provider=lambda: "token",
        authorized=lambda _d, _e: True,
        preview_enabled=True,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200)),
    )
    try:
        assert bridge.rows[handle]["mode"] == "generic"
        assert bridge.rows[handle]["status"] == "active"
        assert bridge.rows[handle]["preview"] is None
        assert json.loads(bridge.path.read_text())["version"] == 3
    finally:
        asyncio.run(bridge.close())


def test_production_preview_uses_production_aad_and_bounded_worker_body(tmp_path):
    async def run():
        calls = []
        bridge = preview_bridge(tmp_path, calls)
        params = {**PARAMS, "environment": "production"}
        try:
            result = await bridge.dispatch("device", 3, "relay.push.preview.register", params)
            bridge.wake(
                "device",
                3,
                b"production-event",
                preview_data={"kind": "completion", "response_text": "ready"},
            )
            await bridge.drain()
            registration, wake_request = calls
            assert json.loads(registration.content)["environment"] == "production"
            assert len(wake_request.content) <= 3072
            wake = json.loads(wake_request.content)
            plaintext = ChaCha20Poly1305(KEY).decrypt(
                decode(wake["preview"]["nonce"]),
                decode(wake["preview"]["ciphertext"]),
                aad_for_preview("production", result["wake_handle"], wake["event_id"], KID),
            )
            assert json.loads(plaintext)["body"] == "ready"
        finally:
            await bridge.close()

    asyncio.run(run())


def test_crash_pending_preview_retry_reuses_handle_and_promotes(tmp_path):
    paths = profile_paths(explicit_path=tmp_path).ensure()
    handle = canonical_b64url(b"h" * 32)
    path = paths.agent_dir / "push.json"
    path.write_text(
        json.dumps(
            {
                "version": 3,
                "rows": {
                    handle: {
                        "device": "device",
                        "epoch": 8,
                        "status": "pending",
                        "origin": "https://relay.example",
                        "route": canonical_b64url(b"i" * 32),
                        "mode": "preview",
                        "environment": "sandbox",
                        "preview": PREVIEW,
                    }
                },
            }
        )
    )
    path.chmod(0o600)

    async def run():
        calls = []
        bridge = preview_bridge(tmp_path, calls)
        try:
            result = await bridge.dispatch("device", 8, "relay.push.preview.register", PARAMS)
            assert result["wake_handle"] == handle
            assert bridge.rows[handle]["status"] == "active"
            assert len(calls) == 1
        finally:
            await bridge.close()

    asyncio.run(run())


def test_malformed_v3_preview_key_fails_closed_before_network(tmp_path):
    paths = profile_paths(explicit_path=tmp_path).ensure()
    handle = canonical_b64url(b"h" * 32)
    path = paths.agent_dir / "push.json"
    path.write_text(
        json.dumps(
            {
                "version": 3,
                "rows": {
                    handle: {
                        "device": "device",
                        "epoch": 1,
                        "status": "active",
                        "origin": "https://relay.example",
                        "route": canonical_b64url(b"i" * 32),
                        "mode": "preview",
                        "environment": "sandbox",
                        "preview": {**PREVIEW, "key": "a" * 43},
                    }
                },
            }
        )
    )
    path.chmod(0o600)
    calls = []
    with pytest.raises(ValueError, match="invalid push state"):
        preview_bridge(tmp_path, calls)
    assert calls == []


def test_disabling_server_preview_fences_registration_and_deletes_key(tmp_path):
    async def run():
        calls = []
        enabled = preview_bridge(tmp_path, calls)
        await enabled.dispatch("device", 1, "relay.push.preview.register", PARAMS)
        await enabled.close()
        calls.clear()
        disabled = PushBridge(
            paths=profile_paths(explicit_path=tmp_path),
            relay_origin="https://relay.example",
            installation_id=b"i" * 32,
            token_provider=lambda: "host-token",
            authorized=lambda _d, _e: True,
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
            preview_enabled=False,
        )
        try:
            assert KEY_TEXT not in disabled.path.read_text()
            assert all(row["status"] == "debt" for row in disabled.rows.values())
            await disabled.drain()
            assert disabled.rows == {}
            assert len(calls) == 1 and calls[0].url.path.endswith("/unregister")
        finally:
            await disabled.close()

    asyncio.run(run())


def test_preview_disabled_keeps_generic_capabilities_and_rejects_new_method(tmp_path):
    async def run():
        service, runtime, _, rpc, requests, attached, _ = await admitted_peer(tmp_path)
        try:
            assert "push_previews" not in attached["params"]["capabilities"]
            response = await rpc("relay.push.preview.register", PARAMS)
            assert response["error"]["message"] == "push_unavailable"
            generic = await rpc(
                "relay.push.register", {"device_token": "ab" * 32, "environment": "sandbox"}
            )
            assert generic["result"]["registered"] is True
            assert len(requests) == 1
        finally:
            await service.close()
            await runtime.close()

    asyncio.run(run())
