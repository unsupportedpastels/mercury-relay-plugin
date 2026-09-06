from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.method_policy import (  # noqa: E402
    ALLOWED_V1_METHODS,
    MethodPolicy,
    MethodPolicyRejected,
)


def request(method: str, *, request_id: object = "r1", params: object = None) -> str:
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {} if params is None else params,
    }
    return json.dumps(body, separators=(",", ":"))


def test_policy_accepts_only_the_explicit_v1_set_and_preserves_bytes() -> None:
    policy = MethodPolicy(profile="default")
    for method in ALLOWED_V1_METHODS:
        raw = request(method)
        assert policy.validate_text(raw) == raw

    with pytest.raises(MethodPolicyRejected, match="method_not_allowed"):
        policy.validate_text(request("config.get"))


def test_policy_allows_read_only_profile_discovery() -> None:
    raw = request("profiles.list", params={"include_sessions": False})
    assert MethodPolicy(profile="default").validate_text(raw) == raw


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("not-json", "invalid_json"),
        ('{"jsonrpc":"2.0","id":"x","id":"y","method":"gateway.ping"}', "invalid_json"),
        ('{"jsonrpc":"2.0","id":NaN,"method":"gateway.ping"}', "invalid_json"),
        ("[]", "invalid_request"),
        (json.dumps({"jsonrpc": "1.0", "id": "x", "method": "gateway.ping"}), "invalid_request"),
        (
            json.dumps({"jsonrpc": "2.0", "method": "gateway.ping", "params": {}}),
            "uncorrelated_request",
        ),
        (request("gateway.ping", request_id=True), "uncorrelated_request"),
        (request("gateway.ping", params=[]), "invalid_params"),
        (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "x",
                    "method": "gateway.ping",
                    "params": {},
                    "auth_identity": {"user_id": "forged"},
                }
            ),
            "invalid_request",
        ),
    ],
)
def test_policy_rejects_malformed_or_uncorrelated_requests(raw: str, reason: str) -> None:
    with pytest.raises(MethodPolicyRejected, match=reason):
        MethodPolicy(profile="default").validate_text(raw)


def test_policy_allows_authorized_profiles_and_rejects_unknown_profiles() -> None:
    policy = MethodPolicy(
        profile="default",
        profile_authorizer=lambda profile: profile in {"default", "researcher"},
    )
    raw = request("session.create", params={"profile": "researcher"})
    assert policy.validate_text(raw) == raw
    with pytest.raises(MethodPolicyRejected, match="profile_not_available"):
        policy.validate_text(request("session.create", params={"profile": "missing"}))


def test_policy_rejects_identity_claims() -> None:
    policy = MethodPolicy(profile="default")
    with pytest.raises(MethodPolicyRejected, match="privileged_identity"):
        policy.validate_text(
            request("session.create", params={"auth_identity": {"user_id": "forged"}})
        )
    with pytest.raises(MethodPolicyRejected, match="privileged_identity"):
        policy.validate_text(request("session.create", params={"principal_id": "forged"}))


def test_rejections_expose_only_stable_reason_codes() -> None:
    secret = "sensitive-payload-value"
    with pytest.raises(MethodPolicyRejected) as caught:
        MethodPolicy(profile="default").validate_text(secret)
    assert caught.value.reason == "invalid_json"
    assert secret not in str(caught.value)
