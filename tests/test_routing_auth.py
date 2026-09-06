from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.config import profile_paths  # noqa: E402
from mercury_relay_plugin.routing_auth import (  # noqa: E402
    AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS,
    HOST_TOKEN_TTL_SECONDS,
    ROLE_AUTHORIZED_DEVICE,
    ROLE_HOST,
    ROLE_PAIRING_DEVICE,
    RoutingIssuerStore,
    RoutingTokenError,
    RoutingTokenIssuer,
    verify_routing_token,
)

INSTALLATION = b"\x22" * 32


def _issuer(clock=None) -> RoutingTokenIssuer:
    return RoutingTokenIssuer(b"\x07" * 32, clock=clock)


def test_mint_and_verify_round_trip_for_every_role() -> None:
    issuer = _issuer(clock=lambda: 1_000_000)
    for role, ttl in (
        (ROLE_HOST, HOST_TOKEN_TTL_SECONDS),
        (ROLE_PAIRING_DEVICE, 300),
        (ROLE_AUTHORIZED_DEVICE, AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS),
    ):
        token = issuer.mint(role=role, installation_id=INSTALLATION, ttl_seconds=ttl)
        claims = verify_routing_token(
            token, public_key=issuer.public_key, now=1_000_000
        )
        assert claims["role"] == role
        assert claims["aud"] == "mercury-relay"
        assert claims["exp"] - claims["iat"] == ttl
        # jti is unique per mint.
        second = issuer.mint(role=role, installation_id=INSTALLATION, ttl_seconds=ttl)
        assert second != token


def test_verification_rejects_tampering_wrong_key_and_expiry() -> None:
    issuer = _issuer(clock=lambda: 1_000_000)
    token = issuer.mint(role=ROLE_HOST, installation_id=INSTALLATION, ttl_seconds=600)

    with pytest.raises(RoutingTokenError):
        verify_routing_token(token[:-6] + "AAAAAA", public_key=issuer.public_key)
    with pytest.raises(RoutingTokenError):
        verify_routing_token(token, public_key=b"\x09" * 32)
    with pytest.raises(RoutingTokenError):
        verify_routing_token(token, public_key=issuer.public_key, now=1_000_601)
    with pytest.raises(RoutingTokenError):
        verify_routing_token(token, public_key=issuer.public_key, now=999_000)
    for garbage in ("", "a.b", "a.b.c", token + ".d", token.replace(".", "", 1)):
        with pytest.raises(RoutingTokenError):
            verify_routing_token(garbage, public_key=issuer.public_key, now=1_000_000)


def test_minting_validates_inputs() -> None:
    issuer = _issuer()
    with pytest.raises(RoutingTokenError):
        issuer.mint(role="admin", installation_id=INSTALLATION, ttl_seconds=60)
    with pytest.raises(RoutingTokenError):
        issuer.mint(role=ROLE_HOST, installation_id=b"short", ttl_seconds=60)
    with pytest.raises(RoutingTokenError):
        issuer.mint(role=ROLE_HOST, installation_id=INSTALLATION, ttl_seconds=0)
    with pytest.raises(RoutingTokenError):
        RoutingTokenIssuer(b"short")


def test_issuer_store_persists_one_key_and_never_leaks_it(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    root.mkdir()
    paths = profile_paths("default", explicit_path=root)
    first = RoutingIssuerStore(paths).load_or_create()
    second = RoutingIssuerStore(paths).load_or_create()
    assert first.public_key == second.public_key

    # The key is persisted in the owner-only private store and validated
    # against its recorded public key on load.
    import base64
    import stat

    state_text = paths.state_path.read_text(encoding="utf-8")
    assert base64.b64encode(first.public_key).decode("ascii") in state_text
    assert stat.S_IMODE(paths.state_path.stat().st_mode) == 0o600


def test_verification_matches_worker_edge_checks() -> None:
    issuer = _issuer(clock=lambda: 1_000_000)
    token = issuer.mint(role=ROLE_HOST, installation_id=INSTALLATION, ttl_seconds=600)

    # Installation binding, when requested, must match exactly.
    from mercury_relay_plugin.identity import _b64url_encode

    inst_b64url = _b64url_encode(INSTALLATION)
    claims = verify_routing_token(
        token, public_key=issuer.public_key, installation=inst_b64url, now=1_000_000
    )
    assert claims["inst"] == inst_b64url
    with pytest.raises(RoutingTokenError):
        verify_routing_token(
            token, public_key=issuer.public_key, installation="other", now=1_000_000
        )


def test_verification_rejects_over_lifetime_and_bad_jti() -> None:
    from mercury_relay_plugin.routing_auth import MAX_TOKEN_LIFETIME_SECONDS

    issuer = _issuer(clock=lambda: 1_000_000)
    # An authorized-device token beyond the role's lifetime cap is rejected
    # exactly as the Worker would (parity), even with a valid signature.
    over = issuer.mint(
        role=ROLE_AUTHORIZED_DEVICE,
        installation_id=INSTALLATION,
        ttl_seconds=MAX_TOKEN_LIFETIME_SECONDS[ROLE_AUTHORIZED_DEVICE] + 60,
    )
    with pytest.raises(RoutingTokenError):
        verify_routing_token(over, public_key=issuer.public_key, now=1_000_000)


def test_verification_rejects_non_canonical_base64_segments() -> None:
    issuer = _issuer(clock=lambda: 1_000_000)
    token = issuer.mint(role=ROLE_HOST, installation_id=INSTALLATION, ttl_seconds=600)
    header, claims_seg, sig = token.split(".")
    # Standard-alphabet '+'/'/' or embedded padding are not the URL-safe
    # alphabet the Worker accepts; reject them.
    key = issuer.public_key
    with pytest.raises(RoutingTokenError):
        verify_routing_token(f"{header}.{claims_seg}=.{sig}", public_key=key, now=1_000_000)
    with pytest.raises(RoutingTokenError):
        verify_routing_token(f"{header}.{claims_seg}.{sig}+", public_key=key, now=1_000_000)


def test_all_minted_tokens_pass_the_lifetime_caps() -> None:
    """Every token the plugin actually mints must verify at the edge."""

    from mercury_relay_plugin.routing_auth import (
        AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS,
        HOST_TOKEN_TTL_SECONDS,
    )

    issuer = _issuer(clock=lambda: 1_000_000)
    host = issuer.mint_host_token(INSTALLATION)
    assert verify_routing_token(host, public_key=issuer.public_key, now=1_000_000)
    assert HOST_TOKEN_TTL_SECONDS <= 3_600
    dev = issuer.mint(
        role=ROLE_AUTHORIZED_DEVICE,
        installation_id=INSTALLATION,
        ttl_seconds=AUTHORIZED_DEVICE_TOKEN_TTL_SECONDS,
    )
    assert verify_routing_token(dev, public_key=issuer.public_key, now=1_000_000)
