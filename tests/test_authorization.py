from __future__ import annotations

import base64
import hashlib
import json
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from conftest import posix_only

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.authorization import (  # noqa: E402
    AuthorizationError,
    AuthorizationRepository,
    PairingRejected,
)
from mercury_relay_plugin.config import profile_paths  # noqa: E402
from mercury_relay_plugin.identity import HostIdentityStore  # noqa: E402
from mercury_relay_plugin.state_store import StateStore  # noqa: E402


def make_paths(tmp_path: Path):
    root = tmp_path / "hermes"
    root.mkdir()
    return profile_paths("default", explicit_path=root)


def device_key(seed: int) -> bytes:
    return bytes([seed]) * 32


@posix_only
def test_offer_is_single_active_bounded_and_secret_safe(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()

    assert len(offer.capability) == 32
    assert offer.installation_id == HostIdentityStore(paths).load_or_create().installation_id
    assert offer.host_public_key == HostIdentityStore(paths).load_or_create().public_key
    assert offer.expires_at == 1300
    assert base64.b64encode(offer.capability).decode("ascii") not in repr(offer)
    assert offer.to_public_dict()["offer_id"] == offer.offer_id
    assert "capability" not in offer.to_public_dict()

    with pytest.raises(AuthorizationError, match="pairing offer already active"):
        repo.create_offer()

    state_text = paths.state_path.read_text(encoding="utf-8")
    assert base64.b64encode(offer.capability).decode("ascii") not in state_text
    assert base64.b64encode(hashlib.sha256(offer.capability).digest()).decode("ascii") in state_text
    assert stat.S_IMODE(paths.state_path.stat().st_mode) == 0o600


def test_consume_rejects_all_wrong_and_replay_inputs_with_one_error(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()
    public_key = device_key(1)
    binding = device_key(2)

    errors = []
    for capability, key, channel_binding in [
        (b"wrong", public_key, binding),
        (offer.capability[:-1], public_key, binding),
        (offer.capability, public_key[:-1], binding),
        (offer.capability, public_key, binding[:-1]),
    ]:
        with pytest.raises(PairingRejected) as error:
            repo.consume_offer(capability, key, channel_binding)
        errors.append(str(error.value))
    assert errors == ["pairing rejected"] * len(errors)

    pending = repo.consume_offer(offer.capability, public_key, binding)
    assert pending.status == "pending"
    assert pending.capabilities == ()
    assert len(pending.fingerprint) == 16

    with pytest.raises(PairingRejected, match="pairing rejected"):
        repo.consume_offer(offer.capability, device_key(3), device_key(4))

    state_text = paths.state_path.read_text(encoding="utf-8")
    assert base64.b64encode(offer.capability).decode("ascii") not in state_text
    assert base64.b64encode(binding).decode("ascii") not in state_text
    assert "channel_binding" not in json.dumps([item.to_dict() for item in repo.list_devices()])


def test_double_consume_has_one_winner_and_one_pending_device(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()

    def consume(seed: int):
        try:
            return (
                "ok",
                repo.consume_offer(offer.capability, device_key(seed), device_key(seed + 10)),
            )
        except PairingRejected as error:
            return ("rejected", str(error))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, [1, 2]))

    assert [outcome[0] for outcome in outcomes].count("ok") == 1
    assert [outcome[0] for outcome in outcomes].count("rejected") == 1
    assert outcomes[[outcome[0] for outcome in outcomes].index("rejected")][1] == "pairing rejected"
    assert [item.status for item in repo.list_devices()] == ["pending"]


def test_approve_requires_full_binding_then_authorizes_fixed_client(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()
    binding = device_key(2)
    pending = repo.consume_offer(offer.capability, device_key(1), binding)

    with pytest.raises(AuthorizationError, match="approval rejected"):
        repo.approve(pending.device_id, hashlib.sha256(device_key(3)).digest())

    digest = hashlib.sha256(binding).digest()
    approved = repo.approve(pending.device_id, digest)
    assert approved.status == "authorized"
    assert approved.capabilities == ("client",)
    assert repo.is_authorized(pending.device_id, device_key(1))
    assert not repo.is_authorized(pending.device_id, device_key(3))
    with pytest.raises(TypeError):
        repo.is_authorized(pending.device_id)

    assert repo.approve(pending.device_id, digest).status == "authorized"

    listed = repo.list_devices()
    assert len(listed) == 1
    safe = listed[0].to_dict()
    assert set(safe) == {
        "device_id",
        "status",
        "fingerprint",
        "created_at",
        "updated_at",
        "epoch",
        "capabilities",
        "device_name",
        "label",
        "display_name",
    }
    assert "public_key" not in json.dumps(safe)
    assert "channel_binding" not in json.dumps(safe)
    assert "digest" not in json.dumps(safe)


def test_revoke_is_idempotent_and_old_key_cannot_reauthorize(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()
    key = device_key(1)
    pending = repo.consume_offer(offer.capability, key, device_key(2))
    repo.approve(pending.device_id, hashlib.sha256(device_key(2)).digest())

    revoked = repo.revoke(pending.device_id)
    again = repo.revoke(pending.device_id)
    assert revoked.status == "revoked"
    assert revoked.epoch == 1
    assert again.to_dict() == revoked.to_dict()
    assert not repo.is_authorized(pending.device_id, key)

    fresh = repo.create_offer()
    with pytest.raises(PairingRejected, match="pairing rejected"):
        repo.consume_offer(fresh.capability, key, device_key(4))


def test_expired_offer_and_malformed_persisted_records_fail_closed(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    now = [1000]
    repo = AuthorizationRepository(paths, clock=lambda: now[0])
    offer = repo.create_offer(ttl_seconds=1)
    now[0] = 1001

    with pytest.raises(PairingRejected, match="pairing rejected"):
        repo.consume_offer(offer.capability, device_key(1), device_key(2))

    state = StateStore(paths).load()
    state["devices"] = [{"device_id": "not-a-record"}]
    StateStore(paths).save(state)
    with pytest.raises(AuthorizationError, match="authorization state invalid"):
        repo.list_devices()


def test_up_to_five_devices_can_pair_and_the_sixth_is_rejected(tmp_path: Path) -> None:
    from mercury_relay_plugin.authorization import MAX_ACTIVE_DEVICES

    root = tmp_path / "hermes"
    root.mkdir()
    repo = AuthorizationRepository(profile_paths(explicit_path=root))
    for index in range(MAX_ACTIVE_DEVICES):
        offer = repo.create_offer()
        summary = repo.consume_offer(
            offer.capability,
            bytes([index + 1]) * 32,
            bytes([index + 101]) * 32,
        )
        assert summary.status == "pending"
    assert len(repo.list_devices()) == MAX_ACTIVE_DEVICES

    offer = repo.create_offer()
    with pytest.raises(PairingRejected):
        repo.consume_offer(offer.capability, bytes([99]) * 32, bytes([98]) * 32)


def test_pending_devices_expire_automatically_at_lifecycle_points(tmp_path: Path) -> None:
    """BR-04: a stalled pairing must not hold an active-device slot forever."""

    from mercury_relay_plugin.authorization import MAX_ACTIVE_DEVICES, MAX_TTL_SECONDS

    now = [1000]
    repo = AuthorizationRepository(make_paths(tmp_path), clock=lambda: now[0])
    for index in range(MAX_ACTIVE_DEVICES):
        offer = repo.create_offer()
        repo.consume_offer(offer.capability, device_key(index + 1), device_key(index + 101))

    # All five slots are pending; a sixth pairing is rejected today.
    offer = repo.create_offer()
    with pytest.raises(PairingRejected):
        repo.consume_offer(offer.capability, device_key(99), device_key(98))

    # After the pending timeout, listing shows the records denied and a new
    # pairing succeeds without any manual owner action.
    now[0] += MAX_TTL_SECONDS
    statuses = {summary.status for summary in repo.list_devices()}
    assert statuses == {"denied"}
    fresh = repo.create_offer()
    summary = repo.consume_offer(fresh.capability, device_key(42), device_key(43))
    assert summary.status == "pending"


def test_lifetime_pair_and_deny_cycles_never_brick_pairing(tmp_path: Path) -> None:
    """BR-05: denied tombstones are pruned; pairing works past 16 lifetime records."""

    from mercury_relay_plugin.authorization import MAX_DEVICE_RECORDS

    repo = AuthorizationRepository(make_paths(tmp_path), clock=lambda: 1000)
    for index in range(MAX_DEVICE_RECORDS + 4):
        offer = repo.create_offer()
        summary = repo.consume_offer(
            offer.capability, device_key(index + 1), device_key((index + 91) % 251 + 1)
        )
        assert summary.status == "pending"
        repo.deny(summary.device_id)
    assert len(repo.list_devices()) <= MAX_DEVICE_RECORDS


def test_pruning_retains_revoked_records_and_blocks_revoked_keys(tmp_path: Path) -> None:
    from mercury_relay_plugin.authorization import MAX_DEVICE_RECORDS

    repo = AuthorizationRepository(make_paths(tmp_path), clock=lambda: 1000)
    offer = repo.create_offer()
    revoked_key = device_key(200)
    summary = repo.consume_offer(offer.capability, revoked_key, device_key(201))
    repo.approve(summary.device_id, hashlib.sha256(device_key(201)).digest())
    repo.revoke(summary.device_id)

    for index in range(MAX_DEVICE_RECORDS + 4):
        offer = repo.create_offer()
        pending = repo.consume_offer(
            offer.capability, device_key(index + 1), device_key((index + 91) % 251 + 1)
        )
        repo.deny(pending.device_id)

    devices = repo.list_devices()
    assert len(devices) <= MAX_DEVICE_RECORDS
    assert any(device.status == "revoked" for device in devices)

    # The revoked key still cannot re-pair after all that churn.
    offer = repo.create_offer()
    with pytest.raises(PairingRejected):
        repo.consume_offer(offer.capability, revoked_key, device_key(202))


def test_cancel_offer_expires_only_the_matching_active_offer(tmp_path: Path) -> None:
    repo = AuthorizationRepository(make_paths(tmp_path), clock=lambda: 1000)
    offer = repo.create_offer()
    # Wrong id: no effect.
    other = "A" * 22
    assert repo.cancel_offer(other) is False
    assert repo.offer_status()["status"] == "active"
    # Matching id: expired, capability no longer consumable, new offer allowed.
    assert repo.cancel_offer(offer.offer_id) is True
    assert repo.offer_status()["status"] == "expired"
    with pytest.raises(PairingRejected):
        repo.consume_offer(offer.capability, device_key(1), device_key(2))
    repo.create_offer()
    # Idempotent on a non-active offer.
    assert repo.cancel_offer(offer.offer_id) is False


def test_expired_pending_cannot_be_approved(tmp_path: Path) -> None:
    """A pending record past its timeout is denied, not approvable."""

    from mercury_relay_plugin.authorization import MAX_TTL_SECONDS

    now = [1000]
    repo = AuthorizationRepository(make_paths(tmp_path), clock=lambda: now[0])
    offer = repo.create_offer()
    binding = device_key(2)
    pending = repo.consume_offer(offer.capability, device_key(1), binding)

    now[0] += MAX_TTL_SECONDS  # stall past the pending timeout
    with pytest.raises(AuthorizationError, match="approval rejected"):
        repo.approve(pending.device_id, hashlib.sha256(binding).digest())
    with pytest.raises(AuthorizationError, match="approval rejected"):
        repo.approve_confirmed(pending.device_id, pending.fingerprint)
    assert [d.status for d in repo.list_devices()] == ["denied"]
