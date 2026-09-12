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

    state_text = paths.state_path.read_text(encoding="utf-8")
    assert base64.b64encode(offer.capability).decode("ascii") not in state_text
    assert base64.b64encode(hashlib.sha256(offer.capability).digest()).decode("ascii") in state_text
    assert stat.S_IMODE(paths.state_path.stat().st_mode) == 0o600


def test_new_offer_supersedes_the_active_one(tmp_path: Path) -> None:
    """The owner asking for a new QR always gets one. The previous offer's
    capability stops working the moment the new offer exists, so at most one
    offer is ever redeemable."""

    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    first = repo.create_offer()
    second = repo.create_offer()

    assert second.offer_id != first.offer_id
    assert repo.offer_status()["offer_id"] == second.offer_id
    assert repo.offer_status()["status"] == "active"
    device_key = bytes(range(32))
    channel_binding = bytes(32)
    with pytest.raises(PairingRejected):
        repo.consume_offer(first.capability, device_key, channel_binding)
    # The superseding offer itself still redeems normally.
    assert repo.consume_offer(second.capability, device_key, channel_binding) is not None


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


def test_revoked_history_compacts_without_forgetting_keys(tmp_path: Path) -> None:
    from mercury_relay_plugin.authorization import MAX_DEVICE_RECORDS

    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    revoked = []
    for index in range(MAX_DEVICE_RECORDS + 4):
        offer = repo.create_offer()
        key = device_key(index + 1)
        pending = repo.consume_offer(offer.capability, key, device_key(90))
        repo.revoke(pending.device_id)
        revoked.append((pending.device_id, key))
        repo = AuthorizationRepository(paths, clock=lambda: 1000)

    assert len(repo.list_devices()) <= MAX_DEVICE_RECORDS
    offer = repo.create_offer()
    for identifier, key in revoked:
        assert not repo.is_authorized(identifier, key)
        with pytest.raises(PairingRejected):
            repo.consume_offer(offer.capability, key, device_key(91))
    assert repo.consume_offer(offer.capability, device_key(100), device_key(92)).status == "pending"


def test_compaction_preserves_active_metadata_and_owner_offer_supersession(tmp_path: Path) -> None:
    from mercury_relay_plugin.authorization import MAX_DEVICE_RECORDS

    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()
    pending = repo.consume_offer(offer.capability, device_key(100), device_key(90))
    approved = repo.approve(pending.device_id, hashlib.sha256(device_key(90)).digest())
    assert repo.note_device_name(approved.device_id, device_key(100), "Fixture phone")
    repo.set_label(approved.device_id, "Fixture nickname")
    for index in range(MAX_DEVICE_RECORDS):
        offer = repo.create_offer()
        old = repo.consume_offer(offer.capability, device_key(index + 1), device_key(90))
        repo.revoke(old.device_id)
    assert StateStore(paths).load()["schema_version"] == 2
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    summary = next(item for item in repo.list_devices() if item.device_id == approved.device_id)
    assert summary.device_name == "Fixture phone"
    assert summary.label == "Fixture nickname"
    assert summary.epoch == approved.epoch
    assert repo.is_authorized(approved.device_id, device_key(100))
    old_offer = repo.create_offer()
    new_offer = repo.create_offer()
    with pytest.raises(PairingRejected):
        repo.consume_offer(old_offer.capability, device_key(101), device_key(90))
    new_pending = repo.consume_offer(new_offer.capability, device_key(101), device_key(90))
    assert new_pending.status == "pending"


def test_compaction_upgrades_legacy_state_only_when_needed(tmp_path: Path) -> None:
    from mercury_relay_plugin.authorization import MAX_DEVICE_RECORDS

    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    for index in range(MAX_DEVICE_RECORDS + 1):
        offer = repo.create_offer()
        pending = repo.consume_offer(offer.capability, device_key(index + 1), device_key(90))
        repo.revoke(pending.device_id)
        if index < MAX_DEVICE_RECORDS:
            assert StateStore(paths).load()["schema_version"] == 1
    state = StateStore(paths).load()
    # Old StateStore readers reject schema 2 before touching any key evidence.
    assert state["schema_version"] == 2
    assert state["revoked_key_digests"]
    identity = HostIdentityStore(paths).load_or_create()
    assert identity.public_key == repo.create_offer().host_public_key
    state["schema_version"] = 1
    StateStore(paths).save(state)
    with pytest.raises(AuthorizationError, match="authorization state invalid"):
        repo.list_devices()


def test_evidence_saturation_preserves_revocation_and_reports_owner_recovery(
    tmp_path: Path,
) -> None:
    import mercury_relay_plugin.authorization as authorization
    from mercury_relay_plugin.state_store import MAX_STATE_BYTES

    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    count = authorization.MAX_DEVICE_RECORDS + authorization.MAX_REVOKED_KEY_DIGESTS
    revoked = []
    pending = None
    for index in range(count):
        offer = repo.create_offer()
        pending = repo.consume_offer(offer.capability, index.to_bytes(32, "big"), device_key(90))
        if index < count - 1:
            revoked.append(repo.revoke(pending.device_id))
    # The last device is still active when storage fills: revocation must work
    # even though fresh pairing cannot proceed. No reserved evidence slot needed.
    assert pending is not None
    approved = repo.approve(pending.device_id, hashlib.sha256(device_key(90)).digest())
    before = paths.state_path.read_bytes()
    with pytest.raises(AuthorizationError, match="revocation history full.*new relay profile"):
        repo.create_offer()
    assert paths.state_path.read_bytes() == before
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    assert repo.is_authorized(approved.device_id, (count - 1).to_bytes(32, "big"))
    revoked.append(repo.revoke(approved.device_id))
    assert repo.revoke(revoked[-1].device_id) == revoked[-1]
    assert not repo.is_authorized(revoked[-1].device_id, (count - 1).to_bytes(32, "big"))
    state = StateStore(paths).load()
    assert len(state["revoked_key_digests"]) == authorization.MAX_REVOKED_KEY_DIGESTS
    assert len(state["devices"]) == authorization.MAX_DEVICE_RECORDS
    assert paths.state_path.stat().st_size < MAX_STATE_BYTES
    with pytest.raises(AuthorizationError, match="revocation history full"):
        repo.create_offer()


@pytest.mark.parametrize("evidence", [None, {}, ["invalid"], [1], ["A" * 44]])
def test_malformed_revocation_evidence_fails_closed(tmp_path: Path, evidence) -> None:
    paths = make_paths(tmp_path)
    StateStore(paths).save({"schema_version": 2, "devices": [], "revoked_key_digests": evidence})
    with pytest.raises(AuthorizationError, match="authorization state invalid"):
        AuthorizationRepository(paths).list_devices()


def test_missing_duplicate_and_oversized_revocation_evidence_fail_closed(tmp_path: Path) -> None:
    from mercury_relay_plugin.authorization import MAX_REVOKED_KEY_DIGESTS

    paths = make_paths(tmp_path)
    store = StateStore(paths)
    digest = base64.b64encode(hashlib.sha256(device_key(1)).digest()).decode("ascii")
    for fields in (
        {},
        {"revoked_key_digests": [digest, digest]},
        {"revoked_key_digests": [digest] * (MAX_REVOKED_KEY_DIGESTS + 1)},
    ):
        store.save({"schema_version": 2, "devices": [], **fields})
        with pytest.raises(AuthorizationError, match="authorization state invalid"):
            AuthorizationRepository(paths).list_devices()


def test_compaction_write_failure_preserves_legacy_revocations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mercury_relay_plugin.authorization import MAX_DEVICE_RECORDS
    from mercury_relay_plugin.state_store import StateStoreError

    paths = make_paths(tmp_path)
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    for index in range(MAX_DEVICE_RECORDS):
        offer = repo.create_offer()
        pending = repo.consume_offer(offer.capability, device_key(index + 1), device_key(90))
        repo.revoke(pending.device_id)
    before = paths.state_path.read_bytes()
    with monkeypatch.context() as patcher:

        def fail_save(state):
            raise StateStoreError("injected write failure")

        patcher.setattr(repo.store, "save", fail_save)
        with pytest.raises(AuthorizationError, match="authorization state unavailable"):
            repo.create_offer()
    assert paths.state_path.read_bytes() == before
    repo = AuthorizationRepository(paths, clock=lambda: 1000)
    offer = repo.create_offer()
    for index in range(MAX_DEVICE_RECORDS):
        with pytest.raises(PairingRejected):
            repo.consume_offer(offer.capability, device_key(index + 1), device_key(90))
    assert repo.consume_offer(offer.capability, device_key(100), device_key(90)).status == "pending"


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
