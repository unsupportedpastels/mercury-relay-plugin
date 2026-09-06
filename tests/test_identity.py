from __future__ import annotations

import base64
import inspect
import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.config import profile_paths  # noqa: E402
from mercury_relay_plugin.identity import (  # noqa: E402
    HostIdentityStore,
    IdentityError,
    IdentityStateError,
)
from mercury_relay_plugin.state_store import StateStore  # noqa: E402


def make_paths(tmp_path: Path):
    root = tmp_path / "hermes"
    root.mkdir()
    return profile_paths("default", explicit_path=root)


def test_identity_is_raw_x25519_and_repr_redacts_private_material(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    identity = HostIdentityStore(paths).load_or_create()

    assert len(identity.private_key) == 32
    assert len(identity.public_key) == 32
    assert len(identity.installation_id) == 32
    derived = x25519.X25519PrivateKey.from_private_bytes(identity.private_key)
    assert (
        derived.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        == identity.public_key
    )
    assert base64.b64encode(identity.private_key).decode() not in repr(identity)
    assert "private_key=<redacted>" in repr(identity)
    assert "deterministic" not in inspect.signature(HostIdentityStore.load_or_create).parameters

    assert stat.S_IMODE(paths.agent_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((paths.agent_dir / ".state.lock").stat().st_mode) == 0o600

    state = StateStore(paths).load()
    persisted = state["host_identity"]
    assert set(persisted) == {"installation_id", "private_key", "public_key"}
    assert base64.b64decode(persisted["private_key"], validate=True) == identity.private_key


def test_concurrent_first_starts_share_one_identity(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)

    def start(_: int):
        return HostIdentityStore(paths).load_or_create()

    with ThreadPoolExecutor(max_workers=8) as pool:
        identities = list(pool.map(start, range(32)))

    assert {
        (item.private_key, item.public_key, item.installation_id) for item in identities
    }.__len__() == 1


def test_persisted_identity_must_have_matching_lengths_and_public_key(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    original = HostIdentityStore(paths).load_or_create()
    state = StateStore(paths).load()

    state["host_identity"]["private_key"] = base64.b64encode(b"x" * 31).decode("ascii")
    StateStore(paths).save(state)
    with pytest.raises(IdentityStateError, match="host identity state invalid"):
        HostIdentityStore(paths).load_or_create()

    state["host_identity"]["private_key"] = base64.b64encode(b"y" * 32).decode("ascii")
    state["host_identity"]["public_key"] = base64.b64encode(original.public_key).decode("ascii")
    StateStore(paths).save(state)
    with pytest.raises(IdentityStateError, match="host identity state invalid"):
        HostIdentityStore(paths).load_or_create()


def test_lock_target_symlink_is_rejected_without_parent_permission_mutation(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    os.chmod(paths.data_root, 0o755)
    before = stat.S_IMODE(paths.data_root.stat().st_mode)
    HostIdentityStore(paths).load_or_create()

    lock_path = paths.agent_dir / ".state.lock"
    lock_path.unlink()
    target = tmp_path / "outside-lock"
    target.write_bytes(b"outside")
    lock_path.symlink_to(target)

    with pytest.raises(IdentityError, match="transaction unavailable"):
        HostIdentityStore(paths).load_or_create()
    assert stat.S_IMODE(paths.data_root.stat().st_mode) == before


def test_malformed_state_failure_does_not_echo_raw_state(tmp_path: Path) -> None:
    paths = make_paths(tmp_path)
    paths.agent_dir.mkdir()
    paths.state_path.write_text(json.dumps({"schema_version": 1, "host_identity": "secret-state"}))
    os.chmod(paths.state_path, 0o600)

    with pytest.raises(IdentityStateError) as error:
        HostIdentityStore(paths).load_or_create()
    assert "secret-state" not in str(error.value)
    assert str(error.value) == "host identity state invalid"
