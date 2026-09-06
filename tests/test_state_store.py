from __future__ import annotations

import json
import os
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from conftest import posix_only

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

import mercury_relay_plugin.state_store as state_module  # noqa: E402
from mercury_relay_plugin.config import profile_paths  # noqa: E402
from mercury_relay_plugin.state_store import (  # noqa: E402
    MAX_STATE_BYTES,
    StateStore,
    StateStoreError,
)


def make_store(tmp_path):
    data_root = tmp_path / "hermes"
    data_root.mkdir()
    return StateStore(profile_paths("default", explicit_path=data_root))


def valid_state(**overrides):
    state = {
        "schema_version": 1,
        "devices": [{"device_id": "device-1", "approved": False}],
    }
    state.update(overrides)
    return state


def test_missing_state_has_secure_v1_default(tmp_path):
    store = make_store(tmp_path)

    assert store.load() == {"schema_version": 1, "devices": []}


@posix_only
def test_round_trip_json_object_and_private_mode(tmp_path):
    store = make_store(tmp_path)
    value = valid_state(last_seen=123)

    store.save(value)

    assert store.load() == value
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700


def test_unknown_schema_version_and_boolean_integer_fail_closed(tmp_path):
    store = make_store(tmp_path)
    store.path.parent.mkdir(parents=True)
    store.path.write_text('{"schema_version": true}', encoding="utf-8")

    with pytest.raises(StateStoreError):
        store.load()

    store.path.write_text('{"schema_version": 2}', encoding="utf-8")
    os.chmod(store.path, 0o600)
    with pytest.raises(StateStoreError):
        store.load()

    store.path.write_text(
        '{"schema_version":1,"devices":[],"value":1e309}',
        encoding="utf-8",
    )
    with pytest.raises(StateStoreError):
        store.load()


def test_duplicate_json_keys_are_rejected(tmp_path):
    store = make_store(tmp_path)
    store.path.parent.mkdir(parents=True)
    store.path.write_text('{"schema_version": 1, "devices": [], "devices": []}', encoding="utf-8")
    os.chmod(store.path, 0o600)

    with pytest.raises(StateStoreError):
        store.load()


def test_duplicate_device_ids_are_rejected_on_save_and_load(tmp_path):
    store = make_store(tmp_path)
    duplicate = valid_state(devices=[{"device_id": "same"}, {"device_id": "same"}])

    with pytest.raises(StateStoreError):
        store.save(duplicate)

    store.path.parent.mkdir(parents=True)
    store.path.write_text(json.dumps(duplicate), encoding="utf-8")
    os.chmod(store.path, 0o600)
    with pytest.raises(StateStoreError):
        store.load()


def test_malformed_non_object_non_regular_and_oversized_state_rejected(tmp_path):
    store = make_store(tmp_path)
    store.path.parent.mkdir(parents=True)

    store.path.write_text("not-json", encoding="utf-8")
    os.chmod(store.path, 0o600)
    with pytest.raises(StateStoreError):
        store.load()

    store.path.write_text("[]", encoding="utf-8")
    with pytest.raises(StateStoreError):
        store.load()

    store.path.write_bytes(b"{" + b"x" * MAX_STATE_BYTES + b"}")
    with pytest.raises(StateStoreError):
        store.load()

    store.path.unlink()
    store.path.mkdir()
    with pytest.raises(StateStoreError):
        store.load()


def test_symlink_target_and_component_are_rejected(tmp_path):
    store = make_store(tmp_path)
    store.save(valid_state())

    target = tmp_path / "outside.json"
    target.write_text(json.dumps(valid_state()), encoding="utf-8")
    store.path.unlink()
    store.path.symlink_to(target)
    with pytest.raises(StateStoreError):
        store.load()

    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real", target_is_directory=True)
    with pytest.raises(StateStoreError):
        StateStore(profile_paths("default", explicit_path=link))


def test_atomic_concurrent_writers_leave_valid_json(tmp_path):
    store = make_store(tmp_path)

    def write(index):
        store.save(valid_state(writer=index, devices=[{"device_id": f"device-{index}"}]))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(32)))

    loaded = store.load()
    assert loaded["schema_version"] == 1
    assert len(loaded["devices"]) == 1
    assert not list(store.path.parent.glob(f".{store.path.name}.*.tmp"))


def test_failed_atomic_write_cleans_temp_file(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    original_replace = os.replace

    def fail_replace(source, destination):
        raise OSError("injected failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(StateStoreError):
        store.save(valid_state())
    monkeypatch.setattr(os, "replace", original_replace)

    assert not list(store.path.parent.glob(f".{store.path.name}.*.tmp"))


def test_custom_validator_output_is_what_gets_persisted(tmp_path):
    paths = profile_paths("default", explicit_path=tmp_path / "hermes")
    paths.data_root.mkdir()
    store = StateStore(
        paths,
        validator=lambda value: {**value, "normalized": True},
    )

    store.save({"schema_version": 1, "devices": []})

    assert json.loads(store.path.read_text(encoding="utf-8"))["normalized"] is True


def test_parent_directory_swap_cannot_redirect_state_read(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.save(valid_state())
    original_dir = store.path.parent
    parked_dir = original_dir.with_name("parked-agent")
    outside_dir = tmp_path / "outside-agent"
    outside_dir.mkdir()
    outside_state = outside_dir / store.path.name
    outside_state.write_text(
        json.dumps({"schema_version": 1, "devices": [], "outside_marker": True}),
        encoding="utf-8",
    )
    outside_state.chmod(0o600)
    original_check = state_module._check_path_components
    swapped = False

    def swap_after_check(path):
        nonlocal swapped
        original_check(path)
        if Path(path) == store.path and not swapped:
            original_dir.rename(parked_dir)
            original_dir.symlink_to(outside_dir, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(state_module, "_check_path_components", swap_after_check)

    with pytest.raises(StateStoreError):
        store.load()


def test_parent_directory_swap_cannot_redirect_state_write(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    store.paths.ensure()
    original_dir = store.path.parent
    parked_dir = original_dir.with_name("parked-agent")
    outside_dir = tmp_path / "outside-agent"
    outside_dir.mkdir()
    original_check = state_module._check_path_components
    swapped = False

    def swap_after_check(path):
        nonlocal swapped
        original_check(path)
        if Path(path) == store.path and not swapped:
            original_dir.rename(parked_dir)
            original_dir.symlink_to(outside_dir, target_is_directory=True)
            swapped = True

    monkeypatch.setattr(state_module, "_check_path_components", swap_after_check)

    with pytest.raises(StateStoreError):
        store.save(valid_state())
    assert not (outside_dir / store.path.name).exists()
