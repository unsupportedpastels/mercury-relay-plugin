from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin.config import (  # noqa: E402
    CONFIG_FILE_NAME,
    DEFAULT_RELAY_ORIGIN,
    STATE_DIR_NAME,
    STATE_FILE_NAME,
    ProfileConfigError,
    ProfilePaths,
    PublicConfigStore,
    profile_paths,
    resolve_data_root,
    validate_profile_id,
)


def test_data_root_uses_explicit_path_before_environment(monkeypatch, tmp_path):
    explicit = tmp_path / "explicit"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "from-env"))

    assert resolve_data_root(explicit) == explicit
    assert resolve_data_root() == Path(tmp_path / "from-env")


def test_data_root_fallback_uses_home_convention_without_hardcoded_home(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "user"))

    if os.name == "nt":
        # Hermes itself uses %LOCALAPPDATA%\hermes on Windows.
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
        assert resolve_data_root() == tmp_path / "local" / "hermes"
        monkeypatch.delenv("LOCALAPPDATA")
        assert resolve_data_root() == tmp_path / "user" / "AppData" / "Local" / "hermes"
    else:
        assert resolve_data_root() == tmp_path / "user" / ".hermes"


@pytest.mark.parametrize(
    "profile_id",
    ["", "Default", "bad.name", "../escape", "A" + "a" * 63, "a" * 65],
)
def test_profile_identifier_is_strict(profile_id):
    with pytest.raises(ProfileConfigError):
        validate_profile_id(profile_id)


@pytest.mark.parametrize("profile_id", ["default", "fixture_profile", "a-1", "z" + "a" * 63])
def test_profile_identifier_accepts_hermes_grammar(profile_id):
    assert validate_profile_id(profile_id) == profile_id


def test_profile_paths_keep_state_under_plugin_directory(tmp_path):
    paths = profile_paths("fixture_profile", explicit_path=tmp_path / "hermes")

    assert isinstance(paths, ProfilePaths)
    assert paths.data_root == tmp_path / "hermes"
    assert paths.agent_dir == paths.data_root / STATE_DIR_NAME
    assert paths.config_path == paths.agent_dir / CONFIG_FILE_NAME
    assert paths.state_path == paths.agent_dir / STATE_FILE_NAME


def test_public_config_is_separate_and_rejects_private_material(tmp_path):
    data_root = tmp_path / "hermes"
    data_root.mkdir()
    paths = profile_paths("default", explicit_path=data_root)
    store = PublicConfigStore(paths)

    store.save(
        {
            "schema_version": 1,
            "profile_id": "default",
            "request_timeout_seconds": 30,
        }
    )
    loaded = store.load()

    assert loaded["profile_id"] == "default"
    assert paths.config_path != paths.state_path
    assert "private_key" not in json.dumps(loaded)

    with pytest.raises(ProfileConfigError):
        store.save(
            {
                "schema_version": 1,
                "profile_id": "default",
                "private_key": "not-config",
            }
        )

    with pytest.raises(ProfileConfigError, match="loopback Hermes origins"):
        store.save(
            {
                "schema_version": 1,
                "profile_id": "default",
                "hermes_origin": "http://localhost:8000",
            }
        )


@pytest.mark.parametrize(
    "field",
    [
        "client_secret",
        "refresh_token",
        "bearer_token",
        "api_key",
        "apikey",
        "authorization",
    ],
)
def test_public_config_rejects_common_secret_field_names(tmp_path, field):
    paths = profile_paths("default", explicit_path=tmp_path / "hermes")
    paths.data_root.mkdir()

    with pytest.raises(ProfileConfigError):
        PublicConfigStore(paths).save(
            {"schema_version": 1, "profile_id": "default", field: "not-public"}
        )


@pytest.mark.parametrize(
    ("origin", "canonical"),
    [
        ("https://relay.example.net", "https://relay.example.net"),
        ("wss://relay.example.net", "wss://relay.example.net"),
        ("https://relay.example.net/", "https://relay.example.net"),
        ("HTTPS://Relay.Example.NET", "https://relay.example.net"),
        ("https://relay.example.net:8443", "https://relay.example.net:8443"),
        ("wss://[2001:db8::1]:443", "wss://[2001:db8::1]:443"),
    ],
)
def test_relay_origin_canonical_forms_are_accepted(origin, canonical):
    from mercury_relay_plugin.config import canonicalize_relay_origin

    assert canonicalize_relay_origin(origin) == canonical


@pytest.mark.parametrize(
    "origin",
    [
        "http://relay.example.net",
        "ftp://relay.example.net",
        "https://",
        "https://user@relay.example.net",
        "https://user:secret@relay.example.net",
        "https://relay.example.net/path",
        "https://relay.example.net/..",
        "https://relay.example.net?query=1",
        "https://relay.example.net#fragment",
        "https://relay.example.net:not-a-port",
        "https://relay.example.net:0",
        "https://relay.example.net:70000",
        "https://relay.example.net:",
        "https://@relay.example.net",
        "https://relay.example.net\t",
        "https://relay.example.net\x00",
        "https://relay. example.net",
        "relay.example.net",
        "https:relay.example.net",
        "https://" + "a" * 300 + ".example.net",
        "",
        None,
        42,
    ],
)
def test_relay_origin_non_canonical_forms_are_rejected(origin):
    from mercury_relay_plugin.config import canonicalize_relay_origin

    with pytest.raises(ProfileConfigError):
        canonicalize_relay_origin(origin)


def test_public_config_normalizes_relay_origin(tmp_path):
    data_root = tmp_path / "hermes"
    data_root.mkdir()
    paths = profile_paths("default", explicit_path=data_root)
    store = PublicConfigStore(paths)
    store.save(
        {
            "schema_version": 1,
            "profile_id": "default",
            "relay_origin": "HTTPS://Relay.Example.NET/",
        }
    )
    assert store.load()["relay_origin"] == "https://relay.example.net"

    with pytest.raises(ProfileConfigError):
        store.save(
            {
                "schema_version": 1,
                "profile_id": "default",
                "relay_origin": "https://user@relay.example.net/path?x=1",
            }
        )


def test_public_config_and_directories_are_owner_only_on_posix(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX mode contract")

    data_root = tmp_path / "hermes"
    data_root.mkdir()
    os.chmod(data_root, 0o755)
    before = stat.S_IMODE(data_root.stat().st_mode)
    paths = profile_paths("default", explicit_path=data_root)
    PublicConfigStore(paths).save({"schema_version": 1, "profile_id": "default"})

    assert stat.S_IMODE(data_root.stat().st_mode) == before
    assert stat.S_IMODE(paths.agent_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(paths.config_path.stat().st_mode) == 0o600


def test_profile_paths_reject_symlinked_data_root(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    paths = profile_paths("default", explicit_path=link)
    with pytest.raises(ProfileConfigError):
        PublicConfigStore(paths).save({"schema_version": 1, "profile_id": "default"})


def test_default_relay_origin_is_the_hosted_relay_and_canonical():
    from mercury_relay_plugin.config import canonicalize_relay_origin

    # The baked-in default must itself pass the origin rules, or every fresh
    # install would fail at connection time instead of dialing out.
    assert canonicalize_relay_origin(DEFAULT_RELAY_ORIGIN) == DEFAULT_RELAY_ORIGIN
    assert DEFAULT_RELAY_ORIGIN.startswith("https://")


def test_fresh_install_uses_default_relay_origin_without_writing_a_file(tmp_path):
    data_root = tmp_path / "hermes"
    data_root.mkdir()
    paths = profile_paths("default", explicit_path=data_root)
    store = PublicConfigStore(paths)

    assert store.load()["relay_origin"] == DEFAULT_RELAY_ORIGIN
    assert not paths.config_path.exists()


def test_config_file_without_relay_origin_gets_default_at_load_only(tmp_path):
    data_root = tmp_path / "hermes"
    data_root.mkdir()
    paths = profile_paths("default", explicit_path=data_root)
    store = PublicConfigStore(paths)
    store.save({"schema_version": 1, "profile_id": "default", "request_timeout_seconds": 20})

    loaded = store.load()
    assert loaded["relay_origin"] == DEFAULT_RELAY_ORIGIN
    assert loaded["request_timeout_seconds"] == 20
    # Applied at load time, never persisted: a later default reaches this file.
    on_disk = json.loads(paths.config_path.read_text(encoding="utf-8"))
    assert "relay_origin" not in on_disk


def test_explicit_relay_origin_overrides_default(tmp_path):
    data_root = tmp_path / "hermes"
    data_root.mkdir()
    paths = profile_paths("default", explicit_path=data_root)
    store = PublicConfigStore(paths)
    store.save(
        {"schema_version": 1, "profile_id": "default", "relay_origin": "https://relay.example.net"}
    )

    assert store.load()["relay_origin"] == "https://relay.example.net"
