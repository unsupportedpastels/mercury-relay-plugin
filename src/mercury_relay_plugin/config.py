"""Profile-scoped paths and the small public configuration surface.

The relay plugin deliberately treats ``HERMES_HOME`` as an already selected
Hermes profile.  It never derives a path from the current working directory,
a project directory, or a user-specific absolute path.  The plugin's own files
live in one owner-only subdirectory below that profile home.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import secure_fs

STATE_DIR_NAME = "mercury-relay"
CONFIG_FILE_NAME = "config.json"
STATE_FILE_NAME = "state.json"
DEFAULT_PROFILE_ID = "default"
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ProfileConfigError(ValueError):
    """Raised when profile configuration or a profile path is unsafe."""


def validate_profile_id(profile_id: str) -> str:
    """Validate and return an on-disk Hermes profile identifier unchanged."""

    if not isinstance(profile_id, str) or PROFILE_ID_RE.fullmatch(profile_id) is None:
        raise ProfileConfigError("invalid profile identifier")
    return profile_id


MAX_RELAY_ORIGIN_CHARS = 256


def canonicalize_relay_origin(origin: Any) -> str:
    """Parse and return the canonical relay origin, or raise.

    The relay origin must be exactly an origin: an ``https``/``wss`` scheme
    and a hostname with an optional explicit port. Userinfo, paths (other
    than a bare trailing ``/``), query strings, fragments, and malformed
    authorities are rejected so the configured value can never resolve to a
    different host or request target than the operator saw. The returned
    value is normalized (lowercase scheme/host, no trailing slash) and is
    what gets stored and re-validated at connection time.
    """

    from urllib.parse import urlsplit

    if (
        not isinstance(origin, str)
        or not 1 <= len(origin) <= MAX_RELAY_ORIGIN_CHARS
        or any(ch.isspace() or ch == "\x00" for ch in origin)
    ):
        raise ProfileConfigError("invalid relay origin configuration")
    try:
        parts = urlsplit(origin)
        port = parts.port  # Raises on out-of-range or non-numeric ports.
        hostname = parts.hostname
    except ValueError:
        raise ProfileConfigError("invalid relay origin configuration") from None
    if (
        parts.scheme not in {"https", "wss"}
        or not hostname
        or port == 0
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ProfileConfigError("invalid relay origin configuration")
    # Reject authority spellings the parser tolerated but did not consume
    # exactly (e.g. a lone "@" or ":" with empty userinfo/port).
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    canonical = f"{parts.scheme}://{netloc}"
    if origin.rstrip("/").lower() != canonical:
        raise ProfileConfigError("invalid relay origin configuration")
    return canonical


def _absolute_path(path: str | os.PathLike[str]) -> Path:
    try:
        value = os.fspath(path)
    except TypeError:
        raise ProfileConfigError("invalid data root") from None
    if not isinstance(value, str) or not value.strip():
        raise ProfileConfigError("invalid data root")
    expanded = os.path.expanduser(value)
    if not os.path.isabs(expanded):
        expanded = os.path.abspath(expanded)
    else:
        # abspath normalizes dot segments without resolving symlinks.
        expanded = os.path.abspath(expanded)
    return Path(expanded)


def _check_path_components(path: Path) -> None:
    """Reject symlink and non-directory components without resolving a path."""

    candidate = _absolute_path(path)
    parts = candidate.parts
    current = Path(candidate.anchor) if candidate.anchor else Path.cwd()
    for index, part in enumerate(parts):
        if candidate.anchor and index == 0 and part == candidate.anchor:
            continue
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            # The remaining components cannot be existing children of a
            # missing component in a normal directory tree.  Creation is
            # checked again one component at a time by _secure_directory.
            continue
        except OSError:
            raise ProfileConfigError("unsafe profile path") from None
        if secure_fs.is_link_like(info):
            raise ProfileConfigError("symlinks are not allowed in profile paths")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ProfileConfigError("profile path component is not a directory")


def _open_directory_nofollow(path: Path) -> secure_fs.DirectoryHandle:
    """Open a directory component-by-component without following symlinks.

    Returns a :class:`secure_fs.DirectoryHandle`: a descriptor on POSIX, a
    re-validated path on Windows.  Callers must close it.
    """

    candidate = _absolute_path(path)
    try:
        return secure_fs.open_directory_nofollow(candidate)
    except OSError:
        raise ProfileConfigError("unsafe profile directory") from None


def _secure_directory(path: Path) -> None:
    """Create *path* and enforce 0700 only on that plugin-owned leaf.

    Existing ancestors are only inspected.  In particular, an explicit
    ``HERMES_HOME`` or a caller-owned temporary directory must not have its
    permissions changed as a side effect of initializing the agent.
    """

    candidate = _absolute_path(path)
    parent = _open_directory_nofollow(candidate.parent)
    child: secure_fs.DirectoryHandle | None = None
    try:
        try:
            child = parent.open_directory(candidate.name)
        except FileNotFoundError:
            with suppress(FileExistsError):
                parent.mkdir(candidate.name, 0o700)
            child = parent.open_directory(candidate.name)
        child.chmod(0o700)
    except ProfileConfigError:
        raise
    except OSError:
        raise ProfileConfigError("cannot secure profile directory") from None
    finally:
        if child is not None:
            with suppress(OSError):
                child.close()
        with suppress(OSError):
            parent.close()


def resolve_data_root(explicit_path: str | os.PathLike[str] | None = None) -> Path:
    """Return the active Hermes profile home.

    Resolution is intentionally limited to an explicit path, ``HERMES_HOME``,
    or Hermes' platform-native fallback (``~/.hermes`` on POSIX,
    ``%LOCALAPPDATA%\\hermes`` on Windows).
    In particular, this function does not inspect the project directory or
    invent a ``/home/...`` path.
    """

    if explicit_path is not None:
        return _absolute_path(explicit_path)
    configured = os.environ.get("HERMES_HOME", "").strip()
    if configured:
        return _absolute_path(configured)
    return _absolute_path(secure_fs.default_hermes_home())


@dataclass(frozen=True)
class ProfilePaths:
    """Owner-local paths for one explicitly selected Hermes profile."""

    profile_id: str
    data_root: Path
    agent_dir: Path
    config_path: Path
    state_path: Path

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        root = _absolute_path(self.data_root)
        agent = _absolute_path(self.agent_dir)
        config = _absolute_path(self.config_path)
        state = _absolute_path(self.state_path)
        if agent != root / STATE_DIR_NAME:
            raise ProfileConfigError("invalid agent data directory")
        if config != agent / CONFIG_FILE_NAME or state != agent / STATE_FILE_NAME:
            raise ProfileConfigError("invalid profile file path")
        object.__setattr__(self, "data_root", root)
        object.__setattr__(self, "agent_dir", agent)
        object.__setattr__(self, "config_path", config)
        object.__setattr__(self, "state_path", state)

    @property
    def config_file(self) -> Path:
        """Compatibility spelling for the public configuration path."""

        return self.config_path

    @property
    def state_file(self) -> Path:
        """Compatibility spelling for the private state path."""

        return self.state_path

    def ensure(self) -> ProfilePaths:
        """Create the agent directory with owner-only permissions."""

        _secure_directory(self.agent_dir)
        return self


def profile_paths(
    profile_id: str = DEFAULT_PROFILE_ID,
    explicit_path: str | os.PathLike[str] | None = None,
) -> ProfilePaths:
    """Build secure paths rooted in the selected Hermes profile home."""

    validate_profile_id(profile_id)
    root = resolve_data_root(explicit_path)
    agent = root / STATE_DIR_NAME
    return ProfilePaths(
        profile_id=profile_id,
        data_root=root,
        agent_dir=agent,
        config_path=agent / CONFIG_FILE_NAME,
        state_path=agent / STATE_FILE_NAME,
    )


_PRIVATE_CONFIG_MARKERS = frozenset(
    {
        "private",
        "secret",
        "token",
        "password",
        "credential",
        "cookie",
        "bearer",
        "authorization",
        "apikey",
        "capability",
        "pairingoffer",
    }
)
_INTEGER_CONFIG_FIELDS = frozenset(
    {"request_timeout_seconds", "transcript_limit_bytes", "max_devices"}
)
_DEFAULT_PUBLIC_CONFIG: dict[str, Any] = {
    "schema_version": 1,
    "request_timeout_seconds": 30,
}


def _contains_private_config_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            compact = str(key).casefold().replace("_", "").replace("-", "")
            if any(marker in compact for marker in _PRIVATE_CONFIG_MARKERS):
                return True
            if _contains_private_config_key(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_private_config_key(item) for item in value)
    return False


def validate_public_config(config: Mapping[str, Any], profile_id: str) -> dict[str, Any]:
    """Validate public behavioral config and reject secret-like material."""

    if not isinstance(config, Mapping):
        raise ProfileConfigError("public configuration must be an object")
    try:
        value = dict(config)
    except (TypeError, ValueError):
        raise ProfileConfigError("public configuration must be an object") from None
    if _contains_private_config_key(value):
        raise ProfileConfigError("private material is not public configuration")
    if "hermes_origin" in value:
        raise ProfileConfigError("loopback Hermes origins are not supported")
    version = value.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise ProfileConfigError("unsupported configuration schema")
    configured_profile = value.get("profile_id", profile_id)
    if not isinstance(configured_profile, str) or configured_profile != profile_id:
        raise ProfileConfigError("configuration profile mismatch")
    validate_profile_id(configured_profile)

    for field in _INTEGER_CONFIG_FIELDS:
        if field in value:
            number = value[field]
            if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                raise ProfileConfigError("invalid integer configuration")
    # update_check: one anonymous release-version GET to GitHub every six
    # hours (plus on start). Off means the page only checks when asked.
    if "update_check" in value and not isinstance(value["update_check"], bool):
        raise ProfileConfigError("invalid update_check configuration")
    timeout = value.get("request_timeout_seconds")
    if timeout is not None and (timeout < 1 or timeout > 300):
        raise ProfileConfigError("invalid timeout configuration")
    origin = value.get("relay_origin")
    if origin is not None:
        # Canonicalize once here so the stored value is already normalized;
        # the relay client re-validates at connection time.
        value["relay_origin"] = canonicalize_relay_origin(origin)
    return value


class PublicConfigStore:
    """Read and atomically write non-secret profile behavior configuration."""

    def __init__(self, paths: ProfilePaths):
        if not isinstance(paths, ProfilePaths):
            raise ProfileConfigError("public config requires profile paths")
        self.paths = paths

    def _default(self) -> dict[str, Any]:
        value = dict(_DEFAULT_PUBLIC_CONFIG)
        value["profile_id"] = self.paths.profile_id
        return value

    def load(self) -> dict[str, Any]:
        from .state_store import StateStore

        return StateStore(
            self.paths.config_path,
            max_bytes=16 * 1024,
            default=self._default(),
            validator=lambda value: validate_public_config(value, self.paths.profile_id),
            private=False,
        ).load()

    def save(self, config: Mapping[str, Any]) -> None:
        from .state_store import StateStore

        validated = validate_public_config(config, self.paths.profile_id)
        StateStore(
            self.paths.config_path,
            max_bytes=16 * 1024,
            validator=lambda value: validate_public_config(value, self.paths.profile_id),
            private=False,
        ).save(validated)


def load_public_config(paths: ProfilePaths) -> dict[str, Any]:
    """Convenience wrapper for :class:`PublicConfigStore`."""

    return PublicConfigStore(paths).load()


def save_public_config(paths: ProfilePaths, config: Mapping[str, Any]) -> None:
    """Convenience wrapper for :class:`PublicConfigStore`."""

    PublicConfigStore(paths).save(config)
