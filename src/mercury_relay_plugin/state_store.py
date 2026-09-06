"""Bounded, owner-private JSON state storage for the relay plugin.

This module intentionally implements persistence rather than migrations or
cryptography.  Only schema version 1 is accepted.  Reads are bounded before
JSON parsing, and writes use a same-directory temporary file followed by file
and directory fsyncs and an atomic replace.
"""

from __future__ import annotations

import copy
import json
import math
import os
import secrets
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from . import secure_fs
from .config import (
    STATE_DIR_NAME,
    STATE_FILE_NAME,
    ProfileConfigError,
    ProfilePaths,
    _check_path_components,
    _open_directory_nofollow,
    _secure_directory,
    profile_paths,
)
from .strict_json import StrictJsonError, loads_strict

STATE_SCHEMA_VERSION = 1
MAX_STATE_BYTES = 64 * 1024
_INTEGER_STATE_FIELDS = frozenset(
    {
        "schema_version",
        "created_at",
        "updated_at",
        "expires_at",
        "last_seen",
        "last_seen_at",
        "sequence",
        "epoch",
        "revocation_epoch",
        "count",
        "max_devices",
    }
)


class StateStoreError(ProfileConfigError):
    """Raised for every invalid, unsafe, oversized, or failed state operation."""


def _is_private_file_mode(mode: int) -> bool:
    return secure_fs.private_mode_ok(mode)


def _validate_json_values(value: Any, *, depth: int = 0) -> None:
    """Reject pathological values before serialization or downstream use."""

    if depth > 64:
        raise StateStoreError("state nesting limit exceeded")
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise StateStoreError("state object keys must be strings")
            if key in _INTEGER_STATE_FIELDS and (
                isinstance(nested, bool) or not isinstance(nested, int)
            ):
                raise StateStoreError("invalid integer state field")
            _validate_json_values(nested, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _validate_json_values(nested, depth=depth + 1)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise StateStoreError("state contains a non-finite number")
    elif value is None or isinstance(value, (str, int, bool)):
        return
    else:
        raise StateStoreError("state contains a non-JSON value")


def _validate_device_ids(value: Any, *, seen: set[str] | None = None) -> None:
    """Validate device records and enforce globally unique device IDs."""

    if seen is None:
        seen = set()
    if isinstance(value, Mapping):
        if "device_id" in value:
            device_id = value["device_id"]
            if not isinstance(device_id, str) or not device_id or len(device_id) > 256:
                raise StateStoreError("invalid device identifier")
            if device_id in seen:
                raise StateStoreError("duplicate device identifier")
            seen.add(device_id)
        for key, nested in value.items():
            if key in {"devices", "pending_devices", "authorized_devices"} and not isinstance(
                nested, (list, tuple)
            ):
                raise StateStoreError("device collection must be a list")
            _validate_device_ids(nested, seen=seen)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            _validate_device_ids(nested, seen=seen)


def _validate_state_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StateStoreError("state must be a JSON object")
    result = dict(value)
    version = result.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != STATE_SCHEMA_VERSION:
        raise StateStoreError("unsupported state schema")
    _validate_json_values(result)
    _validate_device_ids(result)
    return result


def _parse_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, StrictJsonError):
        raise StateStoreError("invalid state JSON") from None
    return _validate_state_object(parsed)


def _encode_object(value: Mapping[str, Any], max_bytes: int) -> bytes:
    validated = _validate_state_object(value)
    try:
        encoded = json.dumps(
            validated,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise StateStoreError("state is not encodable JSON") from None
    if len(encoded) > max_bytes:
        raise StateStoreError("state exceeds size limit")
    return encoded


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a regular owner-private file through anchored directory descriptors."""

    _check_path_components(path)
    try:
        os.lstat(path.parent)
    except FileNotFoundError:
        raise
    except OSError:
        raise StateStoreError("cannot inspect state file") from None
    try:
        parent = _open_directory_nofollow(path.parent)
    except ProfileConfigError:
        raise StateStoreError("cannot inspect state file") from None
    fd: int | None = None
    try:
        info = parent.lstat(path.name)
        if secure_fs.is_link_like(info) or not stat.S_ISREG(info.st_mode):
            raise StateStoreError("state file is not a regular file")
        if not _is_private_file_mode(info.st_mode):
            raise StateStoreError("state file permissions are too broad")
        if info.st_size > max_bytes:
            raise StateStoreError("state exceeds size limit")

        fd = parent.open(path.name, os.O_RDONLY)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _is_private_file_mode(opened.st_mode):
            raise StateStoreError("state file is not secure")
        if opened.st_size > max_bytes:
            raise StateStoreError("state exceeds size limit")
        raw = os.read(fd, max_bytes + 1)
        if len(raw) > max_bytes or os.fstat(fd).st_size > max_bytes:
            raise StateStoreError("state exceeds size limit")
        return raw
    except FileNotFoundError:
        raise
    except StateStoreError:
        raise
    except OSError:
        raise StateStoreError("cannot read state file") from None
    finally:
        if fd is not None:
            with suppress(OSError):
                os.close(fd)
        with suppress(OSError):
            parent.close()


def _fsync_directory(directory: secure_fs.DirectoryHandle) -> None:
    try:
        directory.fsync()
    except OSError:
        raise StateStoreError("cannot sync state directory") from None


def _atomic_write(path: Path, data: bytes) -> None:
    """Atomically replace *path* relative to one anchored directory descriptor."""

    parent = path.parent
    _secure_directory(parent)
    _check_path_components(path)
    try:
        directory = _open_directory_nofollow(parent)
    except ProfileConfigError:
        raise StateStoreError("state write failed") from None
    temp_name: str | None = None
    fd: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for _ in range(8):
            candidate = f".{path.name}.{secrets.token_hex(8)}.tmp"
            try:
                fd = directory.open(candidate, flags, 0o600)
                temp_name = candidate
                break
            except FileExistsError:
                continue
        if fd is None or temp_name is None:
            raise StateStoreError("state write failed")
        secure_fs.fchmod_private(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory.replace(temp_name, path.name)
        temp_name = None
        _fsync_directory(directory)
    except StateStoreError:
        raise
    except (OSError, ValueError):
        raise StateStoreError("state write failed") from None
    finally:
        if fd is not None:
            with suppress(OSError):
                os.close(fd)
        if temp_name is not None:
            with suppress(OSError):
                directory.unlink(temp_name)
        with suppress(OSError):
            directory.close()


class StateStore:
    """Bounded JSON state store rooted below ``mercury-relay``."""

    def __init__(
        self,
        paths_or_path: ProfilePaths | str | os.PathLike[str],
        *,
        max_bytes: int = MAX_STATE_BYTES,
        default: Mapping[str, Any] | None = None,
        validator: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        private: bool = True,
    ) -> None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise StateStoreError("invalid state size limit")
        self.max_bytes = max_bytes
        self.private = private
        self.paths = paths_or_path if isinstance(paths_or_path, ProfilePaths) else None
        if self.paths is not None:
            path = self.paths.state_path
        else:
            try:
                path = Path(paths_or_path)
            except TypeError:
                raise StateStoreError("invalid state path") from None
            # Direct construction remains constrained to the agent-owned
            # namespace; callers needing a path should use profile_paths().
            if path.name not in {STATE_FILE_NAME, "config.json"}:
                raise StateStoreError("state path is outside agent namespace")
        try:
            self.path = Path(os.path.abspath(os.path.expanduser(os.fspath(path))))
        except (TypeError, ValueError):
            raise StateStoreError("invalid state path") from None
        if self.path.parent.name != STATE_DIR_NAME:
            raise StateStoreError("state path is outside agent namespace")
        try:
            _check_path_components(self.path)
        except ProfileConfigError:
            raise StateStoreError("unsafe state path") from None
        self.validator = validator
        self.default = copy.deepcopy(dict(default or {"schema_version": 1, "devices": []}))
        self._validate(self.default)

    @classmethod
    def for_profile(
        cls,
        profile_id: str = "default",
        explicit_path: str | os.PathLike[str] | None = None,
        **kwargs: Any,
    ) -> StateStore:
        return cls(profile_paths(profile_id, explicit_path), **kwargs)

    def _validate(self, value: Mapping[str, Any]) -> dict[str, Any]:
        try:
            validated = _validate_state_object(value)
            if self.validator is not None:
                candidate = self.validator(validated)
                if not isinstance(candidate, Mapping):
                    raise StateStoreError("state validator returned a non-object")
                validated = dict(candidate)
                _validate_state_object(validated)
            return validated
        except StateStoreError:
            raise
        except Exception:
            # Do not leak callback details, paths, state values, or raw
            # provider exceptions through this persistence boundary.
            raise StateStoreError("invalid state object") from None

    def load(self) -> dict[str, Any]:
        try:
            raw = _read_bounded(self.path, self.max_bytes)
        except FileNotFoundError:
            return copy.deepcopy(self.default)
        except StateStoreError:
            raise
        except Exception:
            raise StateStoreError("state read failed") from None
        return self._validate(_parse_object(raw))

    def save(self, value: Mapping[str, Any]) -> None:
        validated = self._validate(value)
        encoded = _encode_object(validated, self.max_bytes)
        try:
            if self.paths is not None:
                self.paths.ensure()
            _atomic_write(self.path, encoded)
        except (ProfileConfigError, StateStoreError):
            raise StateStoreError("state write failed") from None
        except Exception:
            raise StateStoreError("state write failed") from None


# Short aliases make the intended API discoverable without exposing internals.
JsonStateStore = StateStore


def load_json_object(store):
    return store.load()


def save_json_object(store, value):
    return store.save(value)


# Avoid an unused import warning in environments that inspect the module's
# public constants while keeping the path contract visible in one place.
__all__ = [
    "MAX_STATE_BYTES",
    "STATE_SCHEMA_VERSION",
    "JsonStateStore",
    "StateStore",
    "StateStoreError",
    "load_json_object",
    "save_json_object",
]
