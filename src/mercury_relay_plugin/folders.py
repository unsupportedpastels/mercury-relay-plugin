"""Versioned, policy-confined folder browsing and creation for Mercury Relay.

This adapter deliberately sits on Hermes' managed-files policy instead of
reaching through a dashboard route or starting a helper process.  The host
policy decides the default/locked root and sensitive-path taxonomy; the local
secure filesystem primitives then re-check every component and perform the
actual directory operations without following links.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import secure_fs
from .config import validate_profile_id
from .session_reads import SessionReadsError

FOLDER_CAPABILITY_VERSION = 1
MAX_FOLDER_ENTRIES = 500
MAX_FOLDER_SCAN_ENTRIES = MAX_FOLDER_ENTRIES + 1
MAX_FOLDER_PATH_CHARS = 1_024
MAX_FOLDER_NAME_BYTES = 255
MAX_FOLDER_LISTING_BYTES = 1_024 * 1_024

FOLDER_CAPABILITY = {
    "version": FOLDER_CAPABILITY_VERSION,
    "list_method": "relay.folders.list",
    "create_method": "relay.folders.create",
}


@dataclass(frozen=True, slots=True)
class _ManagedFilesPolicy:
    default_path: Path
    locked_root: Path | None
    can_change_path: bool


HostHelpers = tuple[
    Callable[[str], Any],
    Callable[[Path], bool],
    Callable[..., Path],
    Callable[..., Any],
    Callable[[Path, Path], bool],
]


def _descriptor_secure_supported() -> bool:
    """Whether this host has the descriptor primitives the relay requires."""

    return (
        os.name == "posix"
        and os.open in os.supports_dir_fd
        and hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
    )


def _host_helpers() -> HostHelpers:
    """Load the installed Hermes managed-files policy without version guessing.

    Hermes currently keeps these helpers in ``web_server.py`` while the
    split-module layout is used by some released installations.  Either shape
    is accepted only when the complete policy surface is present.
    """

    try:
        from hermes_cli.profiles import get_profile_dir
    except Exception:
        raise SessionReadsError("folders_unavailable") from None

    try:
        from hermes_cli.web_server_files import (
            _canonical_path,
            _managed_files_policy,
            _path_is_under,
        )
    except Exception:
        try:
            from hermes_cli.web_server import (
                _canonical_path,
                _managed_files_policy,
                _path_is_under,
            )
        except Exception:
            raise SessionReadsError("folders_unavailable") from None

    try:
        from hermes_cli.web_routers.files import _is_sensitive_path
    except Exception:
        try:
            from hermes_cli.web_server import _is_sensitive_path
        except Exception:
            raise SessionReadsError("folders_unavailable") from None

    helpers: HostHelpers = (
        get_profile_dir,
        _is_sensitive_path,
        _canonical_path,
        _managed_files_policy,
        _path_is_under,
    )
    if not all(callable(helper) for helper in helpers):
        raise SessionReadsError("folders_unavailable")
    required = ("open_directory_nofollow", "is_link_like")
    if not all(callable(getattr(secure_fs, name, None)) for name in required):
        raise SessionReadsError("folders_unavailable")
    return helpers


def _path_units(raw: str) -> int:
    """Match Kotlin/Native String.length, including supplementary characters."""
    return len(raw.encode("utf-16-le")) // 2


def validate_path(raw: object) -> Path:
    """Validate a canonical absolute path without resolving it."""

    try:
        valid = (
            isinstance(raw, str)
            and 1 <= _path_units(raw) <= MAX_FOLDER_PATH_CHARS
            and not any(ord(char) < 32 or ord(char) == 127 for char in raw)
            and "\\" not in raw
        )
    except UnicodeError:
        valid = False
    if not valid or not isinstance(raw, str):
        raise SessionReadsError("invalid_params")
    if not raw.startswith("/") or "//" in raw or any(
        component in {".", ".."} for component in raw.split("/")
    ):
        raise SessionReadsError("invalid_params")
    path = Path(raw)
    if not path.is_absolute():
        raise SessionReadsError("invalid_params")
    return path


def validate_name(raw: object) -> str:
    """Validate one directory component for the create operation."""

    try:
        valid = (
            isinstance(raw, str)
            and 1 <= len(raw.encode("utf-8")) <= MAX_FOLDER_NAME_BYTES
            and not any(ord(char) < 32 or ord(char) == 127 for char in raw)
            and "/" not in raw
            and "\\" not in raw
            and raw not in {".", ".."}
        )
    except UnicodeError:
        valid = False
    if not valid or not isinstance(raw, str):
        raise SessionReadsError("invalid_params")
    return raw


def _require_secure_adapter(helpers: HostHelpers) -> None:
    if not _descriptor_secure_supported():
        raise SessionReadsError("folders_unavailable")
    if not all(callable(helper) for helper in helpers):
        raise SessionReadsError("folders_unavailable")
    for name in ("open_directory_nofollow", "is_link_like"):
        if not callable(getattr(secure_fs, name, None)):
            raise SessionReadsError("folders_unavailable")


def _as_policy(raw: Any) -> _ManagedFilesPolicy:
    try:
        default_path = Path(raw.default_path)
        locked_value = raw.locked_root
        locked_root = None if locked_value is None else Path(locked_value)
        can_change_path = raw.can_change_path
    except Exception:
        raise SessionReadsError("folders_unavailable") from None
    if (
        not default_path.is_absolute()
        or locked_root is not None
        and not locked_root.is_absolute()
        or not isinstance(can_change_path, bool)
    ):
        raise SessionReadsError("folders_unavailable")
    return _ManagedFilesPolicy(default_path, locked_root, can_change_path)


def _bound_listing(result: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        encoded_size = len(encoded.encode("utf-8"))
    except (TypeError, UnicodeError, ValueError, RecursionError):
        raise SessionReadsError("folder_not_available") from None
    if encoded_size > MAX_FOLDER_LISTING_BYTES:
        raise SessionReadsError("response_too_large")
    return result


def _safe_close(handle: Any) -> None:
    with suppress(Exception):
        handle.close()


class FolderService:
    """Serve the versioned folder extension through a secure host adapter."""

    def __init__(self, *, helpers_factory: Callable[[], HostHelpers] | None = None) -> None:
        if helpers_factory is not None and not callable(helpers_factory):
            raise TypeError("helpers_factory must be callable")
        self._helpers_factory = helpers_factory or _host_helpers

    def _context(self, profile: str) -> tuple[HostHelpers, _ManagedFilesPolicy]:
        try:
            validate_profile_id(profile)
        except Exception:
            raise SessionReadsError("profile_not_available") from None
        try:
            helpers = self._helpers_factory()
            _require_secure_adapter(helpers)
        except SessionReadsError:
            raise
        except Exception:
            raise SessionReadsError("folders_unavailable") from None

        try:
            profile_path = Path(helpers[0](profile))
            profile_handle = secure_fs.open_directory_nofollow(profile_path)
        except Exception:
            raise SessionReadsError("profile_not_available") from None
        else:
            _safe_close(profile_handle)

        try:
            policy = _as_policy(helpers[3](None, create_root=False))
        except SessionReadsError:
            raise
        except Exception:
            raise SessionReadsError("folders_unavailable") from None
        return helpers, policy

    @staticmethod
    def _under(helpers: HostHelpers, root: Path, target: Path) -> bool:
        try:
            return helpers[4](root, target) is True
        except Exception:
            raise SessionReadsError("folder_not_available") from None

    @staticmethod
    def _sensitive(helpers: HostHelpers, target: Path) -> bool:
        try:
            return helpers[1](target) is True
        except Exception:
            raise SessionReadsError("folder_not_available") from None

    @staticmethod
    def _open_existing_directory(path: Path) -> Any:
        try:
            return secure_fs.open_directory_nofollow(path)
        except Exception:
            raise SessionReadsError("folder_not_available") from None

    def _resolve_existing(
        self,
        helpers: HostHelpers,
        policy: _ManagedFilesPolicy,
        raw_path: object,
        *,
        allow_default: bool,
    ) -> Path:
        if raw_path is None:
            if not allow_default:
                raise SessionReadsError("invalid_params")
            candidate = policy.locked_root or policy.default_path
        else:
            requested = validate_path(raw_path)
            # The official managed-files route treats / as the locked root
            # alias.  Preserve that behavior without allowing a root escape.
            candidate = (
                policy.locked_root
                if policy.locked_root is not None and requested == Path("/")
                else requested
            )

        if policy.locked_root is not None and not self._under(
            helpers, policy.locked_root, candidate
        ):
            raise SessionReadsError("folder_not_available")
        if self._sensitive(helpers, candidate):
            raise SessionReadsError("folder_not_available")

        # Open the caller spelling first, not only its resolved spelling. This
        # refuses an existing symlink alias before canonicalization.
        first = self._open_existing_directory(candidate)
        _safe_close(first)
        try:
            target = Path(helpers[2](candidate, require_exists=True))
        except Exception:
            raise SessionReadsError("folder_not_available") from None
        if not target.is_absolute():
            raise SessionReadsError("folder_not_available")
        if _path_units(str(target)) > MAX_FOLDER_PATH_CHARS:
            raise SessionReadsError("folder_not_available")
        if policy.locked_root is not None and not self._under(
            helpers, policy.locked_root, target
        ):
            raise SessionReadsError("folder_not_available")
        if self._sensitive(helpers, target):
            raise SessionReadsError("folder_not_available")
        final = self._open_existing_directory(target)
        _safe_close(final)
        return target

    @staticmethod
    def _metadata(policy: _ManagedFilesPolicy, target: Path) -> dict[str, Any]:
        locked = str(policy.locked_root) if policy.locked_root is not None else None
        parent = None
        if target.parent != target and not (
            policy.locked_root is not None and target == policy.locked_root
        ):
            parent = str(target.parent)
        return {
            "path": str(target),
            "parent": parent,
            "root": locked,
            "locked_root": locked,
            "can_change_path": policy.can_change_path,
        }

    def _list_target(
        self,
        helpers: HostHelpers,
        policy: _ManagedFilesPolicy,
        target: Path,
    ) -> dict[str, Any]:
        handle = self._open_existing_directory(target)
        entries: list[dict[str, Any]] = []
        scanned = 0
        try:
            source: int | Path = handle.fd if handle.fd is not None else handle.path
            with os.scandir(source) as iterator:
                for item in iterator:
                    scanned += 1
                    if scanned > MAX_FOLDER_SCAN_ENTRIES:
                        raise SessionReadsError("response_too_large")
                    name = item.name
                    try:
                        name.encode("utf-8")
                        info = handle.lstat(name)
                    except FileNotFoundError:
                        # A concurrent delete is not a reason to reveal a
                        # filesystem error or fail an otherwise safe listing.
                        continue
                    except (OSError, UnicodeError):
                        raise SessionReadsError("folder_not_available") from None
                    if secure_fs.is_link_like(info):
                        continue
                    if not stat.S_ISDIR(info.st_mode):
                        continue
                    entry_path = target / name
                    if _path_units(str(entry_path)) > MAX_FOLDER_PATH_CHARS:
                        raise SessionReadsError("response_too_large")
                    if self._sensitive(helpers, entry_path):
                        continue
                    entries.append(
                        {
                            "name": name,
                            "path": str(entry_path),
                            "is_dir": True,
                        }
                    )
                    if len(entries) > MAX_FOLDER_ENTRIES:
                        raise SessionReadsError("response_too_large")
        except SessionReadsError:
            raise
        except (OSError, TypeError):
            raise SessionReadsError("folder_not_available") from None
        finally:
            _safe_close(handle)

        entries.sort(
            key=lambda entry: (not entry["is_dir"], entry["name"].casefold(), entry["name"])
        )
        return _bound_listing({**self._metadata(policy, target), "entries": entries})

    def list_folders(self, profile: str, path: object = None) -> dict[str, Any]:
        helpers, policy = self._context(profile)
        target = self._resolve_existing(helpers, policy, path, allow_default=True)
        return self._list_target(helpers, policy, target)

    def create_folder(self, profile: str, parent_path: object, name: object) -> dict[str, Any]:
        helpers, policy = self._context(profile)
        parent = self._resolve_existing(helpers, policy, parent_path, allow_default=False)
        directory_name = validate_name(name)
        target = parent / directory_name
        # Validate the final path before any filesystem mutation, not after mkdir.
        validate_path(str(target))
        if self._sensitive(helpers, target):
            raise SessionReadsError("folder_not_available")
        if policy.locked_root is not None and not self._under(helpers, policy.locked_root, target):
            raise SessionReadsError("folder_not_available")

        handle = self._open_existing_directory(parent)
        try:
            try:
                existing = handle.lstat(directory_name)
            except FileNotFoundError:
                try:
                    handle.mkdir(directory_name, 0o700)
                except FileExistsError:
                    existing = handle.lstat(directory_name)
                else:
                    with suppress(OSError):
                        handle.fsync()
                    existing = handle.lstat(directory_name)
            if secure_fs.is_link_like(existing):
                raise SessionReadsError("folder_not_available")
            if not stat.S_ISDIR(existing.st_mode):
                raise SessionReadsError("folder_exists")
        except SessionReadsError:
            raise
        except (OSError, UnicodeError):
            raise SessionReadsError("folder_create_failed") from None
        finally:
            _safe_close(handle)

        # Re-open the result through the secure path walk before returning it;
        # this fences a rename/symlink race between mkdir and the response.
        created = self._resolve_existing(helpers, policy, str(target), allow_default=False)
        return self._list_target(helpers, policy, created)

    def capability(self) -> dict[str, Any] | None:
        try:
            helpers = self._helpers_factory()
            _require_secure_adapter(helpers)
            policy = _as_policy(helpers[3](None, create_root=False))
            root = policy.locked_root or policy.default_path
            if self._sensitive(helpers, root):
                return None
            if _path_units(str(root)) > MAX_FOLDER_PATH_CHARS:
                return None
            handle = self._open_existing_directory(root)
            _safe_close(handle)
        except Exception:
            return None
        return dict(FOLDER_CAPABILITY)


def capability() -> dict[str, Any] | None:
    """Return the extension descriptor only when the secure adapter is usable."""

    return FolderService().capability()


def list_folders(profile: str, path: object = None) -> dict[str, Any]:
    return FolderService().list_folders(profile, path)


def create_folder(profile: str, parent_path: object, name: object) -> dict[str, Any]:
    return FolderService().create_folder(profile, parent_path, name)


__all__ = [
    "FOLDER_CAPABILITY",
    "FOLDER_CAPABILITY_VERSION",
    "MAX_FOLDER_ENTRIES",
    "MAX_FOLDER_LISTING_BYTES",
    "MAX_FOLDER_NAME_BYTES",
    "MAX_FOLDER_PATH_CHARS",
    "FolderService",
    "capability",
    "create_folder",
    "list_folders",
    "validate_name",
    "validate_path",
]
