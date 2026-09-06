"""Raster-only managed-file adapter. No HTTP, uploads, or core modifications."""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from .session_reads import SessionReadsError

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_PATH_BYTES = 4096
MIME_TYPES = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
}


def _host_helpers():
    # Missing version-sensitive helpers or secure descriptor APIs deny access.
    try:
        from hermes_cli.profiles import get_profile_dir
        from hermes_cli.web_routers.files import _chat_image_extension, _is_sensitive_path
        from hermes_cli.web_server_files import (
            _canonical_path,
            _managed_files_policy,
            _path_is_under,
        )
        if (os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW")
                or not hasattr(os, "O_DIRECTORY")):
            raise RuntimeError
        helpers = (get_profile_dir, _chat_image_extension, _is_sensitive_path,
                   _canonical_path, _managed_files_policy, _path_is_under)
        if not all(callable(helper) for helper in helpers):
            raise RuntimeError
        return helpers
    except Exception:
        raise SessionReadsError("reads_unavailable") from None


def capability() -> dict | None:
    try:
        helpers = _host_helpers()
        # Current policy is installation-scoped and request-independent. No
        # synthetic HTTP identity: future request-dependent policies deny.
        helpers[4](None, create_root=False)
    except Exception:
        return None
    return {"method": "relay.image.read", "max_bytes": MAX_IMAGE_BYTES,
            "mime_types": list(dict.fromkeys(MIME_TYPES.values()))}


def validate_path(raw: object) -> Path:
    try:
        valid = (isinstance(raw, str) and 1 <= len(raw.encode("utf-8")) <= MAX_PATH_BYTES
                 and not any(ord(c) < 32 or ord(c) == 127 for c in raw))
    except UnicodeError:
        valid = False
    if not valid or not isinstance(raw, str):
        raise SessionReadsError("invalid_params")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts or raw.startswith("//"):
        raise SessionReadsError("invalid_params")
    return path


def _read_regular(target: Path) -> bytes:
    # Pin each canonical directory so swapping a component to a symlink cannot
    # redirect the read. O_NONBLOCK prevents a raced FIFO from hanging the host.
    directory = os.open(target.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in target.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise SessionReadsError("image_not_available")
            if info.st_size > MAX_IMAGE_BYTES:
                raise SessionReadsError("response_too_large")
            data = handle.read(MAX_IMAGE_BYTES + 1)
            if len(data) > MAX_IMAGE_BYTES:
                raise SessionReadsError("response_too_large")
            return data
    finally:
        os.close(directory)


def read_image(profile: str, path: Path) -> dict:
    profile_dir, sniff, sensitive, canonical, policy_for, contains = _host_helpers()
    try:
        if not Path(profile_dir(profile)).is_dir():
            raise SessionReadsError("profile_not_available")
    except Exception:
        raise SessionReadsError("profile_not_available") from None
    try:
        policy = policy_for(None, create_root=False)
    except Exception:
        raise SessionReadsError("reads_unavailable") from None
    try:
        target = canonical(path, require_exists=True)
        if sensitive(path) or sensitive(target):
            raise SessionReadsError("image_not_available")
        if policy.locked_root is not None and not contains(policy.locked_root, target):
            raise SessionReadsError("image_not_available")
        mime = MIME_TYPES.get(target.suffix.lower())
        if mime is None:
            raise SessionReadsError("image_not_available")
        data = _read_regular(target)
        if MIME_TYPES.get(sniff(data)) != mime:
            raise SessionReadsError("image_not_available")
        return {"mime_type": mime, "size": len(data),
                "base64": base64.b64encode(data).decode("ascii")}
    except SessionReadsError:
        raise
    except Exception:
        raise SessionReadsError("image_not_available") from None