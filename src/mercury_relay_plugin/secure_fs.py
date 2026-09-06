"""Owner-private file primitives with a POSIX fast path and a Windows fallback.

On POSIX every open is anchored to a directory descriptor and uses
``O_NOFOLLOW``, so a path component swapped for a symlink between check and
use cannot redirect the operation, and the plugin enforces ``0600`` files and
``0700`` directories.

Windows has neither descriptor-relative opens nor ``O_NOFOLLOW``.  The
fallback re-validates every path component with ``lstat`` immediately before
each operation and refuses reparse points (symlinks and junctions).  POSIX
mode bits carry no meaning there; ownership isolation comes from the per-user
ACL on the Hermes home under ``%LOCALAPPDATA%``.  Callers that only need "is
this file owner-private" should use :func:`private_mode_ok`, which is always
true on Windows for that reason.

Every function here raises plain :class:`OSError` subclasses; the callers wrap
them into their own error types without leaking paths.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from contextlib import suppress
from pathlib import Path

IS_POSIX = os.name == "posix"

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOINHERIT = getattr(os, "O_NOINHERIT", 0)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_USE_DIR_FD = IS_POSIX and os.open in os.supports_dir_fd and _O_DIRECTORY != 0
_WINDOWS_REPLACE_RETRY_SECONDS = 2.0

if IS_POSIX:
    import fcntl
else:  # pragma: no cover - exercised on Windows CI only
    import msvcrt


def is_link_like(info: os.stat_result) -> bool:
    """True for symlinks on every platform and for reparse points on Windows."""

    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(_REPARSE_POINT and attributes & _REPARSE_POINT)


def private_mode_ok(mode: int) -> bool:
    """Whether a file's mode bits are owner-only where mode bits mean anything."""

    return not IS_POSIX or stat.S_IMODE(mode) == 0o600


def private_dir_mode_ok(mode: int) -> bool:
    return not IS_POSIX or stat.S_IMODE(mode) == 0o700


def _platform_flags(flags: int) -> int:
    return flags | _O_CLOEXEC | _O_BINARY | _O_NOINHERIT


def _reject_link(info: os.stat_result) -> None:
    if is_link_like(info):
        raise OSError(errno.ELOOP, "reparse point or symlink refused")


def _check_name(name: str) -> None:
    if not name or name in {".", ".."} or os.sep in name or (os.altsep and os.altsep in name):
        raise OSError(errno.EINVAL, "invalid relative name")


class DirectoryHandle:
    """One validated directory: a descriptor on POSIX, a re-checked path on Windows."""

    __slots__ = ("fd", "path")

    def __init__(self, fd: int | None, path: Path) -> None:
        self.fd = fd
        self.path = path

    def close(self) -> None:
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def _child(self, name: str) -> Path:
        _check_name(name)
        return self.path / name

    def lstat(self, name: str) -> os.stat_result:
        _check_name(name)
        if self.fd is not None:
            return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        return os.lstat(self._child(name))

    def open(self, name: str, flags: int, mode: int = 0o600) -> int:
        """Open a regular file below this directory without following links."""

        _check_name(name)
        if self.fd is not None:
            return os.open(name, _platform_flags(flags) | _O_NOFOLLOW, mode, dir_fd=self.fd)
        child = self._child(name)
        if not (flags & os.O_CREAT and flags & os.O_EXCL):
            try:
                _reject_link(os.lstat(child))
            except FileNotFoundError:
                if not flags & os.O_CREAT:
                    raise
        fd = os.open(child, _platform_flags(flags), mode)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def open_directory(self, name: str) -> DirectoryHandle:
        """Open an existing child directory without following links."""

        _check_name(name)
        if self.fd is not None:
            flags = os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW
            fd = os.open(name, flags, dir_fd=self.fd)
            try:
                if not stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError(errno.ENOTDIR, "not a directory")
            except BaseException:
                os.close(fd)
                raise
            return DirectoryHandle(fd, self.path / name)
        child = self._child(name)
        info = os.lstat(child)
        _reject_link(info)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(errno.ENOTDIR, "not a directory")
        return DirectoryHandle(None, child)

    def mkdir(self, name: str, mode: int = 0o700) -> None:
        _check_name(name)
        if self.fd is not None:
            os.mkdir(name, mode, dir_fd=self.fd)
        else:
            os.mkdir(self._child(name), mode)

    def replace(self, source: str, destination: str) -> None:
        _check_name(source)
        _check_name(destination)
        if self.fd is not None:
            os.replace(source, destination, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            return
        # Windows refuses to replace a file that another handle currently has
        # open (a concurrent reader, a second writer racing its own replace,
        # or an indexer). Such holds are brief, so retry within a small bound.
        deadline = time.monotonic() + _WINDOWS_REPLACE_RETRY_SECONDS
        while True:
            try:
                os.replace(self._child(source), self._child(destination))
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)

    def unlink(self, name: str) -> None:
        _check_name(name)
        if self.fd is not None:
            os.unlink(name, dir_fd=self.fd)
        else:
            os.unlink(self._child(name))

    def fsync(self) -> None:
        """Flush directory metadata where the platform supports it."""

        if self.fd is not None:
            os.fsync(self.fd)

    def chmod(self, mode: int) -> None:
        if self.fd is not None:
            os.fchmod(self.fd, mode)


def open_directory_nofollow(path: Path) -> DirectoryHandle:
    """Walk *path* one component at a time, refusing links and non-directories."""

    if _USE_DIR_FD:
        flags = os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW
        fd = os.open(path.anchor or os.path.sep, flags)
        try:
            parts = path.parts[1:] if path.anchor else path.parts
            for part in parts:
                next_fd = os.open(part, flags, dir_fd=fd)
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    os.close(next_fd)
                    raise OSError(errno.ENOTDIR, "not a directory")
                os.close(fd)
                fd = next_fd
            return DirectoryHandle(fd, path)
        except BaseException:
            os.close(fd)
            raise
    anchor = Path(path.anchor) if path.anchor else Path.cwd()
    current = anchor
    for part in path.parts[1:] if path.anchor else path.parts:
        current = current / part
        info = os.lstat(current)
        _reject_link(info)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(errno.ENOTDIR, "not a directory")
    return DirectoryHandle(None, current)


def open_append_nofollow(path: Path, mode: int = 0o600) -> int:
    """Open an owner-private append-only regular file without following links."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if IS_POSIX:
        return os.open(path, _platform_flags(flags) | _O_NOFOLLOW, mode)
    with suppress(FileNotFoundError):
        _reject_link(os.lstat(path))
    return os.open(path, _platform_flags(flags), mode)


def fchmod_private(fd: int, mode: int) -> None:
    """Apply *mode* on POSIX; a no-op where mode bits do not apply."""

    if IS_POSIX:
        os.fchmod(fd, mode)


def try_lock_exclusive(fd: int) -> None:
    """Take a non-blocking exclusive lock or raise :class:`BlockingIOError`."""

    if IS_POSIX:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError as error:  # pragma: no cover - Windows only
        if error.errno in {errno.EACCES, errno.EDEADLOCK, getattr(errno, "EDEADLK", -1)}:
            raise BlockingIOError(error.errno, "locked") from None
        raise


def unlock(fd: int) -> None:
    if IS_POSIX:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # pragma: no cover - Windows only


def default_hermes_home() -> Path:
    """Hermes' platform-native default home, mirroring Hermes itself."""

    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
        base = Path(local_appdata) if local_appdata else Path.home() / "AppData" / "Local"
        return base / "hermes"
    return Path.home() / ".hermes"
