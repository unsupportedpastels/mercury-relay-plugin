"""Owner-local host identity and the process-safe state transaction lock.

The identity is deliberately small: one raw X25519 static private/public key
pair and one random installation identifier.  Private state is serialized only
as canonical base64 inside the existing owner-private ``StateStore`` document.
"""

from __future__ import annotations

import base64
import binascii
import copy
import fcntl
import hmac
import os
import secrets
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .config import ProfileConfigError, ProfilePaths, _open_directory_nofollow, profile_paths
from .state_store import StateStore, StateStoreError

IDENTITY_FIELD = "host_identity"
LOCK_FILE_NAME = ".state.lock"
RAW_BYTES = 32
LOCK_TIMEOUT_SECONDS = 5.0
_MAX_B64_TEXT = 128
_CONSTRUCTOR_TOKEN = object()


class IdentityError(ProfileConfigError):
    """Raised for an unsafe identity operation without sensitive detail."""


class IdentityStateError(IdentityError):
    """Raised when persisted host identity state is missing or malformed."""


def _b64encode(value: bytes) -> str:
    """Encode bytes using the one canonical base64 representation we persist."""

    return base64.b64encode(value).decode("ascii")


def _b64decode_exact(value: Any, expected_length: int) -> bytes:
    if not isinstance(value, str) or len(value) > _MAX_B64_TEXT or not value:
        raise ValueError
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ValueError from None
    if len(decoded) != expected_length or _b64encode(decoded) != value:
        raise ValueError
    return decoded


def _b64url_encode(value: bytes) -> str:
    """Canonical URL-safe encoding for identifiers that travel in URL paths."""

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode_exact(value: Any, expected_length: int) -> bytes:
    if not isinstance(value, str) or len(value) > _MAX_B64_TEXT or not value:
        raise ValueError
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ValueError from None
    if len(decoded) != expected_length or _b64url_encode(decoded) != value:
        raise ValueError
    return decoded


def _coerce_paths(source: ProfilePaths | StateStore | str | os.PathLike[str]) -> ProfilePaths:
    if isinstance(source, ProfilePaths):
        return source
    if isinstance(source, StateStore):
        if source.paths is None:
            raise IdentityError("invalid identity store")
        return source.paths
    try:
        candidate = Path(source)
    except (TypeError, ValueError):
        raise IdentityError("invalid identity store") from None
    try:
        if candidate.name == "state.json":
            StateStore(candidate)
            return profile_paths(explicit_path=candidate.parent.parent)
        return profile_paths(explicit_path=candidate)
    except (ProfileConfigError, StateStoreError):
        raise IdentityError("invalid identity store") from None


def _store_for(
    source: ProfilePaths | StateStore | str | os.PathLike[str],
) -> tuple[ProfilePaths, StateStore]:
    if isinstance(source, StateStore):
        paths = _coerce_paths(source)
        return paths, source
    paths = _coerce_paths(source)
    return paths, StateStore(paths)


def _open_lock(directory_fd: int, name: str) -> int:
    """Open only a regular 0600 lock target, without following symlinks."""

    flags_common = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    for _ in range(2):
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                fd = os.open(
                    name,
                    flags_common | os.O_CREAT | os.O_EXCL | nofollow,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            except OSError:
                raise IdentityError("transaction unavailable") from None
            try:
                os.fchmod(fd, 0o600)
                checked = os.fstat(fd)
                if not stat.S_ISREG(checked.st_mode) or stat.S_IMODE(checked.st_mode) != 0o600:
                    raise IdentityError("transaction unavailable")
                return fd
            except IdentityError:
                with suppress(OSError):
                    os.close(fd)
                raise
            except OSError:
                with suppress(OSError):
                    os.close(fd)
                raise IdentityError("transaction unavailable") from None
        except OSError:
            raise IdentityError("transaction unavailable") from None

        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise IdentityError("transaction unavailable")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise IdentityError("transaction unavailable")
        try:
            fd = os.open(name, flags_common | nofollow, dir_fd=directory_fd)
            checked = os.fstat(fd)
            if not stat.S_ISREG(checked.st_mode) or stat.S_IMODE(checked.st_mode) != 0o600:
                raise IdentityError("transaction unavailable")
            return fd
        except IdentityError:
            with suppress(UnboundLocalError):
                os.close(fd)  # type: ignore[possibly-used-before-assignment]
            raise
        except OSError:
            raise IdentityError("transaction unavailable") from None
    raise IdentityError("transaction unavailable")


@contextmanager
def _transaction_lock(paths: ProfilePaths) -> Iterator[None]:
    """Serialize state transactions with a bounded POSIX advisory lock."""

    try:
        paths.ensure()
        directory_fd = _open_directory_nofollow(paths.agent_dir)
        try:
            fd = _open_lock(directory_fd, LOCK_FILE_NAME)
        finally:
            os.close(directory_fd)
    except IdentityError:
        raise
    except Exception:
        raise IdentityError("transaction unavailable") from None

    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    acquired = False
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except (BlockingIOError, OSError) as error:
                if not isinstance(error, BlockingIOError) and getattr(error, "errno", None) not in {
                    11,
                    13,
                }:
                    raise IdentityError("transaction unavailable") from None
                if time.monotonic() >= deadline:
                    raise IdentityError("transaction unavailable") from None
                time.sleep(0.01)
        yield
    except IdentityError:
        raise
    except Exception:
        raise IdentityError("transaction unavailable") from None
    finally:
        if acquired:
            with suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(fd)


def _new_random_bytes(length: int) -> bytes:
    """Use the OS-backed CSPRNG; this is intentionally not a public injection hook."""

    try:
        value = secrets.token_bytes(length)
    except Exception:
        raise IdentityError("random generation failed") from None
    if not isinstance(value, bytes) or len(value) != length:
        raise IdentityError("random generation failed")
    return value


def _new_identity() -> HostIdentity:
    private_key = _new_random_bytes(RAW_BYTES)
    installation_id = _new_random_bytes(RAW_BYTES)
    try:
        private = x25519.X25519PrivateKey.from_private_bytes(private_key)
        public_key = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    except (TypeError, ValueError):
        raise IdentityError("identity generation failed") from None
    return HostIdentity(
        installation_id=installation_id,
        private_key=private_key,
        public_key=public_key,
        _token=_CONSTRUCTOR_TOKEN,
    )


def _identity_from_record(record: Any) -> HostIdentity:
    if not isinstance(record, Mapping) or set(record) != {
        "installation_id",
        "private_key",
        "public_key",
    }:
        raise IdentityStateError("host identity state invalid")
    try:
        installation_id = _b64decode_exact(record["installation_id"], RAW_BYTES)
        private_key = _b64decode_exact(record["private_key"], RAW_BYTES)
        public_key = _b64decode_exact(record["public_key"], RAW_BYTES)
        derived = (
            x25519.X25519PrivateKey.from_private_bytes(private_key)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
    except (TypeError, ValueError, binascii.Error):
        raise IdentityStateError("host identity state invalid") from None
    if not hmac.compare_digest(derived, public_key):
        raise IdentityStateError("host identity state invalid")
    return HostIdentity(
        installation_id=installation_id,
        private_key=private_key,
        public_key=public_key,
        _token=_CONSTRUCTOR_TOKEN,
    )


def _identity_record(identity: HostIdentity) -> dict[str, str]:
    return {
        "installation_id": _b64encode(identity.installation_id),
        "private_key": _b64encode(identity.private_key),
        "public_key": _b64encode(identity.public_key),
    }


class HostIdentity:
    """One host identity; ``repr`` never includes its private key bytes."""

    __slots__ = ("installation_id", "public_key", "_private_key")

    def __init__(
        self,
        *,
        installation_id: bytes,
        private_key: bytes,
        public_key: bytes,
        _token: object | None = None,
    ) -> None:
        if _token is not _CONSTRUCTOR_TOKEN:
            raise TypeError("identity construction is private")
        if not all(
            isinstance(value, bytes) and len(value) == RAW_BYTES
            for value in (installation_id, private_key, public_key)
        ):
            raise IdentityStateError("host identity state invalid")
        self.installation_id = bytes(installation_id)
        self.public_key = bytes(public_key)
        self._private_key = bytes(private_key)

    @property
    def private_key(self) -> bytes:
        """Return raw key bytes to the bounded Noise wrapper."""

        return self._private_key

    @property
    def installation_id_b64(self) -> str:
        return _b64encode(self.installation_id)

    @property
    def public_key_b64(self) -> str:
        return _b64encode(self.public_key)

    def __repr__(self) -> str:
        return (
            "HostIdentity("
            f"installation_id={self.installation_id_b64!r}, "
            f"public_key={self.public_key_b64!r}, "
            "private_key=<redacted>)"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HostIdentity):
            return NotImplemented
        return self.installation_id == other.installation_id and self.public_key == other.public_key


class HostIdentityStore:
    """Load or atomically create the one host identity for a profile."""

    def __init__(self, source: ProfilePaths | StateStore | str | os.PathLike[str]) -> None:
        try:
            self.paths, self.store = _store_for(source)
        except IdentityError:
            raise
        except Exception:
            raise IdentityError("invalid identity store") from None

    def _load_unlocked(self) -> dict[str, Any]:
        try:
            return self.store.load()
        except StateStoreError:
            raise IdentityStateError("host identity state invalid") from None
        except Exception:
            raise IdentityStateError("host identity state invalid") from None

    def _load_or_create_unlocked(self) -> HostIdentity:
        state = self._load_unlocked()
        if IDENTITY_FIELD in state:
            return _identity_from_record(state[IDENTITY_FIELD])
        identity = _new_identity()
        updated = copy.deepcopy(state)
        updated[IDENTITY_FIELD] = _identity_record(identity)
        try:
            self.store.save(updated)
        except StateStoreError:
            raise IdentityStateError("host identity state invalid") from None
        except Exception:
            raise IdentityError("identity persistence failed") from None
        return identity

    def load_or_create(self) -> HostIdentity:
        with _transaction_lock(self.paths):
            return self._load_or_create_unlocked()

    # Internal transaction callers must hold _transaction_lock already.
    def load_or_create_unlocked(self) -> HostIdentity:
        return self._load_or_create_unlocked()


IdentityStore = HostIdentityStore


def load_or_create_identity(
    source: ProfilePaths | StateStore | str | os.PathLike[str],
) -> HostIdentity:
    """Convenience wrapper for the profile's one host identity."""

    return HostIdentityStore(source).load_or_create()


__all__ = [
    "HostIdentity",
    "IdentityStore",
    "HostIdentityStore",
    "IdentityError",
    "IdentityStateError",
    "LOCK_FILE_NAME",
    "_b64decode_exact",
    "_b64encode",
    "_b64url_decode_exact",
    "_b64url_encode",
    "_coerce_paths",
    "_new_random_bytes",
    "_transaction_lock",
    "load_or_create_identity",
]
