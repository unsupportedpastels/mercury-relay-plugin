"""Bounded in-process session/status reads for authorized Mercury devices.

Implements PROTOCOL §8 correlated reads on the encrypted channel: status,
SessionDB lists/transcripts, and raster images through the host managed-file
policy adapter. No loopback HTTP, Hermes credential, or private SQLite schema.
Database handles are read-only and closed before responding; file reads are
bounded. Failures map to stable non-oracular reason codes.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from .config import validate_profile_id
from .framing import MAX_LOGICAL_MESSAGE_BYTES

RELAY_READ_METHODS = frozenset(
    {
        "relay.status",
        "relay.sessions.list",
        "relay.session.transcript",
        "relay.image.read",
    }
)
RELAY_FOLDER_METHODS = frozenset({"relay.folders.list", "relay.folders.create"})
RELAY_LOCAL_METHODS = RELAY_READ_METHODS | RELAY_FOLDER_METHODS
RELAY_MUTATION_METHODS = frozenset({"relay.folders.create"})
MAX_LIST_LIMIT = 100
DEFAULT_LIST_LIMIT = 20
MAX_TRANSCRIPT_LIMIT = 500
MAX_OFFSET = 1_000_000
MAX_SESSION_ID_TEXT = 256
# Leave envelope slack inside the one-logical-message framing cap.
MAX_RESULT_BYTES = MAX_LOGICAL_MESSAGE_BYTES - 4_096

# Keep the privacy floor on older hosts that predate the shared taxonomy.
# Only stored provenance is authoritative; never classify message text.
try:
    from agent.message_metadata import HIDDEN_DISPLAY_KINDS
except ImportError:
    HIDDEN_DISPLAY_KINDS = frozenset()
_HIDDEN_TRANSCRIPT_KINDS = HIDDEN_DISPLAY_KINDS | {
    "hidden",
    "internal_notification",
    "delegation_closeout",
    "delegation_closeout_provisional",
    "delegation_waiting",
}


class SessionReadsError(RuntimeError):
    """One stable read failure without database or filesystem detail."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _open_profile_session_db(profile: str) -> Any:
    """Default opener: a read-only SessionDB for one existing local profile."""

    try:
        from hermes_cli.profiles import get_profile_dir
        from hermes_state import SessionDB
    except Exception:
        raise SessionReadsError("reads_unavailable") from None
    try:
        profile_dir = Path(get_profile_dir(profile))
        db_path = profile_dir / "state.db"
        exists = profile_dir.is_dir() and db_path.is_file()
    except Exception:
        raise SessionReadsError("profile_not_available") from None
    if not exists:
        raise SessionReadsError("profile_not_available")
    try:
        return SessionDB(db_path, read_only=True)
    except Exception:
        raise SessionReadsError("read_failed") from None


def _require_int(value: Any, *, minimum: int, maximum: int, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SessionReadsError("invalid_params")
    return value


def _bounded_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Prove the result is bounded, JSON-safe, and secret-free by encoding."""

    try:
        encoded = json.dumps(result, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise SessionReadsError("read_failed") from None
    if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES:
        raise SessionReadsError("response_too_large")
    return dict(result)


class SessionReads:
    """Serve bounded v1 read methods for one installation."""

    def __init__(
        self,
        *,
        profile_authorizer: Callable[[str], bool] | None = None,
        db_opener: Callable[[str], Any] | None = None,
        status_snapshot: Callable[[], Mapping[str, Any]] | None = None,
        folder_service: Any | None = None,
    ) -> None:
        if profile_authorizer is not None and not callable(profile_authorizer):
            raise TypeError("profile_authorizer must be callable")
        if db_opener is not None and not callable(db_opener):
            raise TypeError("db_opener must be callable")
        if status_snapshot is not None and not callable(status_snapshot):
            raise TypeError("status_snapshot must be callable")
        if folder_service is not None:
            if not callable(getattr(folder_service, "list_folders", None)) or not callable(
                getattr(folder_service, "create_folder", None)
            ):
                raise TypeError("folder_service must provide list_folders and create_folder")
        else:
            from .folders import FolderService

            folder_service = FolderService()
        self._profile_authorizer = profile_authorizer
        self._db_opener = db_opener or _open_profile_session_db
        self._status_snapshot = status_snapshot
        self._folder_service = folder_service

    def _authorized_profile(self, params: Mapping[str, Any]) -> str:
        profile = params.get("profile", "default")
        try:
            validate_profile_id(profile)
        except Exception:
            raise SessionReadsError("profile_not_available") from None
        if self._profile_authorizer is not None:
            try:
                permitted = self._profile_authorizer(profile) is True
            except Exception:
                permitted = False
            if not permitted:
                raise SessionReadsError("profile_not_available")
        return profile

    async def dispatch(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        """Serve one read request and return its bounded result object."""

        if not isinstance(params, Mapping):
            raise SessionReadsError("invalid_params")
        if method == "relay.status":
            return self._status(params)
        if method == "relay.sessions.list":
            return await self._sessions_list(params)
        if method == "relay.session.transcript":
            return await self._transcript(params)
        if method == "relay.image.read":
            from .image_reads import read_image, validate_path

            if set(params) != {"profile", "path"}:
                raise SessionReadsError("invalid_params")
            profile = self._authorized_profile(params)
            path = validate_path(params["path"])
            return _bounded_result(await self._run_read(lambda: read_image(profile, path)))
        if method == "relay.folders.list":
            return await self._folders_list(params)
        if method == "relay.folders.create":
            return await self._folders_create(params)
        raise SessionReadsError("method_not_allowed")

    def _status(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if set(params):
            raise SessionReadsError("invalid_params")
        if self._status_snapshot is None:
            raise SessionReadsError("reads_unavailable")
        try:
            snapshot = dict(self._status_snapshot())
        except Exception:
            raise SessionReadsError("reads_unavailable") from None
        from .folders import capability as folders_capability
        from .image_reads import capability

        image_read = capability()
        folders = folders_capability()
        capabilities = dict(snapshot.get("capabilities", {}))
        capabilities.pop("image_read", None)
        capabilities.pop("folders", None)
        if image_read is not None:
            capabilities["image_read"] = image_read
        if folders is not None:
            capabilities["folders"] = folders
        if capabilities:
            snapshot["capabilities"] = capabilities
        else:
            snapshot.pop("capabilities", None)
        return _bounded_result(snapshot)

    async def _folders_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if "profile" not in params or not set(params) <= {"profile", "path"}:
            raise SessionReadsError("invalid_params")
        profile = self._authorized_profile(params)
        path = params.get("path")
        return _bounded_result(
            await self._run_read(lambda: self._folder_service.list_folders(profile, path))
        )

    async def _folders_create(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if set(params) != {"profile", "parent_path", "name"}:
            raise SessionReadsError("invalid_params")
        profile = self._authorized_profile(params)
        return _bounded_result(
            await self._run_read(
                lambda: self._folder_service.create_folder(
                    profile, params["parent_path"], params["name"]
                ),
                failure_reason="folder_create_failed",
            )
        )

    async def _sessions_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if not set(params) <= {"profile", "limit", "offset"}:
            raise SessionReadsError("invalid_params")
        profile = self._authorized_profile(params)
        limit = _require_int(
            params.get("limit"), minimum=1, maximum=MAX_LIST_LIMIT, default=DEFAULT_LIST_LIMIT
        )
        offset = _require_int(params.get("offset"), minimum=0, maximum=MAX_OFFSET, default=0)

        def read() -> dict[str, Any]:
            db = self._db_opener(profile)
            try:
                sessions = db.list_sessions_rich(
                    limit=limit,
                    offset=offset,
                    order_by_last_active=True,
                    compact_rows=True,
                    include_pinned=True,
                )
                # exclude_children keeps the total consistent with the rows
                # list_sessions_rich surfaces (Hermes pairs them the same way).
                total = db.session_count(exclude_children=True)
            finally:
                with suppress(Exception):
                    db.close()
            if not isinstance(sessions, list) or not isinstance(total, int):
                raise SessionReadsError("read_failed")
            return {
                "sessions": sessions,
                "total": total,
                "limit": limit,
                "offset": offset,
            }

        return _bounded_result(await self._run_read(read))

    async def _transcript(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if not set(params) <= {"profile", "session_id", "limit", "offset", "order"}:
            raise SessionReadsError("invalid_params")
        profile = self._authorized_profile(params)
        session_id = params.get("session_id")
        if (
            not isinstance(session_id, str)
            or not 1 <= len(session_id) <= MAX_SESSION_ID_TEXT
            or "\x00" in session_id
        ):
            raise SessionReadsError("invalid_params")
        limit = _require_int(
            params.get("limit"),
            minimum=1,
            maximum=MAX_TRANSCRIPT_LIMIT,
            default=MAX_TRANSCRIPT_LIMIT,
        )
        offset = _require_int(params.get("offset"), minimum=0, maximum=MAX_OFFSET, default=0)
        order = params.get("order", "latest")
        if order not in {"latest", "oldest"}:
            raise SessionReadsError("invalid_params")

        def read() -> dict[str, Any]:
            db = self._db_opener(profile)
            try:
                # Durable-ID preference and compression-tip resolution follow
                # Hermes's own transcript endpoint resolution chain.
                resolved = db.resolve_session_id(session_id)
                if not resolved:
                    raise SessionReadsError("session_not_found")
                resolved = db.resolve_resume_session_id(resolved)
                messages = db.get_messages(
                    resolved,
                    limit=limit,
                    offset=offset,
                    latest=order == "latest",
                )
            finally:
                with suppress(Exception):
                    db.close()
            if not isinstance(resolved, str) or not isinstance(messages, list):
                raise SessionReadsError("read_failed")
            raw_returned = len(messages)
            messages = [
                message
                for message in messages
                if message.get("display_kind") not in _HIDDEN_TRANSCRIPT_KINDS
            ]
            return {
                "session_id": resolved,
                "messages": messages,
                "pagination": {
                    "limit": limit,
                    "offset": offset,
                    "order": order,
                    "returned": len(messages),
                    # Offsets address stored rows, not the filtered payload.
                    # Continue while raw_returned == limit, even for an empty
                    # visible page; a final empty raw page is valid at EOF.
                    "raw_returned": raw_returned,
                    "next_offset": offset + raw_returned,
                },
            }

        return _bounded_result(await self._run_read(read))

    @staticmethod
    async def _run_read(
        read: Callable[[], dict[str, Any]], *, failure_reason: str = "read_failed"
    ) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(read)
        except SessionReadsError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            # Locks, malformed rows, and every other database failure map to
            # one stable reason without leaking paths or SQL detail.
            raise SessionReadsError(failure_reason) from None


__all__ = [
    "MAX_LIST_LIMIT",
    "MAX_RESULT_BYTES",
    "MAX_TRANSCRIPT_LIMIT",
    "RELAY_FOLDER_METHODS",
    "RELAY_LOCAL_METHODS",
    "RELAY_MUTATION_METHODS",
    "RELAY_READ_METHODS",
    "SessionReads",
    "SessionReadsError",
]
