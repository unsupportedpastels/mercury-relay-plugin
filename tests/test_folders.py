from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from mercury_relay_plugin import folders  # noqa: E402
from mercury_relay_plugin.session_lease import SessionLease, SessionLeaseError  # noqa: E402
from mercury_relay_plugin.session_reads import SessionReads, SessionReadsError  # noqa: E402
from mercury_relay_plugin.virtual_ws import VirtualWebSocket  # noqa: E402

_POSIX_FOLDER_SERVICE = pytest.mark.skipif(
    os.name != "posix", reason="folder service is advertised only with secure POSIX primitives"
)


class HostFixture:
    def __init__(self, root: Path, profile_root: Path) -> None:
        self.root = root
        self.profile_root = profile_root
        self.policy = SimpleNamespace(
            default_path=root,
            locked_root=root,
            can_change_path=False,
        )

    def helpers(self):
        def profile_dir(profile: str) -> Path:
            return self.profile_root / profile

        def sensitive(path: Path) -> bool:
            return path.name.casefold() in {".env", "auth.json", "config.yaml"} or any(
                part.casefold() in {"mcp-tokens", "pairing"} for part in path.parts
            )

        def canonical(path: Path, *, require_exists: bool = False) -> Path:
            return path.expanduser().resolve(strict=require_exists)

        def policy(_request, *, create_root: bool = True):
            del create_root
            return self.policy

        def under(root: Path, target: Path) -> bool:
            return target == root or root in target.parents

        return profile_dir, sensitive, canonical, policy, under


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> HostFixture:
    root = tmp_path / "managed"
    root.mkdir()
    profile_root = tmp_path / "profiles"
    (profile_root / "default").mkdir(parents=True)
    fixture = HostFixture(root, profile_root)
    monkeypatch.setattr(folders, "_host_helpers", fixture.helpers)
    return fixture


def reads_for(host: HostFixture, *, folder_service=None) -> SessionReads:
    return SessionReads(
        profile_authorizer=lambda profile: profile == "default",
        status_snapshot=lambda: {"runtime": "ready"},
        folder_service=folder_service,
    )


def dispatch(reads: SessionReads, method: str, params: dict):
    return asyncio.run(reads.dispatch(method, params))


def _deep_parent(root: Path, length: int) -> Path:
    parent = root
    while length - len(str(parent)) > 200:
        parent = parent / ("a" * 100)
        parent.mkdir()
    parent = parent / ("b" * (length - len(str(parent)) - 1))
    parent.mkdir()
    assert len(str(parent)) == length
    return parent


@_POSIX_FOLDER_SERVICE
def test_derived_create_path_is_bounded_before_mutation(
    host: HostFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # macOS PATH_MAX leaves no room for a 1,024-byte pathname plus its NUL
    # terminator. Use the same boundary logic with a lower configured limit;
    # Linux exercises the production 1,024-unit value directly.
    limit = folders.MAX_FOLDER_PATH_CHARS
    if sys.platform == "darwin":
        limit = 900
        monkeypatch.setattr(folders, "MAX_FOLDER_PATH_CHARS", limit)
    parent = _deep_parent(host.root, limit - 2)
    service = folders.FolderService()
    result = service.create_folder("default", str(parent), "x")
    assert len(result["path"]) == limit
    assert (parent / "x").is_dir()
    with pytest.raises(SessionReadsError, match="^invalid_params$"):
        service.create_folder("default", str(parent), "xx")
    assert not (parent / "xx").exists()


@_POSIX_FOLDER_SERVICE
def test_listing_never_emits_an_over_bound_child_path(
    host: HostFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    limit = folders.MAX_FOLDER_PATH_CHARS
    if sys.platform == "darwin":
        limit = 900
        monkeypatch.setattr(folders, "MAX_FOLDER_PATH_CHARS", limit)
    parent = _deep_parent(host.root, limit - 2)
    (parent / "x").mkdir()
    service = folders.FolderService()
    assert len(service.list_folders("default", str(parent))["entries"][0]["path"]) == limit
    (parent / "xx").mkdir()
    with pytest.raises(SessionReadsError, match="^response_too_large$"):
        service.list_folders("default", str(parent))


def test_path_bound_uses_the_mobile_utf16_unit() -> None:
    valid = "/" + "😀" * 511 + "x"
    over = "/" + "😀" * 512
    assert folders._path_units(valid) == 1_024
    assert folders._path_units(over) == 1_025
    if os.name == "posix":
        assert folders.validate_path(valid)
        with pytest.raises(SessionReadsError, match="^invalid_params$"):
            folders.validate_path(over)


def test_capability_uses_same_utf16_root_bound_as_listing(
    host: HostFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = host.root
    segment_count = 8
    segment_length = 63
    if sys.platform == "darwin":
        # Keep the real nested path below macOS PATH_MAX while still making
        # UTF-16 units exceed the deliberately reduced test limit.
        monkeypatch.setattr(folders, "MAX_FOLDER_PATH_CHARS", 450)
        segment_count = 4
        segment_length = 50
    for _ in range(segment_count):
        root = root / ("😀" * segment_length)
        root.mkdir()
    host.policy.default_path = root
    host.policy.locked_root = root
    assert folders.FolderService().capability() is None


@_POSIX_FOLDER_SERVICE
def test_status_advertises_versioned_folder_methods(host: HostFixture) -> None:
    status = dispatch(reads_for(host), "relay.status", {})
    assert status["capabilities"]["folders"] == {
        "version": 1,
        "list_method": "relay.folders.list",
        "create_method": "relay.folders.create",
    }


def test_missing_secure_host_adapter_hides_folder_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable():
        raise SessionReadsError("folders_unavailable")

    monkeypatch.setattr(folders, "_host_helpers", unavailable)
    status = dispatch(
        SessionReads(status_snapshot=lambda: {"runtime": "ready"}),
        "relay.status",
        {},
    )
    assert "folders" not in status.get("capabilities", {})


def test_folder_capability_is_hidden_without_posix_descriptor_primitives(
    host: HostFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(folders, "_descriptor_secure_supported", lambda: False)
    status = dispatch(reads_for(host), "relay.status", {})
    assert "folders" not in status.get("capabilities", {})


@_POSIX_FOLDER_SERVICE
def test_real_installed_hermes_managed_files_policy_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from conftest import contract_import

    contract_import("hermes_cli.profiles")
    contract_import("hermes_cli.web_server")
    home = tmp_path / "hermes"
    root = tmp_path / "managed"
    home.mkdir()
    root.mkdir()
    (root / "existing").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_DASHBOARD_FILES_ROOT", str(root))

    reads = SessionReads(
        profile_authorizer=lambda profile: profile == "default",
        status_snapshot=lambda: {"runtime": "ready"},
    )
    status = dispatch(reads, "relay.status", {})
    assert status["capabilities"]["folders"] == {
        "version": 1,
        "list_method": "relay.folders.list",
        "create_method": "relay.folders.create",
    }
    listed = dispatch(reads, "relay.folders.list", {"profile": "default"})
    assert listed["path"] == str(root)
    assert listed["entries"] == [
        {"name": "existing", "path": str(root / "existing"), "is_dir": True}
    ]
    created = dispatch(
        reads,
        "relay.folders.create",
        {"profile": "default", "parent_path": str(root), "name": "created"},
    )
    assert created["path"] == str(root / "created")
    assert (root / "created").is_dir()


@_POSIX_FOLDER_SERVICE
def test_list_returns_relay_shape_filters_sensitive_and_symlink_entries(
    host: HostFixture,
) -> None:
    (host.root / "folder").mkdir()
    (host.root / "notes.txt").write_text("safe")
    (host.root / ".env").write_text("secret")
    (host.root / "pairing").mkdir()
    outside = host.root.parent / "outside"
    outside.mkdir()
    (host.root / "alias").symlink_to(outside, target_is_directory=True)

    result = dispatch(
        reads_for(host),
        "relay.folders.list",
        {"profile": "default"},
    )

    assert set(result) == {
        "path",
        "entries",
        "parent",
        "root",
        "locked_root",
        "can_change_path",
    }
    assert result["path"] == str(host.root)
    assert result["parent"] is None
    assert result["root"] == str(host.root)
    assert result["locked_root"] == str(host.root)
    assert result["can_change_path"] is False
    assert result["entries"] == [
        {"name": "folder", "path": str(host.root / "folder"), "is_dir": True},
    ]


@_POSIX_FOLDER_SERVICE
def test_list_rejects_traversal_and_symlink_path_without_leaking_host_errors(
    host: HostFixture,
) -> None:
    outside = host.root.parent / "outside"
    outside.mkdir()
    (host.root / "alias").symlink_to(outside, target_is_directory=True)
    reads = reads_for(host)

    with pytest.raises(SessionReadsError, match="^invalid_params$"):
        dispatch(reads, "relay.folders.list", {"profile": "default", "path": "/tmp/../x"})
    with pytest.raises(SessionReadsError, match="^invalid_params$"):
        dispatch(reads, "relay.folders.list", {"profile": "default", "path": "/tmp/./x"})
    with pytest.raises(SessionReadsError, match="^folder_not_available$"):
        dispatch(
            reads,
            "relay.folders.list",
            {"profile": "default", "path": str(host.root / "alias")},
        )
    with pytest.raises(SessionReadsError, match="^folder_not_available$") as caught:
        dispatch(
            reads,
            "relay.folders.list",
            {"profile": "default", "path": str(outside)},
        )
    assert "/" not in str(caught.value) or str(caught.value) == "folder_not_available"


@_POSIX_FOLDER_SERVICE
def test_create_returns_listing_and_is_confined_to_locked_root(host: HostFixture) -> None:
    result = dispatch(
        reads_for(host),
        "relay.folders.create",
        {
            "profile": "default",
            "parent_path": str(host.root),
            "name": "new folder",
        },
    )

    created = host.root / "new folder"
    assert created.is_dir()
    assert stat.S_IMODE(created.stat().st_mode) & 0o700 == 0o700
    assert result["path"] == str(created)
    assert result["parent"] == str(host.root)
    assert result["entries"] == []
    assert result["root"] == str(host.root)
    assert result["locked_root"] == str(host.root)
    assert result["can_change_path"] is False

    with pytest.raises(SessionReadsError, match="^folder_not_available$"):
        dispatch(
            reads_for(host),
            "relay.folders.create",
            {"profile": "default", "parent_path": str(host.root), "name": ".env"},
        )

    outside = host.root.parent / "outside"
    outside.mkdir()
    with pytest.raises(SessionReadsError, match="^folder_not_available$"):
        dispatch(
            reads_for(host),
            "relay.folders.create",
            {"profile": "default", "parent_path": str(outside), "name": "escape"},
        )

    alias = host.root / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SessionReadsError, match="^folder_not_available$"):
        dispatch(
            reads_for(host),
            "relay.folders.create",
            {"profile": "default", "parent_path": str(alias), "name": "through-link"},
        )


@_POSIX_FOLDER_SERVICE
def test_create_is_idempotent_for_existing_directory_but_not_files(host: HostFixture) -> None:
    existing = host.root / "existing"
    existing.mkdir()
    reads = reads_for(host)
    first = dispatch(
        reads,
        "relay.folders.create",
        {"profile": "default", "parent_path": str(host.root), "name": "existing"},
    )
    assert first["path"] == str(existing)

    (host.root / "file").write_text("x")
    with pytest.raises(SessionReadsError, match="^folder_exists$"):
        dispatch(
            reads,
            "relay.folders.create",
            {"profile": "default", "parent_path": str(host.root), "name": "file"},
        )


@_POSIX_FOLDER_SERVICE
def test_listing_is_explicitly_bounded_not_silently_truncated(host: HostFixture) -> None:
    for index in range(folders.MAX_FOLDER_ENTRIES + 1):
        (host.root / f"entry-{index:04d}").mkdir()

    with pytest.raises(SessionReadsError, match="^response_too_large$"):
        dispatch(reads_for(host), "relay.folders.list", {"profile": "default"})


@_POSIX_FOLDER_SERVICE
def test_folder_params_and_profile_are_authorized(host: HostFixture) -> None:
    reads = reads_for(host)
    cases = [
        ({}, "invalid_params"),
        ({"profile": "default", "extra": 1}, "invalid_params"),
        ({"profile": "default", "parent_path": str(host.root)}, "invalid_params"),
        (
            {"profile": "default", "parent_path": str(host.root), "name": "../escape"},
            "invalid_params",
        ),
        (
            {"profile": "missing", "parent_path": str(host.root), "name": "new"},
            "profile_not_available",
        ),
    ]
    for params, reason in cases:
        method = "relay.folders.create" if "parent_path" in params else "relay.folders.list"
        with pytest.raises(SessionReadsError, match=f"^{reason}$"):
            dispatch(reads, method, params)


class CountingFolderService:
    def __init__(self) -> None:
        self.create_calls = 0

    def list_folders(self, profile: str, path: str | None = None) -> dict:
        return {
            "path": path or "/workspace",
            "entries": [],
            "parent": None,
            "root": "/workspace",
            "locked_root": "/workspace",
            "can_change_path": False,
        }

    def create_folder(self, profile: str, parent_path: str, name: str) -> dict:
        self.create_calls += 1
        return {
            "path": f"{parent_path}/{name}",
            "entries": [],
            "parent": parent_path,
            "root": "/workspace",
            "locked_root": "/workspace",
            "can_change_path": False,
        }


class FailingFolderService(CountingFolderService):
    def create_folder(self, profile: str, parent_path: str, name: str) -> dict:
        raise RuntimeError("host detail must not escape")


class FlakyFolderService(CountingFolderService):
    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    def create_folder(self, profile: str, parent_path: str, name: str) -> dict:
        if not self.failed:
            self.failed = True
            raise RuntimeError("temporary host failure")
        return super().create_folder(profile, parent_path, name)


def test_unexpected_create_failure_uses_shared_stable_reason() -> None:
    reads = SessionReads(
        profile_authorizer=lambda profile: profile == "default",
        folder_service=FailingFolderService(),
    )
    with pytest.raises(SessionReadsError, match="^folder_create_failed$"):
        dispatch(
            reads,
            "relay.folders.create",
            {"profile": "default", "parent_path": "/workspace", "name": "new"},
        )


def test_failed_folder_mutation_is_not_cached_for_a_same_id_retry() -> None:
    async def exercise() -> None:
        service = FlakyFolderService()
        reads = SessionReads(
            profile_authorizer=lambda profile: profile == "default",
            folder_service=service,
        )
        websocket = VirtualWebSocket()
        await websocket.accept()

        async def close_controller(_controller: str) -> bool:
            return True

        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=websocket,
            close_controller=close_controller,
            read_dispatcher=reads.dispatch,
        )
        lease.start()
        attachment = lease.attach(0)
        await attachment.next_text(timeout=0.5)
        request = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "same-id",
                "method": "relay.folders.create",
                "params": {
                    "profile": "default",
                    "parent_path": "/workspace",
                    "name": "retryable",
                },
            },
            separators=(",", ":"),
        )

        await attachment.feed_text(request)
        failure = json.loads(await attachment.next_text(timeout=0.5))
        assert failure["error"] == {"code": -32000, "message": "folder_create_failed"}
        await attachment.feed_text(request)
        success = json.loads(await attachment.next_text(timeout=0.5))
        assert success["result"]["path"] == "/workspace/retryable"
        assert service.create_calls == 1
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_folder_creation_is_local_deduplicated_across_request_ids_and_reattach() -> None:
    async def exercise() -> None:
        service = CountingFolderService()
        reads = SessionReads(
            profile_authorizer=lambda profile: profile == "default",
            folder_service=service,
        )
        websocket = VirtualWebSocket()
        await websocket.accept()
        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=websocket,
            close_controller=lambda _controller: asyncio.sleep(0),
            read_dispatcher=reads.dispatch,
        )
        lease.start()
        attachment = lease.attach(0)
        await attachment.next_text(timeout=0.5)

        def request(request_id: str | int, name: str = "new") -> str:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "relay.folders.create",
                    "params": {
                        "profile": "default",
                        "parent_path": "/workspace",
                        "name": name,
                    },
                },
                separators=(",", ":"),
            )

        await attachment.feed_text(request("first"))
        first = json.loads(await attachment.next_text(timeout=0.5))
        assert first["id"] == "first"
        assert service.create_calls == 1

        await attachment.feed_text(request("first"))
        retry = json.loads(await attachment.next_text(timeout=0.5))
        assert retry["id"] == "first"
        assert retry["result"] == first["result"]
        assert service.create_calls == 1
        await attachment.feed_text(request("first", "different"))
        conflicting = json.loads(await attachment.next_text(timeout=0.5))
        assert conflicting["error"] == {"code": -32000, "message": "invalid_params"}
        assert service.create_calls == 1
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(websocket.receive_text(), timeout=0.05)

        # A new namespaced request is a new operation even when its payload is
        # identical; the service remains idempotent at the filesystem layer.
        await attachment.feed_text(request("retry"))
        assert json.loads(await attachment.next_text(timeout=0.5))["id"] == "retry"
        assert service.create_calls == 2

        # A new connection may restart numeric JSON-RPC ids. The params
        # namespace and payload identity must not collide across operations.
        await attachment.feed_text(request("socket-1:1", "other"))
        assert json.loads(await attachment.next_text(timeout=0.5))["id"] == "socket-1:1"
        await attachment.feed_text(request("socket-2:1", "third"))
        assert json.loads(await attachment.next_text(timeout=0.5))["id"] == "socket-2:1"
        assert service.create_calls == 4

        attachment.detach()
        reattached = lease.attach(0)
        await reattached.next_text(timeout=0.5)
        await reattached.feed_text(request("first"))
        assert json.loads(await reattached.next_text(timeout=0.5))["id"] == "first"
        assert service.create_calls == 4
        await reattached.feed_text(request("after-reconnect"))
        replay_retry = json.loads(await reattached.next_text(timeout=0.5))
        assert replay_retry["id"] == "after-reconnect"
        assert service.create_calls == 5
        await lease.release("test_finished")

    asyncio.run(exercise())


def test_local_read_rejects_unencodable_request_id() -> None:
    async def exercise() -> None:
        called: list[tuple[str, dict]] = []

        async def dispatch(method: str, params: dict) -> dict:
            called.append((method, params))
            return {}

        websocket = VirtualWebSocket()
        await websocket.accept()
        async def close_controller(_controller: str) -> bool:
            return True

        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=websocket,
            close_controller=close_controller,
            read_dispatcher=dispatch,
        )
        lease.start()
        attachment = lease.attach(0)
        await attachment.next_text(timeout=0.5)
        request = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": chr(0xD800),
                "method": "relay.folders.list",
                "params": {"profile": "default"},
            }
        )
        with pytest.raises(SessionLeaseError, match="^invalid_read_request$"):
            await attachment.feed_text(request)
        assert called == []
        await lease.release("test_finished")

    asyncio.run(exercise())


@_POSIX_FOLDER_SERVICE
def test_new_request_identity_recreates_after_external_delete(host: HostFixture) -> None:
    async def exercise() -> None:
        reads = reads_for(host)
        websocket = VirtualWebSocket()
        await websocket.accept()

        async def close_controller(_controller: str) -> bool:
            return True

        lease = SessionLease(
            device_id="device-1",
            profile="default",
            controller_id="controller-1",
            websocket=websocket,
            close_controller=close_controller,
            read_dispatcher=reads.dispatch,
        )
        lease.start()
        attachment = lease.attach(0)
        await attachment.next_text(timeout=0.5)

        def request(request_id: str) -> str:
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "relay.folders.create",
                    "params": {
                        "profile": "default",
                        "parent_path": str(host.root),
                        "name": "recreated",
                    },
                },
                separators=(",", ":"),
            )

        await attachment.feed_text(request("socket-a"))
        await attachment.next_text(timeout=0.5)
        target = host.root / "recreated"
        assert target.is_dir()
        target.rmdir()

        # New socket namespaces create a new correlated identity and must
        # execute the idempotent service again after external state changed.
        await attachment.feed_text(request("socket-b"))
        await attachment.next_text(timeout=0.5)
        assert target.is_dir()
        target.rmdir()

        # A retry with the original correlated identity replays its success;
        # it does not silently recreate a folder after that request completed.
        await attachment.feed_text(request("socket-b"))
        await attachment.next_text(timeout=0.5)
        assert not target.exists()
        await lease.release("test_finished")

    asyncio.run(exercise())
