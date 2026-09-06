from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mercury_relay_plugin.update_check import (  # noqa: E402
    CHECK_INTERVAL_SECONDS,
    UpdateChecker,
    parse_version,
)


def test_parse_version_accepts_semver_with_or_without_v() -> None:
    assert parse_version("0.2.0") == (0, 2, 0)
    assert parse_version("v1.10.3") == (1, 10, 3)
    for bad in ("", "1.2", "1.2.3-rc1", "latest", None, 3):
        assert parse_version(bad) is None


def test_check_caches_for_six_hours_and_forces_on_demand(tmp_path: Path) -> None:
    calls: list[int] = []
    now = [1_000_000.0]

    def fetch() -> str:
        calls.append(1)
        return "0.3.0"

    checker = UpdateChecker(
        installed_version="0.2.0",
        plugin_dir=tmp_path,
        cache_path=tmp_path / "update-check.json",
        fetch_latest=fetch,
        clock=lambda: now[0],
    )

    async def exercise() -> None:
        first = await checker.check()
        assert first["available"] is True and first["latest"] == "0.3.0"
        assert first["install"] == {"kind": "not_git"}
        # Within the window: no second fetch.
        now[0] += CHECK_INTERVAL_SECONDS - 1
        await checker.check()
        assert len(calls) == 1
        # Forced: fetches again.
        await checker.check(force=True)
        assert len(calls) == 2
        # Past the window: fetches.
        now[0] += CHECK_INTERVAL_SECONDS
        await checker.check()
        assert len(calls) == 3

    asyncio.run(exercise())
    cached = json.loads((tmp_path / "update-check.json").read_text())
    assert cached["latest"] == "0.3.0"

    # A new checker restores the cached answer without fetching.
    again = UpdateChecker(
        installed_version="0.3.0",
        plugin_dir=tmp_path,
        cache_path=tmp_path / "update-check.json",
        fetch_latest=fetch,
        clock=lambda: now[0],
    )
    snapshot = again.snapshot()
    assert snapshot["latest"] == "0.3.0" and snapshot["available"] is False


def test_check_failure_is_sanitized_and_never_raises(tmp_path: Path) -> None:
    def broken() -> str:
        raise RuntimeError("dns exploded at 10.0.0.1")

    checker = UpdateChecker(
        installed_version="0.2.0",
        plugin_dir=tmp_path,
        cache_path=tmp_path / "c.json",
        fetch_latest=broken,
    )
    result = asyncio.run(checker.check())
    assert result["error"] == "check_failed"
    assert "10.0.0.1" not in json.dumps(result)
    assert result["available"] is False


def test_disabled_checker_only_checks_when_forced(tmp_path: Path) -> None:
    calls: list[int] = []
    checker = UpdateChecker(
        installed_version="0.2.0",
        plugin_dir=tmp_path,
        cache_path=tmp_path / "c.json",
        enabled=False,
        fetch_latest=lambda: (calls.append(1), "9.9.9")[1],
    )
    asyncio.run(checker.check())
    assert calls == []
    asyncio.run(checker.check(force=True))
    assert calls == [1]


def test_apply_refuses_non_git_and_runs_hermes_updater_for_git(tmp_path: Path) -> None:
    checker = UpdateChecker(
        installed_version="0.2.0",
        plugin_dir=tmp_path,
        cache_path=tmp_path / "c.json",
        fetch_latest=lambda: "0.2.0",
        update_command=lambda: [sys.executable, "-c", "print('Plugin mercury-relay updated.')"],
    )
    assert asyncio.run(checker.apply()) == {
        "ok": False,
        "reason": "not_git",
        "restart_required": False,
    }

    (tmp_path / ".git").mkdir()
    result = asyncio.run(checker.apply())
    assert result["ok"] is True
    assert result["restart_required"] is True
    assert "updated" in result["output"]

    failing = UpdateChecker(
        installed_version="0.2.0",
        plugin_dir=tmp_path,
        cache_path=tmp_path / "c.json",
        fetch_latest=lambda: "0.2.0",
        update_command=lambda: [sys.executable, "-c", "import sys; print('nope'); sys.exit(3)"],
    )
    result = asyncio.run(failing.apply())
    assert result["ok"] is False and result["reason"] == "update_failed"
    assert result["restart_required"] is False


def test_latest_version_falls_back_to_tags_when_no_release_is_published(monkeypatch) -> None:
    import urllib.error

    from mercury_relay_plugin import update_check

    def fake_get(url: str):
        if url.startswith(update_check.RELEASES_URL):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        assert url.startswith(update_check.TAGS_URL)
        return [{"name": "v0.1.0"}, {"name": "v0.10.0"}, {"name": "v0.2.1"}, {"name": "nightly"}]

    monkeypatch.setattr(update_check, "_get_json", fake_get)
    assert update_check.fetch_latest_release_version() == "0.10.0"

    def prefer_release(url: str):
        if url.startswith(update_check.RELEASES_URL):
            return {"tag_name": "v0.3.0"}
        raise AssertionError("tags must not be consulted when a release exists")

    monkeypatch.setattr(update_check, "_get_json", prefer_release)
    assert update_check.fetch_latest_release_version() == "0.3.0"
