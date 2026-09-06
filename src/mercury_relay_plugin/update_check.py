"""Periodic, read-only update check plus an operator-triggered update.

Mirrors Hermes' own update banner: check on a timer, cache the answer for six
hours, badge the result, and leave the actual update to the operator. The
check sends one anonymous GET to the public repo's latest-release endpoint and
reads nothing but a version string. Applying an update never happens here:
``apply`` shells out to Hermes' own plugin manager (``hermes plugins update``),
so install validation and the supply-chain scan stay in Hermes' hands, and the
gateway still needs an explicit restart to load new code.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

PLUGIN_NAME = "mercury-relay"
RELEASE_REPO = "unsupportedpastels/mercury-relay-plugin"
RELEASES_URL = f"https://api.github.com/repos/{RELEASE_REPO}/releases/latest"
TAGS_URL = f"https://api.github.com/repos/{RELEASE_REPO}/tags?per_page=50"
CHECK_INTERVAL_SECONDS = 6 * 3600
STARTUP_DELAY_SECONDS = (20, 90)
FETCH_TIMEOUT_SECONDS = 8
APPLY_TIMEOUT_SECONDS = 180
MAX_OUTPUT_CHARS = 2000
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse_version(text: object) -> tuple[int, int, int] | None:
    if not isinstance(text, str):
        return None
    match = _VERSION_RE.match(text.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def _get_json(url: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"{PLUGIN_NAME}-plugin",
        },
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        body = response.read(256 * 1024)
    return json.loads(body.decode("utf-8"))


def fetch_latest_release_version() -> str:
    """Anonymous GETs; returns the bare version string (no leading v).

    Prefers the latest published release; when the repo only carries tags
    (GitHub answers 404 for releases/latest), the highest semver tag wins.
    """

    try:
        payload = _get_json(RELEASES_URL)
        version = parse_version(payload.get("tag_name") if isinstance(payload, dict) else None)
        if version is not None:
            return ".".join(str(part) for part in version)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    payload = _get_json(TAGS_URL)
    versions = [
        parsed
        for item in (payload if isinstance(payload, list) else [])
        if isinstance(item, dict)
        for parsed in [parse_version(item.get("name"))]
        if parsed is not None
    ]
    if not versions:
        raise ValueError("no release or version tag found")
    return ".".join(str(part) for part in max(versions))


def default_update_command() -> list[str]:
    """Hermes' own plugin updater, from the same install the gateway runs."""

    hermes = shutil.which("hermes")
    if hermes:
        return [hermes, "plugins", "update", PLUGIN_NAME]
    return [sys.executable, "-m", "hermes_cli.main", "plugins", "update", PLUGIN_NAME]


class UpdateChecker:
    def __init__(
        self,
        *,
        installed_version: str,
        plugin_dir: Path,
        cache_path: Path,
        enabled: bool = True,
        fetch_latest: Callable[[], str] = fetch_latest_release_version,
        update_command: Callable[[], list[str]] = default_update_command,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.installed_version = installed_version
        self.plugin_dir = plugin_dir
        self.cache_path = cache_path
        self.enabled = enabled
        self._fetch_latest = fetch_latest
        self._update_command = update_command
        self._clock = clock
        self._lock = asyncio.Lock()
        self._apply_lock = asyncio.Lock()
        self._latest: str | None = None
        self._checked_at: float | None = None
        self._error: str | None = None
        self._load_cache()

    # -- state ---------------------------------------------------------------

    def _load_cache(self) -> None:
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(raw, dict):
            return
        latest = raw.get("latest")
        checked = raw.get("checked_at")
        if parse_version(latest) is not None and isinstance(checked, (int, float)):
            self._latest = latest
            self._checked_at = float(checked)

    def _save_cache(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"latest": self._latest, "checked_at": self._checked_at}),
                encoding="utf-8",
            )
            os.replace(tmp, self.cache_path)
        except Exception:
            pass

    def install_info(self) -> dict[str, Any]:
        git_dir = self.plugin_dir / ".git"
        if not git_dir.exists():
            return {"kind": "not_git"}
        info: dict[str, Any] = {"kind": "git"}
        for key, args in (
            ("branch", ["rev-parse", "--abbrev-ref", "HEAD"]),
            ("commit", ["rev-parse", "--short", "HEAD"]),
        ):
            try:
                result = subprocess.run(  # noqa: S603
                    ["git", "-C", str(self.plugin_dir), *args],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if result.returncode == 0:
                    info[key] = result.stdout.strip()[:64]
            except Exception:
                continue
        return info

    def is_stale(self) -> bool:
        return (
            self._checked_at is None or self._clock() - self._checked_at >= CHECK_INTERVAL_SECONDS
        )

    def snapshot(self) -> dict[str, Any]:
        installed = parse_version(self.installed_version)
        latest = parse_version(self._latest)
        available = installed is not None and latest is not None and latest > installed
        return {
            "installed": self.installed_version,
            "latest": self._latest,
            "available": available,
            "checked_at": self._checked_at,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "enabled": self.enabled,
            "error": self._error,
            "install": self.install_info(),
            "update_command": f"hermes plugins update {PLUGIN_NAME}",
        }

    # -- checking ------------------------------------------------------------

    async def check(self, *, force: bool = False) -> dict[str, Any]:
        if not self.enabled and not force:
            return self.snapshot()
        async with self._lock:
            if not force and not self.is_stale():
                return self.snapshot()
            try:
                latest = await asyncio.to_thread(self._fetch_latest)
                if parse_version(latest) is None:
                    raise ValueError("invalid version")
                self._latest = latest
                self._checked_at = self._clock()
                self._error = None
                self._save_cache()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Never surface network or parser detail to the page.
                self._error = "check_failed"
        return self.snapshot()

    async def run_forever(self) -> None:
        if not self.enabled:
            return
        try:
            await asyncio.sleep(random.uniform(*STARTUP_DELAY_SECONDS))  # noqa: S311
            while True:
                await self.check()
                jitter = random.uniform(0.9, 1.1)  # noqa: S311
                await asyncio.sleep(CHECK_INTERVAL_SECONDS * jitter)
        except asyncio.CancelledError:
            return

    # -- applying ------------------------------------------------------------

    async def apply(self) -> dict[str, Any]:
        """Run Hermes' plugin updater. The gateway must be restarted afterwards."""

        if self.install_info().get("kind") != "git":
            return {"ok": False, "reason": "not_git", "restart_required": False}
        if self._apply_lock.locked():
            return {"ok": False, "reason": "in_progress", "restart_required": False}
        async with self._apply_lock:
            command = self._update_command()
            env = dict(os.environ)
            env.setdefault("HERMES_HOME", str(self.plugin_dir.parent.parent))
            try:
                result = await asyncio.to_thread(
                    lambda: subprocess.run(  # noqa: S603
                        command,
                        capture_output=True,
                        text=True,
                        timeout=APPLY_TIMEOUT_SECONDS,
                        check=False,
                        env=env,
                        stdin=subprocess.DEVNULL,
                    )
                )
            except subprocess.TimeoutExpired:
                return {"ok": False, "reason": "timeout", "restart_required": False}
            except Exception:
                return {"ok": False, "reason": "launch_failed", "restart_required": False}
            output = (result.stdout or "") + (result.stderr or "")
            output = output[-MAX_OUTPUT_CHARS:]
            ok = result.returncode == 0
            if ok:
                # Whatever landed, the cached "latest" no longer describes a gap
                # we can measure until the new code is loaded.
                await self.check(force=True)
            return {
                "ok": ok,
                "reason": None if ok else "update_failed",
                "output": output,
                "restart_required": ok,
                "install": self.install_info(),
            }


__all__ = [
    "CHECK_INTERVAL_SECONDS",
    "UpdateChecker",
    "default_update_command",
    "fetch_latest_release_version",
    "parse_version",
]
