from __future__ import annotations

import json
from pathlib import Path

import yaml

import mercury_relay_plugin

PLUGIN_ROOT = Path(__file__).parents[1]


def test_plugin_manifest_is_opt_in_backend() -> None:
    manifest = yaml.safe_load((PLUGIN_ROOT / "plugin.yaml").read_text(encoding="utf-8"))
    assert manifest["name"] == "mercury-relay"
    assert manifest["kind"] == "backend"
    assert manifest["version"] == mercury_relay_plugin.__version__
    assert "provides_tools" not in manifest
    assert "hooks" not in manifest


def test_dashboard_manifest_mounts_backend_api_and_management_ui() -> None:
    manifest = json.loads(
        (PLUGIN_ROOT / "dashboard" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["name"] == "mercury-relay"
    assert manifest["api"] == "plugin_api.py"
    # The management page is a dashboard tab served from the plugin's own
    # dashboard/ directory; its API calls are the same authenticated backend
    # routes, so it works unchanged for a Desktop pointed at a remote gateway.
    assert manifest["tab"]["path"] == "/mercury-relay"
    entry = PLUGIN_ROOT / "dashboard" / manifest["entry"]
    assert entry.is_file()
    assert (PLUGIN_ROOT / "dashboard" / manifest["css"]).is_file()
    # The management UI ships no model tool, hook, or platform registration.
    assert "provides_tools" not in manifest
    assert "hooks" not in manifest


def test_vendored_qr_library_is_pure_python_segno() -> None:
    # The QR is rendered server-side (segno, BSD, pure Python) so both the
    # dashboard page and the desktop plugin show one identical QR with no
    # client-side QR library shipped.
    segno_init = PLUGIN_ROOT / "src" / "mercury_relay_plugin" / "_vendor" / "segno" / "__init__.py"
    assert segno_init.is_file()
