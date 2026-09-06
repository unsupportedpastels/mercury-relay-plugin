"""Source-level checks for the desktop plugin half.

The desktop plugin runs in the Electron renderer with the injected
``@hermes/plugin-sdk``/``react`` shims, so it can't be imported here. These
checks assert it parses and keeps the load-bearing structural and safety
properties: it registers a route + nav, reaches its backend only through the
sanctioned ``ctx.rest``, approves via the operator-confirmed fingerprint, and
builds the roster from the connection registry.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

PLUGIN_JS = Path(__file__).parents[1] / "desktop" / "plugin.js"


def _source() -> str:
    return PLUGIN_JS.read_text(encoding="utf-8")


def test_desktop_plugin_file_exists() -> None:
    assert PLUGIN_JS.is_file()


def test_desktop_plugin_parses_as_javascript() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not available to syntax-check the desktop plugin")
    result = subprocess.run(
        [node, "--check", str(PLUGIN_JS)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_registers_route_nav_and_default_export() -> None:
    src = _source()
    assert "id: 'mercury-relay'" in src
    assert "defaultEnabled: false" in src
    assert "ROUTES_AREA" in src
    assert "SIDEBAR_NAV_AREA" in src
    assert "/mercury-relay" in src


def test_uses_sanctioned_backend_access_only() -> None:
    src = _source()
    # Backend calls go through ctx.rest (namespace-scoped, authed, base-path
    # aware), never a hardcoded URL or a raw fetch to the plugin API.
    assert "ctx.rest" in src
    assert "props.rest(" in src
    assert "http://" not in src
    assert "fetch(`/api/plugins" not in src
    assert "workers.dev" not in src  # no hardcoded relay origin in the client


def test_approves_with_operator_confirmed_fingerprint() -> None:
    src = _source()
    assert "confirmed_fingerprint" in src
    # The raw 32-byte channel-binding digest never appears in the UI half.
    assert "channel_binding_digest" not in src


def test_roster_reads_registry_and_probes_scoped() -> None:
    src = _source()
    # The roster lists gateways from the connection registry and probes each
    # one connection-scoped, degrading gracefully when the bridge is absent.
    assert "host.connections()" in src
    assert "window.hermesDesktop" in src
    assert "connectionId" in src
    assert "mr-dot" in src  # explicit-colored status light
    assert "supported === false" in src  # graceful-degrade guard


def test_roster_light_distinguishes_not_installed_from_unreachable() -> None:
    src = _source()
    # A 404 (relay plugin absent) reads amber "not installed", not red
    # "unreachable"; operational is an explicit green.
    assert "notFound" in src
    assert "relay not installed here" in src
    assert "color: 'green'" in src


def test_qr_is_server_rendered_not_reconstructed_client_side() -> None:
    src = _source()
    # The QR SVG comes from the create response; the client never rebuilds the
    # pairing capability into a QR itself.
    assert "qr_svg" in src
    assert "addData" not in src


def test_active_panel_state_is_scoped_by_connection() -> None:
    """BR-06: a gateway switch must not leak the prior gateway's offer,
    status, or device rows into the newly active panel."""

    src = _source()
    # Query caches are keyed by the active connection.
    assert src.count("queryKey: ['mercury-relay', props.connectionId || null,") == 3
    # The panel receives the active connection and is remounted (React key)
    # when it changes, clearing the local one-time QR offer and errors.
    assert "connectionId: activeConnectionId" in src
    assert "key: activeConnectionId || 'no-connection'" in src
