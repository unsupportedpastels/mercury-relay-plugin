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


DASHBOARD_JS = Path(__file__).parents[1] / "dashboard" / "dist" / "index.js"


@pytest.mark.parametrize("source_path", [PLUGIN_JS, DASHBOARD_JS], ids=["desktop", "dashboard"])
def test_pairing_code_is_copyable_but_never_rendered_as_text(source_path: Path) -> None:
    """A phone whose camera auto-zooms past the QR can still pair: both UI
    halves offer a Copy button for the payload the QR encodes. The payload is
    handed to the clipboard only; it is never placed in the DOM as text."""

    src = source_path.read_text(encoding="utf-8")
    assert "Copy pairing code" in src
    assert "copyText(offer.pairing_payload)" in src
    # Clipboard write has a non-secure-context fallback (dashboard over LAN http).
    assert "navigator.clipboard" in src
    assert 'execCommand' in src
    # The payload is never interpolated into an element's children.
    assert "}, offer.pairing_payload)" not in src
    assert "mr-fingerprint' }, offer.pairing_payload" not in src
    assert 'mr-fingerprint" }, offer.pairing_payload' not in src


@pytest.mark.parametrize("source_path", [PLUGIN_JS, DASHBOARD_JS], ids=["desktop", "dashboard"])
def test_qr_is_large_and_click_to_enlarge(source_path: Path) -> None:
    """Phone cameras auto-zoom on a small dense code and overshoot it. Both UI
    halves draw the QR large by default and open a near full-screen copy on
    click, so scanning works from a distance without zoom."""

    src = source_path.read_text(encoding="utf-8")
    assert "mr-qr-overlay" in src
    assert "setEnlarged(true)" in src
    assert "setEnlarged(false)" in src


def test_qr_default_size_is_at_least_320px() -> None:
    desktop = _source()
    dashboard_css = (Path(__file__).parents[1] / "dashboard" / "dist" / "style.css").read_text(
        encoding="utf-8"
    )
    assert ".mr-qr svg{width:320px;height:320px" in desktop
    assert "width: 320px;" in dashboard_css
    assert ".mr-qr svg{width:200px" not in desktop  # the old cramped size is gone


def test_roster_light_distinguishes_the_three_404_states() -> None:
    """Hermes answers a plugin route with two different 404 bodies. The gate
    says "Plugin not found" when the name is not in plugins.enabled; plain
    FastAPI says "Not Found" when it is enabled but the router was never
    mounted (process predates the install). The roster must not collapse
    these into one "not installed" light, and the restart guidance must
    name Hermes Desktop for the local child process."""
    src = _source()
    assert "function classify404" in src
    assert "plugin not found" in src.lower()
    assert '"Not Found"' in src
    assert "relay installed but not enabled here" in src
    assert "relay installed, restart needed" in src
    assert "relay not installed here" in src
    assert "MissingBackendCard" in src
    assert "quit and reopen Hermes Desktop" in src
    assert "hermes plugins enable mercury-relay" in src


DOCS = Path(__file__).parents[1]


@pytest.mark.parametrize("name", ["README.md", "docs/install.html"])
def test_install_docs_name_the_right_restart_and_git(name: str) -> None:
    text = (DOCS / name).read_text(encoding="utf-8")
    # "This device" is Hermes Desktop's own `hermes serve` child; the docs
    # must not send local users to `hermes gateway restart` alone.
    assert "quit and reopen hermes desktop" in text.lower()
    assert "hermes gateway restart" in text
    assert "git" in text and "PATH" in text
