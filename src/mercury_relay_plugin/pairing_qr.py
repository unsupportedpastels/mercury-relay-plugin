"""Server-side pairing-QR construction.

The pairing descriptor and its QR are built here so the dashboard page and the
desktop plugin render one identical QR from the create-offer response, with no
client-side QR library. The QR is returned as an inline SVG string; it carries
the one-time capability and is therefore only ever in the create response.
"""

from __future__ import annotations

import json
from typing import Any

try:
    import segno as _segno
except ImportError:
    import sys as _sys
    from pathlib import Path as _Path

    _vendor = str(_Path(__file__).resolve().parent / "_vendor")
    if _vendor not in _sys.path:
        _sys.path.append(_vendor)
    import segno as _segno

PAIRING_SCHEME = "mercury-relay"
PAIRING_PROTOCOL_MAJOR = 1


def pairing_descriptor(offer_local_dict: dict[str, Any]) -> dict[str, Any]:
    """The compact, self-contained pairing payload the phone validates."""

    descriptor = {
        "s": PAIRING_SCHEME,
        "v": PAIRING_PROTOCOL_MAJOR,
        "o": offer_local_dict.get("relay_origin"),
        "i": offer_local_dict["installation_id"],
        "k": offer_local_dict["host_public_key"],
        "c": offer_local_dict["capability"],
        "x": offer_local_dict["expires_at"],
    }
    # Routing-admission token (MR-01): admits the phone's pairing socket at
    # the relay edge. Expires with the offer; not a pairing secret. The key is
    # present only when a token exists — a null "t" would just be an
    # unusable QR against a fail-closed relay, so it is omitted, and a client
    # that sees no "t" knows the relay does not require routing admission.
    token = offer_local_dict.get("pairing_token")
    if token is not None:
        descriptor["t"] = token
    return descriptor


def pairing_payload_text(offer_local_dict: dict[str, Any]) -> str:
    return json.dumps(
        pairing_descriptor(offer_local_dict),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def pairing_qr_svg(offer_local_dict: dict[str, Any], *, scale: int = 5) -> str:
    """Render the pairing payload as a self-contained, theme-neutral SVG."""

    payload = pairing_payload_text(offer_local_dict)
    qr = _segno.make(payload, error="m")
    import io

    # A 4-module quiet zone is the QR spec minimum; some scanners fail with
    # less, especially against a busy background.
    border = 4
    buffer = io.BytesIO()
    qr.save(
        buffer,
        kind="svg",
        scale=scale,
        border=border,
        dark="#000000",
        light="#ffffff",
        svgclass=None,
        lineclass=None,
        xmldecl=False,
        svgns=True,
    )
    svg = buffer.getvalue().decode("utf-8")

    # segno emits width/height but no viewBox. Without a viewBox, any CSS that
    # sizes the <svg> (the desktop plugin forces 200x200) shrinks the viewport
    # while the modules keep their intrinsic coordinate space, cropping the QR
    # instead of scaling it and making it undecodable. Inject a viewBox so the
    # code scales cleanly at any display size on every surface.
    modules = qr.symbol_size(scale=1, border=border)[0]
    extent = modules * scale
    if "viewBox" not in svg:
        svg = svg.replace(
            "<svg ",
            f'<svg viewBox="0 0 {extent} {extent}" ',
            1,
        )
    return svg


__all__ = [
    "PAIRING_PROTOCOL_MAJOR",
    "PAIRING_SCHEME",
    "pairing_descriptor",
    "pairing_payload_text",
    "pairing_qr_svg",
]
