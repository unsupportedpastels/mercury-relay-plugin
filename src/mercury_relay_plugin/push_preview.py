"""Frozen encrypted push-preview v1 codec and deterministic text policy."""

from __future__ import annotations

import base64
import json
import re
import struct
import unicodedata
from collections.abc import Mapping

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PREVIEW_CAPABILITY = {
    "version": 1,
    "register_method": "relay.push.preview.register",
    "unregister_method": "relay.push.unregister",
    "aead": "CHACHA20-POLY1305",
    "max_plaintext_bytes": 1280,
    "max_title_utf8_bytes": 160,
    "max_body_utf8_bytes": 640,
}
MAX_PLAINTEXT_BYTES = 1280
MAX_TITLE_BYTES = 160
MAX_BODY_BYTES = 640
MAX_ROUTE_SESSION_BYTES = 128
MAX_ROUTE_PROFILE_BYTES = 64
MAX_TITLE_CHARS = 120
MAX_BODY_CHARS = 240
PREVIEW_TTL_SECONDS = 120
AAD_DOMAIN = "mercury.push-preview.v1"
ALGORITHM = "C20P"
_INTERRUPT_PREFIX = "Operation interrupted: waiting for model response ("
_HEADING = re.compile(r"^#{1,6}\s+.+$")

_ATTENTION_TEXT = {
    "approval.request": (
        "Hermes needs approval",
        "Authorization is required to continue",
    ),
    "clarify.request": (
        "Hermes needs your input",
        "Clarification is required to continue",
    ),
    "secret.request": (
        "Hermes needs secure input",
        "Secure input is required to continue",
    ),
    "sudo.request": (
        "Hermes needs secure input",
        "Secure input is required to continue",
    ),
    "vault.unlock.request": (
        "Hermes needs secure input",
        "Secure input is required to continue",
    ),
    "vault.save_login.request": (
        "Hermes needs secure input",
        "Secure input is required to continue",
    ),
}


def canonical_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_canonical_b64url(value: object, size: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("invalid base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        raise ValueError("invalid base64url") from None
    if len(decoded) != size or canonical_b64url(decoded) != value:
        raise ValueError("invalid base64url")
    return decoded


def _length_prefixed(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def aad_for_preview(environment: str, wake_handle: str, event_id: str, key_id: str) -> bytes:
    fields = (AAD_DOMAIN, "1", ALGORITHM, environment, wake_handle, event_id, key_id)
    return b"".join(_length_prefixed(field) for field in fields)


def encrypt_preview(
    *,
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    environment: str,
    wake_handle: str,
    event_id: str,
    key_id: str,
) -> str:
    if len(key) != 32 or len(nonce) != 12 or len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError("invalid preview encryption input")
    aad = aad_for_preview(environment, wake_handle, event_id, key_id)
    return canonical_b64url(ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad))


def _without_controls(value: str, *, keep_newlines: bool) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(
        character
        for character in normalized
        if (keep_newlines and character == "\n")
        or not unicodedata.category(character).startswith("C")
    )


def _truncate_utf8(value: str, byte_limit: int) -> str:
    if len(value.encode("utf-8")) <= byte_limit:
        return value
    encoded = value.encode("utf-8")[:byte_limit]
    while True:
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            encoded = encoded[: error.start]


def _clean_line(line: str) -> str | None:
    line = line.strip()
    if _HEADING.fullmatch(line):
        return None
    return line.replace("**", "").replace("__", "").replace("`", "").strip()


def completion_excerpt(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = _without_controls(value, keep_newlines=True).strip()
    if not cleaned:
        return None
    if cleaned.startswith(_INTERRUPT_PREFIX):
        return "Response completed"
    lines = []
    for raw in cleaned.split("\n"):
        line = _clean_line(raw)
        if line:
            lines.append(line)
        if len(lines) == 3:
            break
    if not lines:
        return "Response completed"
    result = "\n".join(lines)[:MAX_BODY_CHARS]
    result = _truncate_utf8(result, MAX_BODY_BYTES).rstrip()
    return result or None


def normalize_title(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = _without_controls(value, keep_newlines=True)
    first = ""
    for raw in cleaned.split("\n"):
        line = raw.strip()
        if not line:
            continue
        line = re.sub(r"^#{1,6}\s+", "", line)
        first = line.replace("**", "").replace("__", "").replace("`", "").strip()
        if first:
            break
    first = _truncate_utf8(first[:MAX_TITLE_CHARS], MAX_TITLE_BYTES).strip()
    return first or None


def _valid_route(route: object) -> dict[str, str] | None:
    if not isinstance(route, Mapping) or set(route) != {"durable_session_id", "profile"}:
        return None
    sid, profile = route.get("durable_session_id"), route.get("profile")
    if (
        not isinstance(sid, str)
        or not 1 <= len(sid.encode("utf-8")) <= MAX_ROUTE_SESSION_BYTES
        or not isinstance(profile, str)
        or not 1 <= len(profile.encode("utf-8")) <= MAX_ROUTE_PROFILE_BYTES
        or any(unicodedata.category(c).startswith("C") for c in sid + profile)
    ):
        return None
    return {"sid": sid, "profile": profile}


def _serialize(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_preview_plaintext(
    *,
    kind: str,
    attention_kind: str | None = None,
    response_text: object = None,
    title: object = None,
    include_title: bool,
    include_response_excerpt: bool,
    route: object,
    now: int,
) -> bytes:
    if kind not in {"completion", "attention"} or type(now) is not int or now < 0:
        raise ValueError("invalid preview plaintext")
    value: dict = {"v": 1, "kind": kind}
    if kind == "attention":
        try:
            preview_title, preview_body = _ATTENTION_TEXT[attention_kind]
        except KeyError:
            raise ValueError("invalid attention kind") from None
        value["title"], value["body"] = preview_title, preview_body
    else:
        if include_title and (preview_title := normalize_title(title)):
            value["title"] = preview_title
        if include_response_excerpt and (preview_body := completion_excerpt(response_text)):
            value["body"] = preview_body
    if validated_route := _valid_route(route):
        value["route"] = validated_route
    value["iat"], value["exp"] = now, now + PREVIEW_TTL_SECONDS

    result = _serialize(value)
    # Escaping can make the compact JSON larger than the UTF-8 field bounds.
    # Preserve authenticated routing/time metadata before optional display text.
    for field in ("body", "title"):
        while len(result) > MAX_PLAINTEXT_BYTES and value.get(field):
            value[field] = value[field][:-1]
            if not value[field]:
                del value[field]
            result = _serialize(value)
    if len(result) > MAX_PLAINTEXT_BYTES:
        value.pop("route", None)
        result = _serialize(value)
    if len(result) > MAX_PLAINTEXT_BYTES:
        raise ValueError("preview plaintext too large")
    return result
