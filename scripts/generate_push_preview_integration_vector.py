#!/usr/bin/env python3
"""Generate ciphertext with the real host codec for the native opener gate."""
from __future__ import annotations

import argparse
import json
import secrets
from pathlib import Path

from mercury_relay_plugin.push_preview import canonical_b64url, encrypt_preview


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    wake, event, kid = map(
        canonical_b64url,
        (secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_bytes(16)),
    )
    now = 2_000_000_010
    plaintext = json.dumps(
        {
            "v": 1,
            "kind": "completion",
            "title": "Host generated",
            "body": "Native opener verified",
            "iat": now - 10,
            "exp": now + 110,
        },
        separators=(",", ":"),
    ).encode()
    value = {
        "key": canonical_b64url(key), "nonce": canonical_b64url(nonce),
        "wake_handle": wake, "event_id": event, "key_id": kid,
        "environment": "sandbox", "now": str(now),
        "expected_title": "Host generated", "expected_body": "Native opener verified",
        "ciphertext": encrypt_preview(key=key, nonce=nonce, plaintext=plaintext,
            environment="sandbox", wake_handle=wake, event_id=event, key_id=kid),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    args.output.chmod(0o600)


if __name__ == "__main__":
    main()
