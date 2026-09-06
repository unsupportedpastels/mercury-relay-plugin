"""One strict JSON reader shared by every peer-facing parsing boundary.

Every module that parses peer-controlled or persisted JSON must reject the
same hostile shapes the same way: duplicate object keys and the non-standard
``NaN``/``Infinity`` constants are refused before any value is interpreted.
"""

from __future__ import annotations

import json
from typing import Any


class StrictJsonError(ValueError):
    """Raised when text is not strictly-parseable JSON."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise StrictJsonError("non-standard JSON constant")


def loads_strict(text: str) -> Any:
    """Parse *text*, rejecting duplicate keys and NaN/Infinity constants.

    Raises :class:`StrictJsonError` for every parse failure so callers map it
    to their own stable, non-oracular rejection.
    """

    if not isinstance(text, str):
        raise StrictJsonError("input must be text")
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise StrictJsonError("invalid JSON") from None


__all__ = ["StrictJsonError", "loads_strict"]
