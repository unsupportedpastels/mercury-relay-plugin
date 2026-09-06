"""Shared contract-import policy for the plugin test suite.

The Hermes in-process contract tests are the reason Task 1 exists: they freeze
the exact ``tui_gateway.ws.handle_ws`` behavior Mercury depends on.  In a bare
plugin environment those imports are unavailable and the tests skip.  The
full verification gate must never accept those skips silently, so setting
``MERCURY_REQUIRE_FULL_CONTRACT=1`` turns every contract skip into a failure.

Run the strict gate from the pinned Hermes environment via
``scripts/compat_gate.sh``.
"""

from __future__ import annotations

import importlib
import os

import pytest

_STRICT_ENV = "MERCURY_REQUIRE_FULL_CONTRACT"


def contract_import(module_name: str):
    """Import a frozen-contract dependency, skipping only when allowed.

    In the default developer environment a missing dependency skips the test,
    matching ``pytest.importorskip``.  Under the strict full-contract gate the
    import must succeed; a missing module fails the test instead of skipping.
    """

    if os.environ.get(_STRICT_ENV) == "1":
        try:
            return importlib.import_module(module_name)
        except ImportError:
            pytest.fail(
                f"full-contract gate requires importable {module_name!r}; "
                "run via scripts/compat_gate.sh inside the pinned Hermes environment",
                pytrace=False,
            )
    return pytest.importorskip(module_name)


posix_only = pytest.mark.skipif(
    os.name != "posix", reason="POSIX mode bits are not enforced on this platform"
)
