#!/usr/bin/env bash
# Full-contract verification gate.
#
# Runs the plugin test suite with MERCURY_REQUIRE_FULL_CONTRACT=1 inside the
# pinned Hermes environment, so the frozen tui_gateway/starlette/fastapi
# contract tests must RUN and PASS instead of silently skipping.
#
# Usage: scripts/compat_gate.sh [extra pytest args]
#   HERMES_AGENT_ROOT   Hermes source root (default: ~/.hermes/hermes-agent)
#   HERMES_PYTHON       Hermes interpreter (default: $HERMES_AGENT_ROOT/venv/bin/python)
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERMES_AGENT_ROOT="${HERMES_AGENT_ROOT:-$HOME/.hermes/hermes-agent}"
HERMES_PYTHON="${HERMES_PYTHON:-$HERMES_AGENT_ROOT/venv/bin/python}"

if [[ ! -x "$HERMES_PYTHON" ]]; then
    echo "compat_gate: Hermes interpreter not found at $HERMES_PYTHON" >&2
    exit 2
fi
if [[ ! -d "$HERMES_AGENT_ROOT/tui_gateway" ]]; then
    echo "compat_gate: tui_gateway not found under $HERMES_AGENT_ROOT" >&2
    exit 2
fi

# The Hermes venv carries everything the frozen contract needs; the plugin's
# pure-Python Noise runtime is vendored in the package itself, so the Hermes
# environment is never modified.
cd "$PLUGIN_DIR"
exec env \
    MERCURY_REQUIRE_FULL_CONTRACT=1 \
    PYTHONPATH="$HERMES_AGENT_ROOT:$PLUGIN_DIR/src" \
    "$HERMES_PYTHON" -m pytest -q "$@"
