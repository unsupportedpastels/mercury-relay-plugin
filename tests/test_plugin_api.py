from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from conftest import contract_import

contract_import("fastapi")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PLUGIN_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))


def _load_plugin_api():
    path = PLUGIN_ROOT / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("mercury_relay_test_plugin_api", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_router_lifespan_starts_and_stops_one_runtime() -> None:
    module = _load_plugin_api()

    class FakeRuntime:
        def __init__(self) -> None:
            self.started = 0
            self.closed = 0
            self.state = "ready"
            self.contract = {"status": "ready", "supported": True}

        async def start(self) -> None:
            self.started += 1

        async def close(self) -> None:
            self.closed += 1

        def snapshot(self) -> dict:
            return {
                "installed": True,
                "runtime": self.state,
                "hermes_contract": self.contract,
            }

    fake = FakeRuntime()
    module._runtime = fake
    app = FastAPI()
    app.include_router(module.router, prefix="/api/plugins/mercury-relay")
    with TestClient(app) as client:
        response = client.get("/api/plugins/mercury-relay/status")
        assert response.status_code == 200
        assert response.json()["runtime"] == "ready"
        assert fake.started == 1
        assert fake.closed == 0
    assert fake.started == 1
    assert fake.closed == 1


def test_status_sanitizes_missing_hermes_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Isolate HERMES_HOME so `relay_origin_configured` is deterministic — it
    # reads the profile's public config, and the machine's real home may
    # override relay_origin. An empty home resolves to the built-in hosted
    # relay default, so a fresh install reports the origin as configured.
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    module = _load_plugin_api()
    module._runtime = module.RelayRuntime(
        loader=lambda: (_ for _ in ()).throw(ImportError("private"))
    )
    app = FastAPI()
    app.include_router(module.router, prefix="/api/plugins/mercury-relay")
    with TestClient(app) as client:
        payload = client.get("/api/plugins/mercury-relay/status").json()
    assert payload == {
        "installed": True,
        "runtime": "unsupported_hermes_contract",
        "hermes_contract": {
            "status": "unsupported_hermes_contract",
            "supported": False,
        },
        "active_controllers": 0,
        "max_controllers": 8,
        "relay_origin_configured": True,
        "relay_connected": False,
        "relay_refusal": None,
        "relay_machine_id": None,
    }
    assert "private" not in str(payload)
