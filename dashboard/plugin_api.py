"""Authenticated backend routes and lifecycle for the Mercury Relay plugin.

Hermes mounts this router behind its normal dashboard authentication; the
routes below add no second authentication layer and must never be exposed
without one.  Bodies are read bounded and parsed strictly; every error is a
stable reason code without filesystem, database, or cryptographic detail.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, Request

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_PLUGIN_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SRC))

# isort: off
from mercury_relay_plugin.admission import DeviceAdmissionService  # noqa: E402
from mercury_relay_plugin.authorization import AuthorizationRepository  # noqa: E402
import mercury_relay_plugin  # noqa: E402
from mercury_relay_plugin.config import load_public_config, profile_paths  # noqa: E402
from mercury_relay_plugin.update_check import UpdateChecker  # noqa: E402
from mercury_relay_plugin.connector import RelayConnectorService  # noqa: E402
from mercury_relay_plugin.relay_client import CloudflareRelayConnector  # noqa: E402
from mercury_relay_plugin.management import (  # noqa: E402
    MAX_BODY_BYTES,
    ManagementError,
    ManagementService,
)
from mercury_relay_plugin.routing_auth import RoutingIssuerStore  # noqa: E402
from mercury_relay_plugin.runtime import RelayRuntime  # noqa: E402
from mercury_relay_plugin.strict_json import StrictJsonError, loads_strict  # noqa: E402
# isort: on


_runtime: RelayRuntime = RelayRuntime()
_admission: DeviceAdmissionService | None = None
_management: ManagementService | None = None
# Hosted-connector seam: tests install deterministic fakes here; production
# uses the default provider below, which activates the outbound Cloudflare
# host socket only when the owner has configured a bounded `relay_origin`.
# The provider receives the admission service and returns an object with
# ``start()``/``close()``, or None to run without a hosted connection.
_connector_provider = None
_connector = None
_updates: UpdateChecker | None = None
_update_task: asyncio.Task[None] | None = None


def _build_update_checker(admission: DeviceAdmissionService | None) -> UpdateChecker:
    paths = admission.repository.paths if admission is not None else profile_paths()
    enabled = True
    try:
        enabled = bool(load_public_config(paths).get("update_check", True))
    except Exception:
        enabled = True
    return UpdateChecker(
        installed_version=mercury_relay_plugin.__version__,
        plugin_dir=_PLUGIN_ROOT,
        cache_path=paths.agent_dir / "update-check.json",
        enabled=enabled,
    )


def _default_connector_provider(admission: DeviceAdmissionService):
    config = load_public_config(admission.repository.paths)
    relay_origin = config.get("relay_origin")
    if not relay_origin:
        return None
    identity = admission.repository.identity_store.load_or_create()
    # Phase 0 static routing issuer (MR-01): the plugin mints its own
    # short-lived host tokens per connect attempt; the same issuer signs the
    # QR pairing token and the pairing-ack device token.
    issuer = RoutingIssuerStore(admission.repository.store).load_or_create()
    connector = CloudflareRelayConnector(
        relay_origin=relay_origin,
        installation_id=identity.installation_id,
        token_provider=lambda: issuer.mint_host_token(identity.installation_id),
        journal=admission.journal,
    )
    import os

    if os.environ.get("MERCURY_RELAY_PUSH_ENABLED") == "1":
        try:
            from mercury_relay_plugin.push import PushBridge

            admission.push = PushBridge(
                paths=admission.repository.paths,
                relay_origin=relay_origin,
                installation_id=identity.installation_id,
                token_provider=lambda: issuer.mint_host_token(identity.installation_id),
                authorized=lambda device, epoch: admission._epoch(device) == epoch,
            )
            admission.push.start()
        except Exception:
            # Optional push must not strand existing ciphertext clients.
            admission.push = None
    return RelayConnectorService(
        admission, connector, routing_issuer=issuer, journal=admission.journal
    )


def _build_admission(runtime: RelayRuntime) -> DeviceAdmissionService:
    repository = AuthorizationRepository(profile_paths())
    return DeviceAdmissionService(repository, runtime, profile="default")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    global _admission, _management, _connector
    runtime = _runtime
    await runtime.start()
    try:
        admission = _build_admission(runtime)
    except Exception:
        # Management stays responsive with a sanitized stable state; the
        # status route still reports the runtime snapshot.
        admission = None
    _admission = admission
    _management = ManagementService(admission) if admission is not None else None
    global _updates, _update_task
    try:
        _updates = _build_update_checker(admission)
        _update_task = asyncio.create_task(_updates.run_forever())
    except Exception:
        _updates = None
        _update_task = None
    if admission is not None:
        provider = _connector_provider or _default_connector_provider
        try:
            _connector = provider(admission)
            if _connector is not None:
                await _connector.start()
        except Exception:
            _connector = None
    try:
        yield
    finally:
        task, _update_task = _update_task, None
        if task is not None:
            task.cancel()
        _updates = None
        _management = None
        connector, _connector = _connector, None
        if connector is not None:
            await connector.close()
        admission, _admission = _admission, None
        if admission is not None:
            await admission.close()
        await runtime.close()


router = APIRouter(lifespan=_lifespan)


def _require_management() -> ManagementService:
    if _management is None:
        raise HTTPException(status_code=503, detail="management_unavailable")
    return _management


async def _bounded_json_body(request: Request) -> dict[str, Any]:
    # Stream and stop at the cap: the limit must bound allocation, not just
    # be checked after the whole body has been buffered.
    buffer = bytearray()
    async for chunk in request.stream():
        buffer.extend(chunk)
        if len(buffer) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="body_too_large")
    body = bytes(buffer)
    if not body:
        return {}
    try:
        value = loads_strict(body.decode("utf-8"))
    except (UnicodeDecodeError, StrictJsonError):
        raise HTTPException(status_code=400, detail="invalid_body") from None
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="invalid_body")
    return value


def _managed(callable_result):
    try:
        return callable_result()
    except ManagementError as error:
        raise HTTPException(status_code=error.status_code, detail=error.reason) from None


def _relay_origin_configured() -> bool:
    if _admission is None:
        return False
    try:
        return bool(load_public_config(_admission.repository.paths).get("relay_origin"))
    except Exception:
        return False


@router.get("/status")
async def status() -> dict[str, Any]:
    # Lightweight health for the desktop roster: whether the plugin is present
    # (this route answering proves it), the runtime is ready, a relay origin is
    # configured, and the outbound host socket is live (phone-reachable now).
    snapshot = _runtime.snapshot()
    snapshot["relay_origin_configured"] = _relay_origin_configured()
    snapshot["relay_connected"] = bool(_connector is not None and _connector.connected)
    # "unauthorized" when the relay refused the last upgrade (401/403): this
    # machine is not allowlisted yet. The desktop half turns that into
    # "awaiting relay access" rather than a generic "host offline".
    refusal = getattr(_connector, "last_refusal", None) if _connector is not None else None
    snapshot["relay_refusal"] = refusal if isinstance(refusal, str) else None
    # The machine ID the owner gives the relay operator to be allowlisted.
    snapshot["relay_machine_id"] = (
        _management.relay_machine_id() if _management is not None else None
    )
    return snapshot


@router.post("/pairing-offers")
async def create_pairing_offer(request: Request) -> dict[str, Any]:
    management = _require_management()
    body = await _bounded_json_body(request)
    return _managed(lambda: management.create_pairing_offer(body))


@router.get("/pairing-offers/{offer_id}")
async def pairing_offer_status(offer_id: str) -> dict[str, Any]:
    management = _require_management()
    return _managed(lambda: management.pairing_offer_status(offer_id))


@router.get("/devices")
async def devices() -> dict[str, Any]:
    management = _require_management()
    return _managed(management.devices)


@router.get("/devices/pending")
async def pending_devices() -> dict[str, Any]:
    management = _require_management()
    return _managed(management.pending_devices)


@router.post("/devices/{device_id}/approve")
async def approve_device(device_id: str, request: Request) -> dict[str, Any]:
    management = _require_management()
    body = await _bounded_json_body(request)
    return _managed(lambda: management.approve_device(device_id, body))


@router.post("/devices/{device_id}/label")
async def label_device(device_id: str, request: Request) -> dict[str, Any]:
    management = _require_management()
    body = await _bounded_json_body(request)
    return _managed(lambda: management.label_device(device_id, body))


@router.post("/devices/{device_id}/deny")
async def deny_device(device_id: str) -> dict[str, Any]:
    management = _require_management()
    return _managed(lambda: management.deny_device(device_id))


@router.post("/devices/{device_id}/revoke")
async def revoke_device(device_id: str) -> dict[str, Any]:
    management = _require_management()
    try:
        return await management.revoke_device(device_id)
    except ManagementError as error:
        raise HTTPException(status_code=error.status_code, detail=error.reason) from None


@router.get("/update")
async def update_status() -> dict[str, Any]:
    """Installed vs latest release; cached six hours, no code moves."""

    if _updates is None:
        raise HTTPException(status_code=503, detail="management_unavailable")
    return _updates.snapshot()


@router.post("/update/check")
async def update_check_now() -> dict[str, Any]:
    if _updates is None:
        raise HTTPException(status_code=503, detail="management_unavailable")
    return await _updates.check(force=True)


@router.post("/update/apply")
async def update_apply() -> dict[str, Any]:
    """Run Hermes' own ``hermes plugins update mercury-relay``; the gateway
    must be restarted afterwards to load the new code."""

    if _updates is None:
        raise HTTPException(status_code=503, detail="management_unavailable")
    return await _updates.apply()


@router.get("/diagnostics")
async def diagnostics() -> dict[str, Any]:
    management = _require_management()
    return _managed(management.diagnostics)
