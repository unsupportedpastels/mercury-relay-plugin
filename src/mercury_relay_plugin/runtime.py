"""Lifecycle owner for policy-gated in-process Hermes controllers."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .hermes_compat import HermesSessionBridge, load_handle_ws, probe_hermes_contract
from .method_policy import MethodPolicy
from .virtual_ws import VirtualWebSocket

DEFAULT_MAX_CONTROLLERS = 8


class RelayRuntimeError(RuntimeError):
    """Base class for stable non-oracular runtime failures."""


class RuntimeUnavailable(RelayRuntimeError):
    def __init__(self, reason: str = "runtime_not_ready") -> None:
        self.reason = reason
        super().__init__(reason)


class ControllerLimitReached(RelayRuntimeError):
    def __init__(self) -> None:
        super().__init__("controller_limit_reached")


class ControllerIdUnavailable(RelayRuntimeError):
    def __init__(self) -> None:
        super().__init__("controller_id_unavailable")


class ProfileNotAvailable(RelayRuntimeError):
    def __init__(self) -> None:
        super().__init__("profile_not_available")


def _local_profile_exists(profile: str) -> bool:
    """Resolve profiles through Hermes's public profile path helper."""

    try:
        from hermes_cli.profiles import get_active_profile_name, get_profile_dir

        return (
            profile == (get_active_profile_name() or "default") or get_profile_dir(profile).is_dir()
        )
    except ImportError:
        # Standalone plugin tests do not install Hermes. Production plugin
        # loading always has the public profile helper available.
        return profile == "default"
    except Exception:
        return False


class _Bridge(Protocol):
    async def start(self) -> None: ...

    async def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ControllerHandle:
    controller_id: str
    profile: str
    websocket: VirtualWebSocket
    bridge: _Bridge


class RelayRuntime:
    """Own all inner Hermes controllers for one loaded plugin backend."""

    def __init__(
        self,
        *,
        loader=load_handle_ws,
        bridge_factory: Callable[[VirtualWebSocket], _Bridge] | None = None,
        max_controllers: int = DEFAULT_MAX_CONTROLLERS,
        id_factory: Callable[[], str] | None = None,
        profile_authorizer: Callable[[str], bool] | None = None,
    ) -> None:
        if isinstance(max_controllers, bool) or not isinstance(max_controllers, int):
            raise ValueError("max_controllers must be an integer")
        if max_controllers < 1 or max_controllers > 64:
            raise ValueError("max_controllers is outside the supported range")
        self._loader = loader
        self._bridge_factory = bridge_factory or (
            lambda websocket: HermesSessionBridge(websocket, loader=self._loader)
        )
        self._id_factory = id_factory or (lambda: secrets.token_urlsafe(16))
        if profile_authorizer is not None and not callable(profile_authorizer):
            raise ValueError("profile_authorizer must be callable")
        self._profile_authorizer = profile_authorizer or _local_profile_exists
        self.max_controllers = max_controllers
        self.state = "stopped"
        self.contract: dict[str, bool | str] = {
            "status": "not_checked",
            "supported": False,
        }
        self._controllers: dict[str, ControllerHandle] = {}
        self._lock = asyncio.Lock()

    @property
    def profile_authorizer(self) -> Callable[[str], bool]:
        """The one profile-existence policy shared by controllers and reads."""

        return self._profile_authorizer

    def snapshot(self) -> dict[str, object]:
        return {
            "installed": True,
            "runtime": self.state,
            "hermes_contract": dict(self.contract),
            "active_controllers": len(self._controllers),
            "max_controllers": self.max_controllers,
        }

    async def start(self) -> None:
        async with self._lock:
            if self.state in {"ready", "unsupported_hermes_contract"}:
                return
            if self.state == "closing":
                raise RuntimeUnavailable("runtime_closing")
            self.contract = probe_hermes_contract(loader=self._loader)
            self.state = str(self.contract["status"])

    def _new_controller_id(self) -> str:
        for _ in range(8):
            controller_id = self._id_factory()
            if (
                isinstance(controller_id, str)
                and 1 <= len(controller_id) <= 128
                and controller_id not in self._controllers
            ):
                return controller_id
        raise ControllerIdUnavailable

    async def open_controller(self, *, profile: str) -> ControllerHandle:
        async with self._lock:
            if self.state != "ready":
                raise RuntimeUnavailable
            if len(self._controllers) >= self.max_controllers:
                raise ControllerLimitReached
            try:
                profile_available = self._profile_authorizer(profile) is True
            except Exception:
                profile_available = False
            if not profile_available:
                raise ProfileNotAvailable

            policy = MethodPolicy(
                profile=profile,
                profile_authorizer=self._profile_authorizer,
            )
            controller_id = self._new_controller_id()
            websocket = VirtualWebSocket(inbound_validator=policy.validate_text)
            bridge = self._bridge_factory(websocket)
            try:
                await bridge.start()
            except BaseException:
                await self._close_bridges([bridge])
                raise

            handle = ControllerHandle(
                controller_id=controller_id,
                profile=profile,
                websocket=websocket,
                bridge=bridge,
            )
            self._controllers[handle.controller_id] = handle
            return handle

    async def close_controller(self, controller_id: str) -> bool:
        async with self._lock:
            handle = self._controllers.pop(controller_id, None)
        if handle is None:
            return False
        await self._close_bridges([handle.bridge])
        return True

    async def close(self) -> None:
        async with self._lock:
            if self.state == "stopped" and not self._controllers:
                return
            self.state = "closing"
            bridges = [handle.bridge for handle in self._controllers.values()]
            self._controllers.clear()

        cancelled: asyncio.CancelledError | None = None
        try:
            await self._close_bridges(bridges)
        except asyncio.CancelledError as exc:
            cancelled = exc
        finally:
            async with self._lock:
                self.state = "stopped"
        if cancelled is not None:
            raise cancelled

    @staticmethod
    async def _close_bridges(bridges: list[_Bridge]) -> None:
        if not bridges:
            return
        cleanup = asyncio.ensure_future(
            asyncio.gather(*(bridge.close() for bridge in bridges), return_exceptions=True)
        )
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError:
            await cleanup
            raise
