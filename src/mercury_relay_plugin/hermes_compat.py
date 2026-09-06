"""Narrow compatibility wrapper around Hermes's in-process WS session gateway."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import inspect
from collections.abc import Callable
from typing import Any

from .virtual_ws import VirtualWebSocket

UNSUPPORTED_STATUS = "unsupported_hermes_contract"


class HermesContractUnavailable(RuntimeError):
    """Raised without leaking host import or configuration details."""

    def __init__(self) -> None:
        super().__init__(UNSUPPORTED_STATUS)


def _validate_handler(handler: Any) -> Callable[..., Any]:
    try:
        signature = inspect.signature(handler)
        ws_parameter = signature.parameters.get("ws")
        identity_parameter = signature.parameters.get("auth_identity")
        if (
            not callable(handler)
            or not inspect.iscoroutinefunction(handler)
            or ws_parameter is None
            or identity_parameter is None
            or identity_parameter.default is not None
        ):
            raise HermesContractUnavailable
        return handler
    except HermesContractUnavailable:
        raise
    except Exception:
        raise HermesContractUnavailable from None


def load_handle_ws() -> Callable[..., Any]:
    """Resolve and validate the smallest Hermes transport contract we use."""

    try:
        module = importlib.import_module("tui_gateway.ws")
        return _validate_handler(module.handle_ws)
    except HermesContractUnavailable:
        raise
    except Exception:
        raise HermesContractUnavailable from None


def probe_hermes_contract(
    *, loader: Callable[[], Callable[..., Any]] = load_handle_ws
) -> dict[str, bool | str]:
    try:
        _validate_handler(loader())
    except Exception:
        return {"status": UNSUPPORTED_STATUS, "supported": False}
    return {"status": "ready", "supported": True}


class HermesSessionBridge:
    """Own one invocation of Hermes's existing JSON-RPC WebSocket handler."""

    def __init__(
        self,
        websocket: VirtualWebSocket,
        *,
        loader: Callable[[], Callable[..., Any]] = load_handle_ws,
        close_timeout: float = 5.0,
    ) -> None:
        if close_timeout <= 0:
            raise ValueError("close_timeout must be positive")
        self.websocket = websocket
        self._loader = loader
        self._close_timeout = float(close_timeout)
        self._task: asyncio.Task[None] | None = None
        self.status = "stopped"

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.running:
            return
        try:
            handler = _validate_handler(self._loader())
        except Exception:
            self.status = UNSUPPORTED_STATUS
            raise HermesContractUnavailable from None

        self.status = "starting"

        async def run() -> None:
            try:
                await handler(self.websocket, auth_identity=None)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.status = "failed"
            finally:
                if self.status not in {UNSUPPORTED_STATUS, "failed"}:
                    self.status = "stopped"
                # Any handler exit is terminal: close the virtual socket so
                # the lease pump observes the close instead of waiting on an
                # outbound queue no handler will ever drain again.
                with contextlib.suppress(Exception):
                    await self.websocket.close(code=1011, reason="bridge_exit")

        self._task = asyncio.create_task(run(), name="mercury-hermes-session-bridge")
        await asyncio.sleep(0)
        if self._task.done():
            # The handler completed before startup was established; a normal
            # return here is just as unusable as a crash.
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
            if self.status not in {UNSUPPORTED_STATUS, "failed"}:
                self.status = "failed"
            raise RuntimeError("hermes_session_bridge_failed")
        self.status = "running"

    async def close(self) -> None:
        task = self._task
        if task is None:
            self.status = "stopped"
            await self.websocket.close()
            return
        await self.websocket.close(code=1000, reason="bridge_closed")
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=self._close_timeout)
        except TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        finally:
            self._task = None
            self.status = "stopped"
