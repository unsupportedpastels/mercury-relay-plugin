"""Bounded in-memory WebSocket facade for the Hermes session gateway."""

from __future__ import annotations

import asyncio
import importlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn

DEFAULT_MAX_QUEUE_ITEMS = 256
DEFAULT_MAX_FRAME_BYTES = 16_777_216
DEFAULT_MAX_QUEUE_BYTES = 8_388_608


class VirtualWebSocketError(RuntimeError):
    """Base class for stable local virtual-transport failures."""


class VirtualWebSocketClosed(VirtualWebSocketError):
    """Raised when a caller uses a closed virtual transport."""


class VirtualWebSocketFrameTooLarge(VirtualWebSocketError):
    """Raised before an oversized frame enters a queue."""


class VirtualWebSocketBackpressure(VirtualWebSocketError):
    """Raised when a bounded queue cannot accept another frame."""


@dataclass(frozen=True, slots=True)
class _VirtualClient:
    host: str = "mercury-inner"
    port: int | None = None


@dataclass(frozen=True, slots=True)
class _CloseSignal:
    code: int
    reason: str


class VirtualWebSocket:
    """The subset of Starlette's WebSocket contract used by ``handle_ws``.

    The relay runtime feeds decrypted JSON-RPC text into ``feed_text`` and
    drains Hermes output through ``next_text``. Both directions are bounded.
    Outer transport detach is deliberately separate from ``close``; a retained
    controller lease keeps this object alive while a mobile socket reconnects.
    """

    def __init__(
        self,
        *,
        max_queue_items: int = DEFAULT_MAX_QUEUE_ITEMS,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_queue_bytes: int = DEFAULT_MAX_QUEUE_BYTES,
        inbound_validator: Callable[[str], str] | None = None,
    ) -> None:
        if max_queue_items < 1:
            raise ValueError("max_queue_items must be positive")
        if max_frame_bytes < 1:
            raise ValueError("max_frame_bytes must be positive")
        if max_queue_bytes < 1:
            raise ValueError("max_queue_bytes must be positive")
        self.max_queue_items = int(max_queue_items)
        self.max_frame_bytes = int(max_frame_bytes)
        self.max_queue_bytes = int(max_queue_bytes)
        self._inbound_validator = inbound_validator
        self.client = _VirtualClient()
        self.scope: dict[str, Any] = {"type": "websocket", "extensions": {}}
        self.accepted = False
        self.accepted_subprotocol: str | None = None
        self.closed = False
        self.close_code: int | None = None
        self.close_reason = ""
        self._inbound: asyncio.Queue[str | _CloseSignal] = asyncio.Queue(
            maxsize=self.max_queue_items
        )
        self._outbound: asyncio.Queue[str | _CloseSignal] = asyncio.Queue(
            maxsize=self.max_queue_items
        )
        self._inbound_bytes = 0
        self._outbound_bytes = 0

    def _validate_text(self, text: str) -> int:
        if not isinstance(text, str):
            raise TypeError("virtual WebSocket frames must be text")
        size = len(text.encode("utf-8"))
        if size > self.max_frame_bytes:
            raise VirtualWebSocketFrameTooLarge("virtual WebSocket frame exceeds limit")
        return size

    def _signal_close(self, *, code: int, reason: str) -> None:
        signal = _CloseSignal(code=code, reason=reason)
        while True:
            try:
                item = self._inbound.get_nowait()
                if isinstance(item, str):
                    self._inbound_bytes -= len(item.encode("utf-8"))
            except asyncio.QueueEmpty:
                break
        self._inbound_bytes = 0
        self._inbound.put_nowait(signal)
        while True:
            try:
                item = self._outbound.get_nowait()
                if isinstance(item, str):
                    self._outbound_bytes -= len(item.encode("utf-8"))
            except asyncio.QueueEmpty:
                break
        self._outbound_bytes = 0
        self._outbound.put_nowait(signal)

    def _close_now(self, *, code: int, reason: str) -> None:
        if not self.closed:
            self.closed = True
            self.close_code = int(code)
            self.close_reason = str(reason)
        self._signal_close(code=self.close_code or code, reason=self.close_reason or reason)

    async def accept(self, subprotocol: str | None = None) -> None:
        if self.closed:
            raise VirtualWebSocketClosed("virtual WebSocket is closed")
        self.accepted = True
        self.accepted_subprotocol = subprotocol

    async def feed_text(self, text: str) -> None:
        """Queue one decrypted peer frame without trimming or normalization."""

        if self.closed:
            raise VirtualWebSocketClosed("virtual WebSocket is closed")
        size = self._validate_text(text)
        if self._inbound_validator is not None:
            text = self._inbound_validator(text)
            size = self._validate_text(text)
        if self._inbound_bytes + size > self.max_queue_bytes:
            self._close_now(code=1013, reason="inbound_backpressure")
            raise VirtualWebSocketBackpressure("virtual inbound byte budget exceeded")
        try:
            self._inbound.put_nowait(text)
            self._inbound_bytes += size
        except asyncio.QueueFull:
            self._close_now(code=1013, reason="inbound_backpressure")
            raise VirtualWebSocketBackpressure("virtual inbound queue is full") from None

    async def feed_json(self, value: Any) -> None:
        await self.feed_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")))

    async def receive_text(self) -> str:
        if self.closed and self._inbound.empty():
            await self._raise_disconnect(self.close_code or 1000, self.close_reason)
        item = await self._inbound.get()
        if isinstance(item, _CloseSignal):
            await self._raise_disconnect(item.code, item.reason)
        self._inbound_bytes -= len(item.encode("utf-8"))
        return item

    @staticmethod
    async def _raise_disconnect(code: int, reason: str) -> NoReturn:
        websocket_module = importlib.import_module("starlette.websockets")
        disconnect_type = websocket_module.WebSocketDisconnect
        raise disconnect_type(code=code, reason=reason)

    async def send_text(self, text: str) -> None:
        """Queue one exact Hermes frame for encryption by the Relay runtime."""

        if self.closed:
            raise VirtualWebSocketClosed("virtual WebSocket is closed")
        size = self._validate_text(text)
        if self._outbound_bytes + size > self.max_queue_bytes:
            self._close_now(code=1013, reason="outbound_backpressure")
            raise VirtualWebSocketBackpressure("virtual outbound byte budget exceeded")
        try:
            self._outbound.put_nowait(text)
            self._outbound_bytes += size
        except asyncio.QueueFull:
            self._close_now(code=1013, reason="outbound_backpressure")
            raise VirtualWebSocketBackpressure("virtual outbound queue is full") from None
        # Hermes can flush a whole buffered token batch in one coroutine. A
        # put_nowait-only send never suspends, starving the runnable lease pump
        # until an otherwise healthy inner transport hits its item cap. Yield
        # after enqueue; do not wait for capacity or relax either queue bound.
        await asyncio.sleep(0)

    async def next_text(self, *, timeout: float | None = None) -> str:
        if timeout is None:
            item = await self._outbound.get()
        else:
            item = await asyncio.wait_for(self._outbound.get(), timeout=timeout)
        if isinstance(item, _CloseSignal):
            raise VirtualWebSocketClosed("virtual WebSocket is closed")
        self._outbound_bytes -= len(item.encode("utf-8"))
        return item

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self._close_now(code=code, reason=reason)
