"""Settle ordered shutdown steps despite errors and caller cancellation."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Iterable


async def cleanup_steps(steps: Iterable[Callable[[], object]]) -> None:
    errors = []
    cancelled = False
    for step in steps:
        try:
            result = step()
            if inspect.isawaitable(result):
                await result
        except asyncio.CancelledError:
            cancelled = True
        except Exception as error:
            errors.append(error)
    # Preserve the original error type for a single failure, matching lease
    # cleanup's error-before-cancellation contract. Multiple failures stay visible.
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise ExceptionGroup("plugin_shutdown_failed", errors)
    if cancelled:
        raise asyncio.CancelledError


async def await_cleanup(task: asyncio.Task) -> None:
    """Join one owned cleanup task; repeated cancellation cannot orphan it."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break  # Retrieve and propagate the owned task's error below.
    task.result()
    if cancelled:
        raise asyncio.CancelledError
