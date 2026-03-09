"""Keyed async queue — serialize tasks per key, parallel across keys."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

ErrorHandler = Callable[[str, BaseException], Awaitable[None] | None]


class KeyedAsyncQueue:
    """Run async tasks serialized per key, parallel across different keys.

    Typical use: ensure messages from the same customer (session_id) are
    processed one at a time (FIFO), while messages from different customers
    run concurrently.

    Usage::

        queue = KeyedAsyncQueue()
        await queue.run("customer_123", some_coroutine())
    """

    def __init__(self, *, on_error: ErrorHandler | None = None) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._active: dict[str, int] = {}  # refcount per key
        self._on_error = on_error

    async def run(self, key: str, coro: Awaitable) -> None:
        """Execute *coro* under the lock for *key*.

        If the lock for *key* doesn't exist yet it is created on the fly.
        Once all tasks for a key have completed the lock is cleaned up to
        avoid unbounded memory growth.
        """
        # Get or create lock
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock

        self._active[key] = self._active.get(key, 0) + 1

        try:
            async with lock:
                await coro
        except Exception as exc:
            logger.error("keyed_queue error for key=%s: %s", key, exc)
            if self._on_error is not None:
                maybe_coro = self._on_error(key, exc)
                if asyncio.iscoroutine(maybe_coro):
                    await maybe_coro
        finally:
            self._active[key] -= 1
            if self._active[key] <= 0:
                self._active.pop(key, None)
                self._locks.pop(key, None)
