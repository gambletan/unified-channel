"""MessageQueue middleware — decouples message receiving from processing via async queues."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .middleware import Handler, Middleware
from .types import OutboundMessage, UnifiedMessage

logger = logging.getLogger(__name__)

ProcessHandler = Callable[[UnifiedMessage], Awaitable[str | OutboundMessage | None]]


class InMemoryQueue:
    """Simple async queue with bounded concurrency and max size."""

    def __init__(self, concurrency: int = 5, max_size: int = 1000) -> None:
        self._concurrency = concurrency
        self._max_size = max_size
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue(maxsize=max_size)
        self._handler: ProcessHandler | None = None
        self._running = False
        self._workers: list[asyncio.Task[None]] = []

    def enqueue(self, msg: UnifiedMessage) -> bool:
        """Push a message onto the queue. Returns False if full."""
        try:
            self._queue.put_nowait(msg)
            return True
        except asyncio.QueueFull:
            return False

    def on_process(self, handler: ProcessHandler) -> None:
        """Register the processing callback."""
        self._handler = handler

    def start(self) -> None:
        """Start worker tasks that consume from the queue."""
        if self._running:
            return
        self._running = True
        loop = asyncio.get_running_loop()
        for i in range(self._concurrency):
            task = loop.create_task(self._worker(i))
            self._workers.append(task)

    async def stop(self) -> None:
        """Stop consuming (in-flight items finish, then workers exit)."""
        self._running = False
        for task in self._workers:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._workers.clear()

    def size(self) -> int:
        """Current number of queued (unprocessed) items."""
        return self._queue.qsize()

    async def drain(self) -> None:
        """Wait until queue is empty and all in-flight work completes."""
        await self._queue.join()

    async def _worker(self, _worker_id: int) -> None:
        """Internal worker loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            except (asyncio.TimeoutError, TimeoutError):
                continue
            if msg is None:
                # Sentinel for shutdown
                self._queue.task_done()
                break
            try:
                if self._handler:
                    await self._handler(msg)
            except Exception:
                logger.exception("Error processing queued message %s", msg.id)
            finally:
                self._queue.task_done()


class QueueMiddleware(Middleware):
    """
    Middleware that intercepts messages and enqueues them instead of processing inline.
    The actual processing happens asynchronously via the queue's on_process callback.
    """

    def __init__(self, queue: InMemoryQueue) -> None:
        self._queue = queue

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        accepted = self._queue.enqueue(msg)
        if not accepted:
            logger.warning("Queue full, dropping message %s", msg.id)
        # Message will be processed asynchronously; return None (no inline reply)
        return None


class QueueProcessor:
    """
    Convenience: creates a processor that pulls from the queue and sends replies
    through the provided send function.
    """

    def __init__(
        self,
        queue: InMemoryQueue,
        send_reply: Callable[[str, str | OutboundMessage | None], Awaitable[Any]],
    ) -> None:
        self._queue = queue
        self._send_reply = send_reply

    def start(self, handler: ProcessHandler) -> None:
        """Wire up a handler and start the queue."""

        async def _wrapped(msg: UnifiedMessage) -> str | OutboundMessage | None:
            result = await handler(msg)
            if result is not None and msg.chat_id:
                await self._send_reply(msg.chat_id, result)
            return result

        self._queue.on_process(_wrapped)
        self._queue.start()

    async def stop(self) -> None:
        """Stop the queue."""
        await self._queue.stop()
