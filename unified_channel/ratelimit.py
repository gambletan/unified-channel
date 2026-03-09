"""Rate-limiting middleware — sliding window per sender."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from .middleware import Handler, Middleware
from .types import OutboundMessage, UnifiedMessage


class RateLimitMiddleware(Middleware):
    """Limits how many messages a user can send within a time window.

    Uses a sliding-window algorithm: timestamps of recent messages are stored
    per key. Expired entries are evicted on each call.
    """

    def __init__(
        self,
        max_messages: int = 10,
        window_seconds: float = 60,
        key_fn: Callable[[UnifiedMessage], str] | None = None,
        reply_text: str | None = None,
    ) -> None:
        self.max_messages = max_messages
        self.window_seconds = window_seconds
        self.key_fn = key_fn or (lambda msg: msg.sender.id)
        self.reply_text = reply_text
        # key -> list of timestamps (monotonic seconds)
        self._windows: dict[str, list[float]] = {}

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        key = self.key_fn(msg)
        now = time.monotonic()
        cutoff = now - self.window_seconds

        timestamps = self._windows.get(key)
        if timestamps is None:
            timestamps = []
            self._windows[key] = timestamps

        # Evict expired entries
        idx = 0
        while idx < len(timestamps) and timestamps[idx] <= cutoff:
            idx += 1
        if idx > 0:
            del timestamps[:idx]

        if len(timestamps) >= self.max_messages:
            if self.reply_text:
                return self.reply_text
            return None

        timestamps.append(now)
        return await next_handler(msg)

    def cleanup(self) -> None:
        """Remove expired entries from all tracked keys."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        to_delete = []
        for key, timestamps in self._windows.items():
            idx = 0
            while idx < len(timestamps) and timestamps[idx] <= cutoff:
                idx += 1
            if idx >= len(timestamps):
                to_delete.append(key)
            elif idx > 0:
                del timestamps[:idx]
        for key in to_delete:
            del self._windows[key]

    def reset(self) -> None:
        """Reset all rate limit state."""
        self._windows.clear()
