"""Channel health monitor — detect stale connections and auto-reconnect."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manager import ChannelManager

logger = logging.getLogger(__name__)

# Backoff boundaries
_MIN_INTERVAL = 30.0
_MAX_INTERVAL = 300.0


class HealthMonitor:
    """Periodically check channel health and auto-reconnect on failure.

    Features:
    - Configurable check interval (default 30 s).
    - Exponential backoff per channel on repeated reconnect failures
      (30 s -> 60 s -> 120 s -> max 300 s).
    - Backoff resets once a channel is healthy again.

    Usage::

        monitor = HealthMonitor(interval=30)
        await monitor.start(manager)
        # ... later ...
        await monitor.stop()
    """

    def __init__(self, *, interval: float = 30.0) -> None:
        self._base_interval = max(interval, 1.0)
        self._task: asyncio.Task | None = None
        # Per-channel backoff state: consecutive failure count
        self._failures: dict[str, int] = {}

    async def start(self, manager: ChannelManager) -> None:
        """Start the background health-check loop."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(
            self._loop(manager), name="health-monitor"
        )
        logger.info(
            "health monitor started (interval=%.0fs)", self._base_interval
        )

    async def stop(self) -> None:
        """Cancel the background loop and wait for it to finish."""
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
        logger.info("health monitor stopped")

    # ------------------------------------------------------------------

    async def _loop(self, manager: ChannelManager) -> None:
        try:
            while True:
                await asyncio.sleep(self._base_interval)
                await self._check_all(manager)
        except asyncio.CancelledError:
            pass

    async def _check_all(self, manager: ChannelManager) -> None:
        for channel_id, adapter in manager._channels.items():
            try:
                status = await adapter.get_status()
                if status.connected:
                    # Healthy — reset backoff
                    if channel_id in self._failures:
                        logger.info(
                            "channel %s recovered", channel_id
                        )
                        self._failures.pop(channel_id, None)
                    continue

                # Not connected — attempt reconnect
                failures = self._failures.get(channel_id, 0)
                backoff = min(
                    _MIN_INTERVAL * (2 ** failures), _MAX_INTERVAL
                )

                logger.warning(
                    "channel %s not connected (failures=%d), "
                    "reconnecting in %.0fs...",
                    channel_id,
                    failures,
                    backoff,
                )
                await asyncio.sleep(backoff)
                await self._reconnect(channel_id, adapter)

            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "health check error for channel %s", channel_id
                )
                self._failures[channel_id] = (
                    self._failures.get(channel_id, 0) + 1
                )

    async def _reconnect(self, channel_id: str, adapter) -> None:
        try:
            try:
                await adapter.disconnect()
            except Exception:
                logger.debug(
                    "disconnect before reconnect failed for %s (ignored)",
                    channel_id,
                )
            await adapter.connect()
            logger.info("channel %s reconnected successfully", channel_id)
            self._failures.pop(channel_id, None)
        except Exception as exc:
            self._failures[channel_id] = (
                self._failures.get(channel_id, 0) + 1
            )
            logger.error(
                "reconnect failed for channel %s: %s", channel_id, exc
            )
