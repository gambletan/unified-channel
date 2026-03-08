"""Base channel adapter — each channel only needs to implement this."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import AsyncIterator

from .types import ChannelStatus, OutboundMessage, UnifiedMessage


class ChannelAdapter(ABC):
    """
    Minimal interface per the #39827 proposal.
    A new channel = 1 adapter file implementing these 3 methods.
    """

    channel_id: str  # "telegram", "discord", "slack", ...

    @abstractmethod
    async def connect(self) -> None:
        """Start the channel connection (polling, webhook, websocket, etc.)."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully shut down the channel."""

    @abstractmethod
    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        """Yield incoming messages as a unified stream."""
        yield  # type: ignore[misc]

    @abstractmethod
    async def send(self, msg: OutboundMessage) -> str | None:
        """
        Send a message via this channel.
        Returns the sent message ID if available.
        """

    @abstractmethod
    async def get_status(self) -> ChannelStatus:
        """Return current connection status."""

    async def run_forever(self) -> None:
        """Block until disconnected. Override for custom lifecycle."""
        try:
            await self.connect()
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.disconnect()
