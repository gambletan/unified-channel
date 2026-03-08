"""Middleware layer — shared logic that channels don't re-implement."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Any

from .types import OutboundMessage, UnifiedMessage

logger = logging.getLogger(__name__)

# Handler signature: receives message, returns optional reply text
Handler = Callable[[UnifiedMessage], Awaitable[str | OutboundMessage | None]]


class Middleware(ABC):
    """Base middleware that wraps a handler."""

    @abstractmethod
    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        """Process message, optionally call next_handler to continue the chain."""


class AccessMiddleware(Middleware):
    """Gate messages by sender allowlist."""

    def __init__(self, allowed_user_ids: set[str] | None = None):
        self.allowed_user_ids = allowed_user_ids

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        if self.allowed_user_ids and msg.sender.id not in self.allowed_user_ids:
            logger.warning(
                "access denied: user=%s channel=%s", msg.sender.id, msg.channel
            )
            return None  # silently drop
        return await next_handler(msg)


class CommandMiddleware(Middleware):
    """
    Route /commands to registered handlers.
    Non-command messages pass through to the next handler.
    """

    def __init__(self) -> None:
        self._commands: dict[str, Callable[..., Awaitable[Any]]] = {}

    def command(
        self, name: str
    ) -> Callable[
        [Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]
    ]:
        """Decorator to register a command handler."""

        def decorator(
            fn: Callable[..., Awaitable[Any]],
        ) -> Callable[..., Awaitable[Any]]:
            self._commands[name] = fn
            return fn

        return decorator

    def register(self, name: str, handler: Callable[..., Awaitable[Any]]) -> None:
        """Register a command handler programmatically."""
        self._commands[name] = handler

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        if msg.content.command and msg.content.command in self._commands:
            handler = self._commands[msg.content.command]
            result = await handler(msg)
            if isinstance(result, str):
                return result
            return result
        return await next_handler(msg)

    @property
    def registered_commands(self) -> list[str]:
        return list(self._commands.keys())
