"""ServiceBridge — turn any service into a chat-controllable interface."""

from __future__ import annotations

import asyncio
import inspect
import logging
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .manager import ChannelManager
from .middleware import CommandMiddleware
from .types import UnifiedMessage

logger = logging.getLogger(__name__)


@dataclass
class _CommandEntry:
    handler: Callable[..., Awaitable[str]]
    description: str
    params: list[str]


class ServiceBridge:
    """Turn any service into a chat-controllable interface.

    Wraps a ChannelManager and provides a simple API to expose functions as
    chat commands with automatic /help generation, argument parsing, error
    handling, and sync-function support.
    """

    def __init__(self, manager: ChannelManager, prefix: str = "/") -> None:
        self.manager = manager
        self.prefix = prefix
        self._commands: dict[str, _CommandEntry] = {}
        self._middleware = CommandMiddleware()
        manager.add_middleware(self._middleware)

        # Register built-in /help
        self._register_builtin("help", self._handle_help, "Show available commands")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def expose(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str = "",
        params: list[str] | None = None,
    ) -> None:
        """Expose a function as a chat command.

        *handler* can be:
        - ``async def handler(args: list[str]) -> str``
        - ``async def handler(args: list[str], msg: UnifiedMessage) -> str``
        - ``def handler(args: list[str]) -> str``  (sync, auto-wrapped)
        """
        wrapped = self._wrap_handler(handler)
        entry = _CommandEntry(handler=wrapped, description=description, params=params or [])
        self._commands[name] = entry
        self._middleware.register(name, self._make_command_callback(name, wrapped))

    def expose_status(self, handler: Callable[..., Any]) -> None:
        """Register a status check, auto-mapped to /status."""
        self.expose("status", handler, description="Show service status")

    def expose_logs(self, handler: Callable[..., Any]) -> None:
        """Register a log viewer, auto-mapped to /logs."""
        self.expose("logs", handler, description="Show recent logs")

    async def run(self) -> None:
        """Start the bridge (delegates to manager.run())."""
        await self.manager.run()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _register_builtin(self, name: str, handler: Callable[..., Awaitable[str]], description: str) -> None:
        """Register a built-in command (help, etc.)."""
        entry = _CommandEntry(handler=handler, description=description, params=[])
        self._commands[name] = entry
        self._middleware.register(name, self._make_command_callback(name, handler))

    def _wrap_handler(self, handler: Callable[..., Any]) -> Callable[..., Awaitable[str]]:
        """Wrap sync handlers to async; detect signature to pass (args) or (args, msg)."""
        if not inspect.iscoroutinefunction(handler):
            orig = handler

            async def async_wrapper(*a: Any, **kw: Any) -> str:
                return orig(*a, **kw)

            # Preserve signature for _wants_msg check
            async_wrapper.__wrapped__ = orig  # type: ignore[attr-defined]
            return async_wrapper
        return handler

    def _wants_msg(self, handler: Callable[..., Any]) -> bool:
        """Return True if *handler* accepts a second positional parameter (the message)."""
        fn = getattr(handler, "__wrapped__", handler)
        try:
            sig = inspect.signature(fn)
        except (ValueError, TypeError):
            return False
        params = [
            p
            for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        return len(params) >= 2

    def _parse_args(self, raw_args: list[str]) -> tuple[list[str], dict[str, str]]:
        """Split raw args into positional args and --flag values."""
        positional: list[str] = []
        flags: dict[str, str] = {}
        i = 0
        while i < len(raw_args):
            token = raw_args[i]
            if token.startswith("--"):
                key = token.lstrip("-")
                if "=" in key:
                    k, v = key.split("=", 1)
                    flags[k] = v
                elif i + 1 < len(raw_args) and not raw_args[i + 1].startswith("--"):
                    flags[key] = raw_args[i + 1]
                    i += 1
                else:
                    flags[key] = "true"
            else:
                positional.append(token)
            i += 1
        return positional, flags

    def _make_command_callback(
        self, name: str, handler: Callable[..., Awaitable[str]]
    ) -> Callable[[UnifiedMessage], Awaitable[str | None]]:
        """Create the CommandMiddleware-compatible callback for a command."""

        async def callback(msg: UnifiedMessage) -> str | None:
            try:
                raw_args = msg.content.args or []
                positional, flags = self._parse_args(raw_args)
                # Merge flags into positional for handlers that just take args
                all_args = positional
                if flags:
                    # Attach flags as metadata so advanced handlers can use them
                    msg.metadata["_flags"] = flags

                if self._wants_msg(handler):
                    return await handler(all_args, msg)
                else:
                    return await handler(all_args)
            except Exception as exc:
                logger.exception("command /%s failed", name)
                return f"Error running /{name}: {exc}"

        return callback

    async def _handle_help(self, args: list[str]) -> str:
        """Auto-generate /help from all exposed commands."""
        return self._generate_help()

    def _generate_help(self) -> str:
        """Build a help string from all registered commands."""
        lines = ["Available commands:", ""]
        for name, entry in self._commands.items():
            param_str = " ".join(f"<{p}>" for p in entry.params) if entry.params else ""
            desc = f" — {entry.description}" if entry.description else ""
            cmd = f"  {self.prefix}{name}"
            if param_str:
                cmd += f" {param_str}"
            lines.append(f"{cmd}{desc}")
        return "\n".join(lines)
