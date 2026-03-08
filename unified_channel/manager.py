"""ChannelManager — ties adapters + middleware together into a running system."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from .adapter import ChannelAdapter
from .middleware import CommandMiddleware, Handler, Middleware
from .types import ContentType, MessageContent, OutboundMessage, UnifiedMessage

logger = logging.getLogger(__name__)


class ChannelManager:
    """
    Central manager: register channels + middleware, start all, route messages.

    Usage:
        manager = ChannelManager()
        manager.add_channel(TelegramAdapter(token="..."))
        manager.add_middleware(AccessMiddleware(allowed_user_ids={"123"}))

        cmds = CommandMiddleware()
        @cmds.command("status")
        async def status(msg): return "all good"
        manager.add_middleware(cmds)

        await manager.run()
    """

    def __init__(self) -> None:
        self._channels: dict[str, ChannelAdapter] = {}
        self._middlewares: list[Middleware] = []
        self._fallback_handler: Handler | None = None
        self._tasks: list[asyncio.Task[Any]] = []

    def add_channel(self, adapter: ChannelAdapter) -> "ChannelManager":
        self._channels[adapter.channel_id] = adapter
        return self

    def add_middleware(self, mw: Middleware) -> "ChannelManager":
        self._middlewares.append(mw)
        return self

    def on_message(self, handler: Handler) -> Handler:
        """Set fallback handler for non-command messages (decorator or direct)."""
        self._fallback_handler = handler
        return handler

    async def send(
        self,
        channel: str,
        chat_id: str,
        text: str,
        *,
        reply_to_id: str | None = None,
        parse_mode: str | None = None,
    ) -> str | None:
        """Send a message to a specific channel + chat."""
        adapter = self._channels.get(channel)
        if not adapter:
            raise ValueError(f"channel not registered: {channel}")
        return await adapter.send(
            OutboundMessage(
                chat_id=chat_id,
                text=text,
                reply_to_id=reply_to_id,
                parse_mode=parse_mode,
            )
        )

    async def broadcast(self, text: str, chat_ids: dict[str, str]) -> None:
        """Send to multiple channels. chat_ids = {channel: chat_id}."""
        tasks = [
            self.send(channel, chat_id, text)
            for channel, chat_id in chat_ids.items()
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def get_status(self) -> dict[str, Any]:
        """Get status of all registered channels."""
        statuses = {}
        for cid, adapter in self._channels.items():
            try:
                statuses[cid] = await adapter.get_status()
            except Exception as e:
                statuses[cid] = {"connected": False, "error": str(e)}
        return statuses

    async def run(self) -> None:
        """Start all channels and process messages."""
        if not self._channels:
            raise RuntimeError("no channels registered")

        for adapter in self._channels.values():
            await adapter.connect()
            task = asyncio.create_task(
                self._consume(adapter), name=f"channel:{adapter.channel_id}"
            )
            self._tasks.append(task)

        logger.info(
            "unified-channel started: channels=%s",
            list(self._channels.keys()),
        )
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Stop all channels gracefully."""
        for task in self._tasks:
            task.cancel()
        for adapter in self._channels.values():
            try:
                await adapter.disconnect()
            except Exception:
                logger.exception("error disconnecting %s", adapter.channel_id)
        self._tasks.clear()
        logger.info("unified-channel shut down")

    async def _consume(self, adapter: ChannelAdapter) -> None:
        """Read from one channel adapter and process through middleware."""
        try:
            async for msg in adapter.receive():
                try:
                    reply = await self._run_pipeline(msg)
                    if reply and msg.chat_id:
                        out = self._to_outbound(reply, msg)
                        await adapter.send(out)
                except Exception:
                    logger.exception(
                        "error processing message id=%s channel=%s",
                        msg.id,
                        msg.channel,
                    )
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("channel %s consumer crashed", adapter.channel_id)

    async def _run_pipeline(
        self, msg: UnifiedMessage
    ) -> str | OutboundMessage | None:
        """Run message through middleware chain, ending at fallback handler."""

        async def fallback(m: UnifiedMessage) -> str | OutboundMessage | None:
            if self._fallback_handler:
                return await self._fallback_handler(m)
            return None

        handler: Handler = fallback
        # Build chain in reverse so first-added middleware runs first
        for mw in reversed(self._middlewares):

            def make_next(
                current_mw: Middleware, next_h: Handler
            ) -> Handler:
                async def wrapped(m: UnifiedMessage) -> str | OutboundMessage | None:
                    return await current_mw.process(m, next_h)

                return wrapped

            handler = make_next(mw, handler)

        return await handler(msg)

    @staticmethod
    def _to_outbound(reply: str | OutboundMessage, orig: UnifiedMessage) -> OutboundMessage:
        if isinstance(reply, OutboundMessage):
            if not reply.chat_id:
                reply.chat_id = orig.chat_id or ""
            return reply
        return OutboundMessage(
            chat_id=orig.chat_id or "",
            text=reply,
            reply_to_id=orig.id,
        )
