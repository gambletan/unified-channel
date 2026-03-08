"""Discord adapter — bridges discord.py to UnifiedMessage."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

import discord

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus,
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)

logger = logging.getLogger(__name__)


class DiscordAdapter(ChannelAdapter):
    """
    Discord channel adapter using discord.py.

    Only responds in specified channel IDs (or DMs if allow_dm=True).
    """

    channel_id = "discord"

    def __init__(
        self,
        token: str,
        *,
        allowed_channel_ids: set[int] | None = None,
        allow_dm: bool = True,
        command_prefix: str = "/",
    ) -> None:
        self._token = token
        self._allowed_channels = allowed_channel_ids
        self._allow_dm = allow_dm
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._bot_user: str | None = None

        intents = discord.Intents.default()
        intents.message_content = True
        self._client = discord.Client(intents=intents)
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        @self._client.event
        async def on_ready():
            self._connected = True
            self._bot_user = str(self._client.user)
            logger.info("discord connected: %s", self._bot_user)

        @self._client.event
        async def on_message(message: discord.Message):
            # Ignore own messages
            if message.author == self._client.user:
                return

            # Filter channels
            if isinstance(message.channel, discord.DMChannel):
                if not self._allow_dm:
                    return
            elif self._allowed_channels and message.channel.id not in self._allowed_channels:
                return

            content = message.content or ""
            self._last_activity = datetime.now()

            # Check if it's a command
            if content.startswith(self._prefix):
                parts = content[len(self._prefix):].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(
                    type=ContentType.COMMAND,
                    text=content,
                    command=cmd,
                    args=args,
                )
            elif message.attachments:
                mc = MessageContent(
                    type=ContentType.MEDIA,
                    text=content,
                    media_url=message.attachments[0].url,
                    media_type=message.attachments[0].content_type or "unknown",
                )
            else:
                mc = MessageContent(type=ContentType.TEXT, text=content)

            msg = UnifiedMessage(
                id=str(message.id),
                channel="discord",
                sender=Identity(
                    id=str(message.author.id),
                    username=message.author.name,
                    display_name=message.author.display_name,
                ),
                content=mc,
                timestamp=message.created_at,
                chat_id=str(message.channel.id),
                thread_id=(
                    str(message.thread.id)
                    if hasattr(message, "thread") and message.thread
                    else None
                ),
                reply_to_id=(
                    str(message.reference.message_id)
                    if message.reference
                    else None
                ),
                raw=message,
            )
            await self._queue.put(msg)

    async def connect(self) -> None:
        # Start client in background — discord.py's start() does not block
        asyncio.create_task(self._client.start(self._token))
        # Wait for ready
        for _ in range(30):
            if self._connected:
                return
            await asyncio.sleep(1)
        raise RuntimeError("discord connection timed out")

    async def disconnect(self) -> None:
        await self._client.close()
        self._connected = False
        logger.info("discord disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        channel = self._client.get_channel(int(msg.chat_id))
        if not channel:
            # Try as DM user ID
            try:
                user = await self._client.fetch_user(int(msg.chat_id))
                channel = await user.create_dm()
            except Exception:
                logger.error("discord: cannot find channel/user %s", msg.chat_id)
                return None

        kwargs: dict = {"content": msg.text}
        if msg.reply_to_id:
            try:
                ref = await channel.fetch_message(int(msg.reply_to_id))  # type: ignore
                kwargs["reference"] = ref
            except Exception:
                pass

        sent = await channel.send(**kwargs)  # type: ignore
        self._last_activity = datetime.now()
        return str(sent.id)

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="discord",
            account_id=self._bot_user,
            last_activity=self._last_activity,
        )
