"""Twitch adapter — IRC-based chat via TMI (Twitch Messaging Interface).

Requires: pip install websockets
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import AsyncIterator

import websockets

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)

TMI_URL = "wss://irc-ws.chat.twitch.tv:443"
_MSG_RE = re.compile(
    r"^:(\w+)!\w+@\w+\.tmi\.twitch\.tv PRIVMSG #(\w+) :(.+)$"
)


class TwitchAdapter(ChannelAdapter):
    """Twitch chat adapter using IRC over WebSocket."""

    channel_id = "twitch"

    def __init__(
        self,
        oauth_token: str,
        bot_username: str,
        channels: list[str],
        *,
        command_prefix: str = "!",
    ) -> None:
        self._token = oauth_token  # oauth:xxx
        self._username = bot_username.lower()
        self._channels = [c.lower().lstrip("#") for c in channels]
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._ws: websockets.WebSocketClientProtocol | None = None
        self._listen_task: asyncio.Task | None = None

    async def connect(self) -> None:
        self._ws = await websockets.connect(TMI_URL)
        token = self._token if self._token.startswith("oauth:") else f"oauth:{self._token}"
        await self._ws.send(f"PASS {token}")
        await self._ws.send(f"NICK {self._username}")
        await self._ws.send("CAP REQ :twitch.tv/tags twitch.tv/commands")

        for ch in self._channels:
            await self._ws.send(f"JOIN #{ch}")

        self._connected = True
        self._listen_task = asyncio.create_task(self._listen())
        logger.info("twitch connected: %s in %s", self._username, self._channels)

    async def disconnect(self) -> None:
        self._connected = False
        if self._listen_task:
            self._listen_task.cancel()
        if self._ws:
            await self._ws.close()
        logger.info("twitch disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._ws:
            raise RuntimeError("twitch not connected")
        channel = msg.chat_id.lstrip("#")
        await self._ws.send(f"PRIVMSG #{channel} :{msg.text}")
        self._last_activity = datetime.now()
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="twitch",
                             account_id=self._username, last_activity=self._last_activity)

    async def _listen(self) -> None:
        try:
            async for raw in self._ws:
                for line in raw.strip().split("\r\n"):
                    if line.startswith("PING"):
                        await self._ws.send("PONG :tmi.twitch.tv")
                        continue
                    await self._process_line(line)
        except (websockets.ConnectionClosed, asyncio.CancelledError):
            self._connected = False

    async def _process_line(self, line: str) -> None:
        # Parse tags if present
        tags = {}
        if line.startswith("@"):
            tag_str, line = line.split(" ", 1)
            for pair in tag_str[1:].split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    tags[k] = v

        match = _MSG_RE.match(line)
        if not match:
            return

        username, channel, text = match.groups()
        if username == self._username:
            return

        self._last_activity = datetime.now()
        user_id = tags.get("user-id", username)
        display = tags.get("display-name", username)
        msg_id = tags.get("id", "")

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=msg_id, channel="twitch",
            sender=Identity(id=user_id, username=username, display_name=display),
            content=mc, chat_id=channel,
            raw={"tags": tags, "text": text},
        )
        await self._queue.put(msg)
