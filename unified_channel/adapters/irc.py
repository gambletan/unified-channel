"""IRC adapter — plain IRC protocol via asyncio sockets.

No external dependencies.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from typing import AsyncIterator

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)

_PRIVMSG_RE = re.compile(r"^:(\S+)!(\S+) PRIVMSG (\S+) :(.+)$")


class IRCAdapter(ChannelAdapter):
    """Plain IRC adapter using asyncio streams."""

    channel_id = "irc"

    def __init__(
        self,
        server: str,
        port: int = 6667,
        nickname: str = "unified-bot",
        channels: list[str] | None = None,
        *,
        password: str | None = None,
        use_ssl: bool = False,
        command_prefix: str = "!",
    ) -> None:
        self._server = server
        self._port = port
        self._nickname = nickname
        self._channels = channels or []
        self._password = password
        self._use_ssl = use_ssl
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._listen_task: asyncio.Task | None = None
        self._msg_counter = 0

    async def connect(self) -> None:
        if self._use_ssl:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            self._reader, self._writer = await asyncio.open_connection(
                self._server, self._port, ssl=ctx,
            )
        else:
            self._reader, self._writer = await asyncio.open_connection(
                self._server, self._port,
            )

        if self._password:
            await self._send_raw(f"PASS {self._password}")
        await self._send_raw(f"NICK {self._nickname}")
        await self._send_raw(f"USER {self._nickname} 0 * :{self._nickname}")

        self._connected = True
        self._listen_task = asyncio.create_task(self._listen())

        # Wait for MOTD end (001 or 376/422)
        await asyncio.sleep(2)
        for ch in self._channels:
            await self._send_raw(f"JOIN {ch}")

        logger.info("irc connected: %s@%s:%d channels=%s",
                     self._nickname, self._server, self._port, self._channels)

    async def disconnect(self) -> None:
        self._connected = False
        if self._listen_task:
            self._listen_task.cancel()
        if self._writer:
            try:
                await self._send_raw("QUIT :bye")
            except Exception:
                pass
            self._writer.close()
        logger.info("irc disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        target = msg.chat_id
        # Split long messages (IRC 512 byte limit)
        for line in msg.text.split("\n"):
            if line.strip():
                await self._send_raw(f"PRIVMSG {target} :{line}")
        self._last_activity = datetime.now()
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="irc",
                             account_id=f"{self._nickname}@{self._server}",
                             last_activity=self._last_activity)

    async def _send_raw(self, line: str) -> None:
        if self._writer:
            self._writer.write((line + "\r\n").encode("utf-8"))
            await self._writer.drain()

    async def _listen(self) -> None:
        try:
            while self._connected and self._reader:
                raw = await self._reader.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").strip()
                if line.startswith("PING"):
                    token = line.split(" ", 1)[1] if " " in line else ""
                    await self._send_raw(f"PONG {token}")
                    continue
                await self._process_line(line)
        except (asyncio.CancelledError, ConnectionError):
            self._connected = False

    async def _process_line(self, line: str) -> None:
        match = _PRIVMSG_RE.match(line)
        if not match:
            return

        nick, hostmask, target, text = match.groups()
        if nick == self._nickname:
            return

        self._last_activity = datetime.now()
        self._msg_counter += 1

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        # For DMs, target is our nickname; reply to sender
        chat_id = target if target.startswith("#") else nick

        msg = UnifiedMessage(
            id=str(self._msg_counter), channel="irc",
            sender=Identity(id=nick, username=nick),
            content=mc, chat_id=chat_id, raw=line,
        )
        await self._queue.put(msg)
