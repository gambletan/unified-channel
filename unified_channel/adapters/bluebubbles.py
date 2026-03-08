"""BlueBubbles adapter — iMessage via BlueBubbles REST API.

Requires: pip install httpx
BlueBubbles server: https://bluebubbles.app/
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

import httpx

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)


class BlueBubblesAdapter(ChannelAdapter):
    """iMessage via BlueBubbles macOS server REST API."""

    channel_id = "bluebubbles"

    def __init__(
        self,
        server_url: str,
        password: str,
        *,
        poll_interval: float = 3.0,
        command_prefix: str = "/",
    ) -> None:
        self._server = server_url.rstrip("/")
        self._password = password
        self._poll_interval = poll_interval
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._http: httpx.AsyncClient | None = None
        self._last_timestamp: int = 0
        self._poll_task: asyncio.Task | None = None

    async def connect(self) -> None:
        self._http = httpx.AsyncClient(
            base_url=self._server,
            params={"password": self._password},
            timeout=30,
        )
        # Verify connection
        resp = await self._http.get("/api/v1/server/info")
        resp.raise_for_status()
        self._last_timestamp = int(datetime.now().timestamp() * 1000)

        self._connected = True
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info("bluebubbles connected: %s", self._server)

    async def disconnect(self) -> None:
        self._connected = False
        if self._poll_task:
            self._poll_task.cancel()
        if self._http:
            await self._http.aclose()
        logger.info("bluebubbles disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._http:
            raise RuntimeError("bluebubbles not connected")
        payload = {
            "chatGuid": msg.chat_id,
            "message": msg.text,
            "method": "apple-script",
        }
        resp = await self._http.post("/api/v1/message/text", json=payload)
        self._last_activity = datetime.now()
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("guid")
        logger.error("bluebubbles send failed: %d", resp.status_code)
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="bluebubbles",
                             last_activity=self._last_activity)

    async def _poll_loop(self) -> None:
        while self._connected:
            try:
                await self._check_messages()
            except Exception as e:
                logger.error("bluebubbles poll error: %s", e)
            await asyncio.sleep(self._poll_interval)

    async def _check_messages(self) -> None:
        resp = await self._http.post("/api/v1/message/query", json={
            "after": self._last_timestamp,
            "limit": 50,
            "sort": "ASC",
            "with": ["chat", "handle"],
        })
        if resp.status_code != 200:
            return

        messages = resp.json().get("data", [])
        for m in messages:
            date_created = m.get("dateCreated", 0)
            if date_created > self._last_timestamp:
                self._last_timestamp = date_created

            if m.get("isFromMe", False):
                continue

            text = m.get("text", "") or ""
            if not text:
                continue

            handle = m.get("handle", {})
            sender_id = handle.get("address", "")
            chat_guid = ""
            chats = m.get("chats", [])
            if chats:
                chat_guid = chats[0].get("guid", "")

            self._last_activity = datetime.now()

            if text.startswith(self._prefix):
                parts = text[len(self._prefix):].split()
                mc = MessageContent(type=ContentType.COMMAND, text=text,
                                    command=parts[0] if parts else "", args=parts[1:])
            elif m.get("hasAttachments"):
                mc = MessageContent(type=ContentType.MEDIA, text=text, media_type="attachment")
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)

            msg = UnifiedMessage(
                id=m.get("guid", ""), channel="bluebubbles",
                sender=Identity(id=sender_id),
                content=mc, chat_id=chat_guid, raw=m,
            )
            await self._queue.put(msg)
