"""Zalo adapter — Official Account API (webhook + REST).

Requires: pip install httpx aiohttp
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

import httpx
from aiohttp import web

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)
ZALO_API = "https://openapi.zalo.me/v3.0/oa"


class ZaloAdapter(ChannelAdapter):
    """Zalo Official Account adapter using webhook + REST API."""

    channel_id = "zalo"

    def __init__(
        self,
        access_token: str,
        *,
        app_secret: str = "",
        port: int = 8060,
        path: str = "/zalo/webhook",
        command_prefix: str = "/",
    ) -> None:
        self._access_token = access_token
        self._app_secret = app_secret
        self._port = port
        self._path = path
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None

    async def connect(self) -> None:
        app = web.Application()
        app.router.add_post(self._path, self._handle_webhook)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        self._connected = True
        logger.info("zalo connected: webhook port %d", self._port)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("zalo disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{ZALO_API}/message/cs",
                headers={"access_token": self._access_token},
                json={
                    "recipient": {"user_id": msg.chat_id},
                    "message": {"text": msg.text},
                },
            )
        self._last_activity = datetime.now()
        data = resp.json()
        if data.get("error") == 0:
            return data.get("data", {}).get("message_id")
        logger.error("zalo send failed: %s", data.get("message"))
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="zalo",
                             last_activity=self._last_activity)

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        body = await request.json()
        event_name = body.get("event_name", "")

        if event_name == "user_send_text":
            await self._process_text(body)
        elif event_name == "user_send_image":
            await self._process_media(body, "image")

        return web.json_response({"error": 0})

    async def _process_text(self, body: dict) -> None:
        sender = body.get("sender", {})
        message = body.get("message", {})
        text = message.get("text", "")
        self._last_activity = datetime.now()

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=message.get("msg_id", ""), channel="zalo",
            sender=Identity(id=sender.get("id", "")),
            content=mc, chat_id=sender.get("id", ""),
            raw=body,
        )
        await self._queue.put(msg)

    async def _process_media(self, body: dict, media_type: str) -> None:
        sender = body.get("sender", {})
        message = body.get("message", {})
        self._last_activity = datetime.now()

        mc = MessageContent(type=ContentType.MEDIA, media_type=media_type,
                            media_url=message.get("url"))
        msg = UnifiedMessage(
            id=message.get("msg_id", ""), channel="zalo",
            sender=Identity(id=sender.get("id", "")),
            content=mc, chat_id=sender.get("id", ""),
            raw=body,
        )
        await self._queue.put(msg)
