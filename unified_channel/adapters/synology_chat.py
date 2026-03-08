"""Synology Chat adapter — incoming/outgoing webhook.

Requires: pip install aiohttp
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator
from urllib.parse import parse_qs

import httpx
from aiohttp import web

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)


class SynologyChatAdapter(ChannelAdapter):
    """Synology Chat adapter using incoming + outgoing webhooks."""

    channel_id = "synology-chat"

    def __init__(
        self,
        incoming_webhook_url: str,
        *,
        outgoing_token: str = "",
        port: int = 8070,
        path: str = "/synology/webhook",
        command_prefix: str = "/",
    ) -> None:
        self._incoming_url = incoming_webhook_url
        self._outgoing_token = outgoing_token
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
        logger.info("synology-chat connected: webhook port %d", self._port)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("synology-chat disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        payload = f'payload={{"text": {repr(msg.text)}}}'
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                self._incoming_url,
                content=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        self._last_activity = datetime.now()
        return None if resp.status_code == 200 else None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="synology-chat",
                             last_activity=self._last_activity)

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        body = await request.text()
        params = parse_qs(body)

        token = params.get("token", [""])[0]
        if self._outgoing_token and token != self._outgoing_token:
            return web.Response(status=403)

        text = params.get("text", [""])[0]
        user_id = params.get("user_id", [""])[0]
        username = params.get("username", [""])[0]
        self._last_activity = datetime.now()

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=str(datetime.now().timestamp()), channel="synology-chat",
            sender=Identity(id=user_id, username=username),
            content=mc, chat_id=user_id, raw=params,
        )
        await self._queue.put(msg)
        return web.json_response({"success": True})
