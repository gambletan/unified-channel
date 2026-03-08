"""Google Chat adapter — webhook mode using Google Auth.

Requires: pip install google-auth aiohttp httpx
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import AsyncIterator

import httpx
from aiohttp import web
from google.oauth2 import service_account
from google.auth.transport.requests import Request as AuthRequest

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)
CHAT_API = "https://chat.googleapis.com/v1"


class GoogleChatAdapter(ChannelAdapter):
    """Google Chat adapter using webhook for inbound and REST API for outbound."""

    channel_id = "googlechat"

    def __init__(
        self,
        service_account_file: str,
        *,
        port: int = 8090,
        path: str = "/googlechat/webhook",
        command_prefix: str = "/",
    ) -> None:
        self._sa_file = service_account_file
        self._port = port
        self._path = path
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None
        self._credentials = service_account.Credentials.from_service_account_file(
            service_account_file, scopes=["https://www.googleapis.com/auth/chat.bot"]
        )

    def _get_token(self) -> str:
        if not self._credentials.valid:
            self._credentials.refresh(AuthRequest())
        return self._credentials.token

    async def connect(self) -> None:
        app = web.Application()
        app.router.add_post(self._path, self._handle_webhook)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        self._connected = True
        logger.info("googlechat connected: webhook port %d", self._port)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("googlechat disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        token = self._get_token()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{CHAT_API}/{msg.chat_id}/messages",
                headers={"Authorization": f"Bearer {token}"},
                json={"text": msg.text},
            )
        self._last_activity = datetime.now()
        if resp.status_code == 200:
            return resp.json().get("name")
        logger.error("googlechat send failed: %d %s", resp.status_code, resp.text)
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="googlechat",
                             last_activity=self._last_activity)

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        body = await request.json()
        event_type = body.get("type", "")

        if event_type == "ADDED_TO_SPACE":
            logger.info("googlechat: added to space %s", body.get("space", {}).get("name"))
            return web.json_response({"text": "Hello! Send /start for commands."})

        if event_type == "MESSAGE":
            await self._process_message(body)

        return web.json_response({})

    async def _process_message(self, body: dict) -> None:
        message = body.get("message", {})
        sender = message.get("sender", {})
        text = message.get("text", "").strip()
        space = body.get("space", {})
        self._last_activity = datetime.now()

        # Google Chat prepends @bot mention — strip it
        if text.startswith("@"):
            parts = text.split(None, 1)
            text = parts[1] if len(parts) > 1 else ""

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=message.get("name", ""), channel="googlechat",
            sender=Identity(id=sender.get("name", ""), display_name=sender.get("displayName")),
            content=mc, chat_id=space.get("name", ""),
            thread_id=message.get("thread", {}).get("name"),
            raw=body,
        )
        await self._queue.put(msg)
