"""Feishu/Lark adapter — bridges Feishu Bot to UnifiedMessage.

Requires: pip install lark-oapi
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import AsyncIterator

from aiohttp import web
import lark_oapi as lark
from lark_oapi.api.im.v1 import (
    CreateMessageRequest,
    CreateMessageRequestBody,
)

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


class FeishuAdapter(ChannelAdapter):
    """
    Feishu/Lark channel adapter using the official lark-oapi SDK.

    Uses webhook (event subscription) for receiving and REST API for sending.
    """

    channel_id = "feishu"

    def __init__(
        self,
        app_id: str,
        app_secret: str,
        *,
        verification_token: str = "",
        encrypt_key: str = "",
        port: int = 9000,
        path: str = "/feishu/webhook",
        command_prefix: str = "/",
    ) -> None:
        self._app_id = app_id
        self._app_secret = app_secret
        self._verification_token = verification_token
        self._encrypt_key = encrypt_key
        self._port = port
        self._path = path
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None

        self._client = lark.Client.builder() \
            .app_id(app_id) \
            .app_secret(app_secret) \
            .build()

    async def connect(self) -> None:
        app = web.Application()
        app.router.add_post(self._path, self._handle_webhook)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        self._connected = True
        logger.info("feishu connected: webhook on port %d%s", self._port, self._path)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("feishu disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        content = json.dumps({"text": msg.text})
        request = CreateMessageRequest.builder() \
            .receive_id_type("chat_id") \
            .request_body(
                CreateMessageRequestBody.builder()
                .receive_id(msg.chat_id)
                .msg_type("text")
                .content(content)
                .build()
            ).build()

        response = self._client.im.v1.message.create(request)
        self._last_activity = datetime.now()

        if response.success():
            return response.data.message_id if response.data else None
        logger.error("feishu send failed: %s %s", response.code, response.msg)
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="feishu",
            account_id=self._app_id,
            last_activity=self._last_activity,
        )

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        body = await request.json()

        # URL verification challenge
        if body.get("type") == "url_verification":
            return web.json_response({"challenge": body.get("challenge", "")})

        # Verify token if configured
        token = body.get("token", "")
        if self._verification_token and token != self._verification_token:
            return web.Response(status=403)

        header = body.get("header", {})
        event = body.get("event", {})
        event_type = header.get("event_type", "")

        if event_type == "im.message.receive_v1":
            await self._process_message(event)

        return web.json_response({"code": 0})

    async def _process_message(self, event: dict) -> None:
        sender = event.get("sender", {})
        sender_id_info = sender.get("sender_id", {})
        sender_id = sender_id_info.get("open_id", "")
        sender_type = sender.get("sender_type", "")

        message = event.get("message", {})
        msg_id = message.get("message_id", "")
        msg_type = message.get("message_type", "")
        chat_id = message.get("chat_id", "")
        content_str = message.get("content", "{}")
        create_time = message.get("create_time", "0")

        self._last_activity = datetime.now()

        try:
            content = json.loads(content_str)
        except json.JSONDecodeError:
            content = {}

        if msg_type == "text":
            text = content.get("text", "")
            if text.startswith(self._prefix):
                parts = text[len(self._prefix):].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(type=ContentType.COMMAND, text=text, command=cmd, args=args)
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)
        elif msg_type in ("image", "video", "file"):
            mc = MessageContent(type=ContentType.MEDIA, media_type=msg_type)
        else:
            return

        try:
            ts = datetime.fromtimestamp(int(create_time) / 1000)
        except (ValueError, OSError):
            ts = datetime.now()

        msg = UnifiedMessage(
            id=msg_id,
            channel="feishu",
            sender=Identity(id=sender_id),
            content=mc,
            timestamp=ts,
            chat_id=chat_id,
            raw=event,
        )
        await self._queue.put(msg)
