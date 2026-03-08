"""LINE adapter — bridges LINE Messaging API to UnifiedMessage.

Requires: pip install line-bot-sdk
Uses webhook mode with aiohttp server.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

from linebot.v3.messaging import AsyncApiClient, AsyncMessagingApi, Configuration
from linebot.v3.messaging.models import ReplyMessageRequest, TextMessage
from linebot.v3.webhook import WebhookParser
from linebot.v3.webhooks import (
    FollowEvent,
    MessageEvent,
    TextMessageContent,
    ImageMessageContent,
    VideoMessageContent,
)
from aiohttp import web

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


class LineAdapter(ChannelAdapter):
    """LINE channel adapter using the official LINE Bot SDK v3."""

    channel_id = "line"

    def __init__(
        self,
        channel_secret: str,
        channel_access_token: str,
        *,
        port: int = 8080,
        path: str = "/line/webhook",
        command_prefix: str = "/",
    ) -> None:
        self._channel_secret = channel_secret
        self._access_token = channel_access_token
        self._port = port
        self._path = path
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._parser = WebhookParser(channel_secret)
        self._config = Configuration(access_token=channel_access_token)
        self._api_client: AsyncApiClient | None = None
        self._api: AsyncMessagingApi | None = None
        self._runner: web.AppRunner | None = None
        # LINE reply tokens expire quickly; store for immediate reply
        self._reply_tokens: dict[str, str] = {}

    async def connect(self) -> None:
        self._api_client = AsyncApiClient(self._config)
        self._api = AsyncMessagingApi(self._api_client)

        app = web.Application()
        app.router.add_post(self._path, self._handle_webhook)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()

        self._connected = True
        logger.info("line connected: webhook on port %d%s", self._port, self._path)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        if self._api_client:
            await self._api_client.close()
        self._connected = False
        logger.info("line disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._api:
            raise RuntimeError("line not connected")

        # LINE push message (no reply token needed)
        from linebot.v3.messaging.models import PushMessageRequest

        await self._api.push_message(
            PushMessageRequest(
                to=msg.chat_id,
                messages=[TextMessage(text=msg.text)],
            )
        )
        self._last_activity = datetime.now()
        return None  # LINE push doesn't return message ID

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="line",
            last_activity=self._last_activity,
        )

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        signature = request.headers.get("X-Line-Signature", "")
        body = await request.text()

        try:
            events = self._parser.parse(body, signature)
        except Exception as e:
            logger.warning("line webhook parse error: %s", e)
            return web.Response(status=400)

        for event in events:
            if isinstance(event, MessageEvent):
                await self._process_message(event)
            elif isinstance(event, FollowEvent):
                logger.info("line: new follower %s", event.source.user_id)

        return web.Response(text="OK")

    async def _process_message(self, event: MessageEvent) -> None:
        user_id = event.source.user_id
        self._last_activity = datetime.now()

        # Try to get user profile for display name
        display_name = None
        if self._api:
            try:
                profile = await self._api.get_profile(user_id)
                display_name = profile.display_name
            except Exception:
                pass

        if isinstance(event.message, TextMessageContent):
            text = event.message.text
            if text.startswith(self._prefix):
                parts = text[len(self._prefix):].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(
                    type=ContentType.COMMAND, text=text, command=cmd, args=args,
                )
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)
        elif isinstance(event.message, (ImageMessageContent, VideoMessageContent)):
            mtype = "image" if isinstance(event.message, ImageMessageContent) else "video"
            mc = MessageContent(type=ContentType.MEDIA, media_type=mtype)
        else:
            return  # skip unsupported message types

        # Store reply token for potential immediate reply
        self._reply_tokens[event.message.id] = event.reply_token

        msg = UnifiedMessage(
            id=event.message.id,
            channel="line",
            sender=Identity(id=user_id, display_name=display_name),
            content=mc,
            timestamp=datetime.fromtimestamp(event.timestamp / 1000),
            chat_id=user_id,  # LINE uses user_id for 1:1, group_id for groups
            raw=event,
        )
        await self._queue.put(msg)
