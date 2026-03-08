"""Microsoft Teams adapter — bridges Bot Framework to UnifiedMessage.

Requires: pip install botbuilder-core botbuilder-integration-aiohttp
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

from aiohttp import web
from botbuilder.core import (
    BotFrameworkAdapter,
    BotFrameworkAdapterSettings,
    TurnContext,
)
from botbuilder.schema import Activity, ActivityTypes

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


class MSTeamsAdapter(ChannelAdapter):
    """
    Microsoft Teams adapter using Bot Framework SDK.

    Runs an aiohttp webhook server that receives activities from Teams.
    """

    channel_id = "msteams"

    def __init__(
        self,
        app_id: str,
        app_password: str,
        *,
        port: int = 3978,
        path: str = "/api/messages",
        command_prefix: str = "/",
    ) -> None:
        self._app_id = app_id
        self._app_password = app_password
        self._port = port
        self._path = path
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None

        settings = BotFrameworkAdapterSettings(app_id, app_password)
        self._bf_adapter = BotFrameworkAdapter(settings)
        # Store conversation references for proactive messaging
        self._conversations: dict[str, object] = {}

    async def connect(self) -> None:
        app = web.Application()
        app.router.add_post(self._path, self._handle_incoming)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        self._connected = True
        logger.info("msteams connected: webhook on port %d%s", self._port, self._path)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("msteams disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        # For proactive messaging, need stored conversation reference
        conv_ref = self._conversations.get(msg.chat_id)
        if not conv_ref:
            logger.error("msteams: no conversation ref for %s", msg.chat_id)
            return None

        sent_id = None

        async def _send(turn: TurnContext):
            nonlocal sent_id
            resp = await turn.send_activity(Activity(type=ActivityTypes.message, text=msg.text))
            sent_id = resp.id if resp else None

        await self._bf_adapter.continue_conversation(conv_ref, _send, self._app_id)
        self._last_activity = datetime.now()
        return sent_id

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="msteams",
            account_id=self._app_id,
            last_activity=self._last_activity,
        )

    async def _handle_incoming(self, request: web.Request) -> web.Response:
        body = await request.json()
        activity = Activity().deserialize(body)

        auth_header = request.headers.get("Authorization", "")

        async def _on_turn(turn: TurnContext):
            # Store conversation reference for proactive messaging
            conv_ref = TurnContext.get_conversation_reference(turn.activity)
            conv_id = turn.activity.conversation.id if turn.activity.conversation else ""
            self._conversations[conv_id] = conv_ref

            if turn.activity.type == ActivityTypes.message:
                await self._process_message(turn)

        try:
            await self._bf_adapter.process_activity(activity, auth_header, _on_turn)
        except Exception as e:
            logger.error("msteams processing error: %s", e)
            return web.Response(status=500)

        return web.Response(status=200)

    async def _process_message(self, turn: TurnContext) -> None:
        activity = turn.activity
        text = activity.text or ""
        self._last_activity = datetime.now()

        sender_id = activity.from_property.id if activity.from_property else ""
        sender_name = activity.from_property.name if activity.from_property else ""
        conv_id = activity.conversation.id if activity.conversation else ""

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            cmd = parts[0] if parts else ""
            args = parts[1:]
            mc = MessageContent(type=ContentType.COMMAND, text=text, command=cmd, args=args)
        elif activity.attachments:
            mc = MessageContent(
                type=ContentType.MEDIA,
                text=text,
                media_url=activity.attachments[0].content_url,
                media_type=activity.attachments[0].content_type,
            )
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=activity.id or "",
            channel="msteams",
            sender=Identity(id=sender_id, display_name=sender_name),
            content=mc,
            timestamp=activity.timestamp or datetime.now(),
            chat_id=conv_id,
            thread_id=activity.reply_to_id,
            raw=activity,
        )
        await self._queue.put(msg)
