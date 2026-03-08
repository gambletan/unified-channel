"""Slack adapter — bridges slack-bolt to UnifiedMessage."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp

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


class SlackAdapter(ChannelAdapter):
    """
    Slack channel adapter using slack-bolt (Socket Mode).

    Requires:
        - SLACK_BOT_TOKEN (xoxb-...)
        - SLACK_APP_TOKEN (xapp-...) for Socket Mode
    """

    channel_id = "slack"

    def __init__(
        self,
        bot_token: str,
        app_token: str,
        *,
        allowed_channel_ids: set[str] | None = None,
        command_prefix: str = "/",
    ) -> None:
        self._bot_token = bot_token
        self._app_token = app_token
        self._allowed_channels = allowed_channel_ids
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._bot_user_id: str | None = None
        self._handler: AsyncSocketModeHandler | None = None

        self._app = AsyncApp(token=bot_token)
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        @self._app.event("message")
        async def handle_message(event: dict, say, context: dict):
            # Ignore bot messages
            if event.get("bot_id") or event.get("subtype"):
                return

            channel = event.get("channel", "")
            # Filter channels
            if self._allowed_channels and channel not in self._allowed_channels:
                # Allow DMs through (channel type starts with "D")
                if not channel.startswith("D"):
                    return

            text = event.get("text", "")
            user_id = event.get("user", "")
            self._last_activity = datetime.now()

            # Resolve user info
            try:
                user_info = await self._app.client.users_info(user=user_id)
                user_data = user_info.get("user", {})
                username = user_data.get("name", user_id)
                display_name = user_data.get("real_name", username)
            except Exception:
                username = user_id
                display_name = user_id

            # Check if it's a command
            if text.startswith(self._prefix):
                parts = text[len(self._prefix):].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(
                    type=ContentType.COMMAND,
                    text=text,
                    command=cmd,
                    args=args,
                )
            elif event.get("files"):
                files = event["files"]
                mc = MessageContent(
                    type=ContentType.MEDIA,
                    text=text,
                    media_url=files[0].get("url_private"),
                    media_type=files[0].get("mimetype", "unknown"),
                )
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)

            msg = UnifiedMessage(
                id=event.get("ts", ""),
                channel="slack",
                sender=Identity(
                    id=user_id,
                    username=username,
                    display_name=display_name,
                ),
                content=mc,
                timestamp=datetime.now(),
                chat_id=channel,
                thread_id=event.get("thread_ts"),
                reply_to_id=event.get("thread_ts"),
                raw=event,
            )
            await self._queue.put(msg)

    async def connect(self) -> None:
        self._handler = AsyncSocketModeHandler(self._app, self._app_token)
        asyncio.create_task(self._handler.start_async())

        # Get bot user ID
        try:
            auth = await self._app.client.auth_test()
            self._bot_user_id = auth.get("user_id")
        except Exception as e:
            logger.warning("slack auth_test failed: %s", e)

        self._connected = True
        logger.info("slack connected: user=%s", self._bot_user_id)

    async def disconnect(self) -> None:
        if self._handler:
            await self._handler.close_async()
        self._connected = False
        logger.info("slack disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        kwargs: dict = {
            "channel": msg.chat_id,
            "text": msg.text,
        }
        if msg.reply_to_id:
            kwargs["thread_ts"] = msg.reply_to_id

        try:
            result = await self._app.client.chat_postMessage(**kwargs)
            self._last_activity = datetime.now()
            return result.get("ts")
        except Exception as e:
            logger.error("slack send failed: %s", e)
            return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="slack",
            account_id=self._bot_user_id,
            last_activity=self._last_activity,
        )
