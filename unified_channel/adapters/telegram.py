"""Telegram adapter — bridges python-telegram-bot to UnifiedMessage."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
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


class TelegramAdapter(ChannelAdapter):
    """
    Telegram channel adapter using python-telegram-bot.

    This is the ONLY file needed to add Telegram support.
    Compare with openclaw's 125-file Telegram implementation —
    all routing/session/middleware logic lives in the shared layer.
    """

    channel_id = "telegram"

    def __init__(self, token: str, *, parse_mode: str = "Markdown") -> None:
        self._token = token
        self._parse_mode = parse_mode
        self._app: Application | None = None  # type: ignore[type-arg]
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._bot_username: str | None = None

    async def connect(self) -> None:
        self._app = (
            Application.builder()
            .token(self._token)
            .build()
        )

        # Register handlers that push to the unified queue
        self._app.add_handler(
            CommandHandler(
                self._app.bot.commands if hasattr(self._app.bot, "commands") else [],
                self._on_command,
            )
        )
        # Catch-all command handler (any /xxx)
        self._app.add_handler(MessageHandler(filters.COMMAND, self._on_command))
        self._app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_text))
        self._app.add_handler(MessageHandler(filters.PHOTO | filters.Document.ALL, self._on_media))
        self._app.add_handler(CallbackQueryHandler(self._on_callback))

        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)  # type: ignore[union-attr]

        me = await self._app.bot.get_me()
        self._bot_username = me.username
        self._connected = True
        logger.info("telegram connected: @%s", self._bot_username)

    async def disconnect(self) -> None:
        if self._app:
            await self._app.updater.stop()  # type: ignore[union-attr]
            await self._app.stop()
            await self._app.shutdown()
        self._connected = False
        logger.info("telegram disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._app:
            raise RuntimeError("telegram not connected")

        kwargs: dict = {"chat_id": int(msg.chat_id), "text": msg.text}
        if msg.parse_mode:
            kwargs["parse_mode"] = msg.parse_mode
        elif self._parse_mode:
            kwargs["parse_mode"] = self._parse_mode
        if msg.reply_to_id:
            kwargs["reply_to_message_id"] = int(msg.reply_to_id)

        # Build inline keyboard if buttons provided
        if msg.buttons:
            from telegram import InlineKeyboardButton, InlineKeyboardMarkup

            keyboard = [
                [
                    InlineKeyboardButton(
                        b.label,
                        callback_data=b.callback_data,
                        url=b.url,
                    )
                    for b in row
                ]
                for row in msg.buttons
            ]
            kwargs["reply_markup"] = InlineKeyboardMarkup(keyboard)

        sent = await self._app.bot.send_message(**kwargs)
        self._last_activity = datetime.now()
        return str(sent.message_id)

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="telegram",
            account_id=self._bot_username,
            last_activity=self._last_activity,
        )

    # -- internal handlers: convert platform events to UnifiedMessage --

    async def _on_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not update.message or not update.message.text:
            return
        text = update.message.text
        parts = text.split()
        cmd = parts[0].lstrip("/").split("@")[0]  # strip /cmd@botname
        args = parts[1:]

        msg = self._build_message(
            update,
            MessageContent(
                type=ContentType.COMMAND,
                text=text,
                command=cmd,
                args=args,
            ),
        )
        await self._queue.put(msg)

    async def _on_text(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not update.message or not update.message.text:
            return
        msg = self._build_message(
            update,
            MessageContent(type=ContentType.TEXT, text=update.message.text),
        )
        await self._queue.put(msg)

    async def _on_media(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not update.message:
            return
        caption = update.message.caption or ""
        msg = self._build_message(
            update,
            MessageContent(
                type=ContentType.MEDIA,
                text=caption,
                media_type="photo" if update.message.photo else "document",
            ),
        )
        await self._queue.put(msg)

    async def _on_callback(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not update.callback_query:
            return
        query = update.callback_query
        await query.answer()

        sender = query.from_user
        msg = UnifiedMessage(
            id=str(query.id),
            channel="telegram",
            sender=Identity(
                id=str(sender.id),
                username=sender.username,
                display_name=sender.full_name,
            ),
            content=MessageContent(
                type=ContentType.CALLBACK,
                text=query.data or "",
                callback_data=query.data,
            ),
            chat_id=str(query.message.chat_id) if query.message else None,
            raw=update,
        )
        self._last_activity = datetime.now()
        await self._queue.put(msg)

    def _build_message(
        self, update: Update, content: MessageContent
    ) -> UnifiedMessage:
        tg_msg = update.message
        assert tg_msg is not None
        user = tg_msg.from_user
        assert user is not None

        self._last_activity = datetime.now()
        return UnifiedMessage(
            id=str(tg_msg.message_id),
            channel="telegram",
            sender=Identity(
                id=str(user.id),
                username=user.username,
                display_name=user.full_name,
            ),
            content=content,
            timestamp=tg_msg.date,
            chat_id=str(tg_msg.chat_id),
            thread_id=(
                str(tg_msg.message_thread_id) if tg_msg.message_thread_id else None
            ),
            reply_to_id=(
                str(tg_msg.reply_to_message.message_id)
                if tg_msg.reply_to_message
                else None
            ),
            raw=update,
        )
