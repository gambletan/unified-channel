"""Matrix adapter — bridges matrix-nio to UnifiedMessage.

Requires: pip install matrix-nio[e2e]
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

from nio import (
    AsyncClient,
    LoginResponse,
    RoomMessageText,
    RoomMessageImage,
    RoomMessageVideo,
    InviteMemberEvent,
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


class MatrixAdapter(ChannelAdapter):
    """
    Matrix channel adapter using matrix-nio.

    Supports E2E encryption if matrix-nio[e2e] is installed.
    """

    channel_id = "matrix"

    def __init__(
        self,
        homeserver: str,
        user_id: str,
        password: str | None = None,
        access_token: str | None = None,
        *,
        allowed_room_ids: set[str] | None = None,
        auto_join: bool = True,
        command_prefix: str = "/",
        device_name: str = "unified-channel",
    ) -> None:
        self._homeserver = homeserver
        self._user_id = user_id
        self._password = password
        self._access_token = access_token
        self._allowed_rooms = allowed_room_ids
        self._auto_join = auto_join
        self._prefix = command_prefix
        self._device_name = device_name
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._client: AsyncClient | None = None

    async def connect(self) -> None:
        self._client = AsyncClient(self._homeserver, self._user_id)

        if self._access_token:
            self._client.access_token = self._access_token
        elif self._password:
            resp = await self._client.login(self._password, device_name=self._device_name)
            if not isinstance(resp, LoginResponse):
                raise RuntimeError(f"matrix login failed: {resp}")
            logger.info("matrix logged in: %s", self._user_id)
        else:
            raise ValueError("matrix: either password or access_token required")

        # Register callbacks
        self._client.add_event_callback(self._on_message, RoomMessageText)
        self._client.add_event_callback(self._on_media, (RoomMessageImage, RoomMessageVideo))
        if self._auto_join:
            self._client.add_event_callback(self._on_invite, InviteMemberEvent)

        # Start sync in background
        self._connected = True
        asyncio.create_task(self._sync_loop())
        logger.info("matrix connected: %s @ %s", self._user_id, self._homeserver)

    async def _sync_loop(self) -> None:
        try:
            await self._client.sync_forever(timeout=30000, full_state=True)
        except Exception as e:
            logger.error("matrix sync error: %s", e)
            self._connected = False

    async def disconnect(self) -> None:
        if self._client:
            await self._client.close()
        self._connected = False
        logger.info("matrix disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._client:
            raise RuntimeError("matrix not connected")

        content = {"msgtype": "m.text", "body": msg.text}
        if msg.parse_mode == "html":
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = msg.text

        resp = await self._client.room_send(
            room_id=msg.chat_id,
            message_type="m.room.message",
            content=content,
        )
        self._last_activity = datetime.now()
        return getattr(resp, "event_id", None)

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="matrix",
            account_id=self._user_id,
            last_activity=self._last_activity,
        )

    async def _on_invite(self, room, event) -> None:
        if event.membership == "invite" and event.state_key == self._user_id:
            await self._client.join(room.room_id)
            logger.info("matrix: auto-joined %s", room.room_id)

    async def _on_message(self, room, event: RoomMessageText) -> None:
        # Skip own messages
        if event.sender == self._user_id:
            return
        if self._allowed_rooms and room.room_id not in self._allowed_rooms:
            return

        text = event.body
        self._last_activity = datetime.now()

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            cmd = parts[0] if parts else ""
            args = parts[1:]
            mc = MessageContent(type=ContentType.COMMAND, text=text, command=cmd, args=args)
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=event.event_id,
            channel="matrix",
            sender=Identity(
                id=event.sender,
                display_name=room.user_name(event.sender),
            ),
            content=mc,
            timestamp=datetime.fromtimestamp(event.server_timestamp / 1000),
            chat_id=room.room_id,
            raw=event,
        )
        await self._queue.put(msg)

    async def _on_media(self, room, event) -> None:
        if event.sender == self._user_id:
            return
        if self._allowed_rooms and room.room_id not in self._allowed_rooms:
            return

        self._last_activity = datetime.now()
        mtype = "image" if isinstance(event, RoomMessageImage) else "video"
        url = getattr(event, "url", None)

        mc = MessageContent(
            type=ContentType.MEDIA,
            text=getattr(event, "body", ""),
            media_url=url,
            media_type=mtype,
        )
        msg = UnifiedMessage(
            id=event.event_id,
            channel="matrix",
            sender=Identity(
                id=event.sender,
                display_name=room.user_name(event.sender),
            ),
            content=mc,
            timestamp=datetime.fromtimestamp(event.server_timestamp / 1000),
            chat_id=room.room_id,
            raw=event,
        )
        await self._queue.put(msg)
