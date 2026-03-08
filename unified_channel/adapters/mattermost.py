"""Mattermost adapter — WebSocket + REST API.

Requires: pip install websockets httpx
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import AsyncIterator

import httpx
import websockets

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


class MattermostAdapter(ChannelAdapter):
    """Mattermost adapter using WebSocket for events and REST for sending."""

    channel_id = "mattermost"

    def __init__(
        self,
        url: str,
        token: str,
        *,
        allowed_channel_ids: set[str] | None = None,
        command_prefix: str = "/",
    ) -> None:
        self._url = url.rstrip("/")
        self._token = token
        self._allowed_channels = allowed_channel_ids
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._ws: websockets.WebSocketClientProtocol | None = None
        self._http: httpx.AsyncClient | None = None
        self._bot_user_id: str | None = None
        self._ws_task: asyncio.Task | None = None

    async def connect(self) -> None:
        self._http = httpx.AsyncClient(
            base_url=f"{self._url}/api/v4",
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=30,
        )
        me = await self._http.get("/users/me")
        me.raise_for_status()
        self._bot_user_id = me.json()["id"]

        ws_url = self._url.replace("http", "ws") + "/api/v4/websocket"
        self._ws = await websockets.connect(ws_url)
        await self._ws.send(json.dumps({
            "seq": 1, "action": "authentication_challenge",
            "data": {"token": self._token},
        }))

        self._connected = True
        self._ws_task = asyncio.create_task(self._listen())
        logger.info("mattermost connected: %s", self._bot_user_id)

    async def disconnect(self) -> None:
        self._connected = False
        if self._ws_task:
            self._ws_task.cancel()
        if self._ws:
            await self._ws.close()
        if self._http:
            await self._http.aclose()
        logger.info("mattermost disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._http:
            raise RuntimeError("mattermost not connected")
        payload: dict = {"channel_id": msg.chat_id, "message": msg.text}
        if msg.reply_to_id:
            payload["root_id"] = msg.reply_to_id
        resp = await self._http.post("/posts", json=payload)
        self._last_activity = datetime.now()
        if resp.status_code == 201:
            return resp.json().get("id")
        logger.error("mattermost send failed: %d", resp.status_code)
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected, channel="mattermost",
            account_id=self._bot_user_id, last_activity=self._last_activity,
        )

    async def _listen(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "posted":
                    await self._process_post(event)
        except (websockets.ConnectionClosed, asyncio.CancelledError):
            self._connected = False

    async def _process_post(self, event: dict) -> None:
        data = json.loads(event.get("data", {}).get("post", "{}"))
        if data.get("user_id") == self._bot_user_id:
            return
        channel_id = data.get("channel_id", "")
        if self._allowed_channels and channel_id not in self._allowed_channels:
            return

        text = data.get("message", "")
        self._last_activity = datetime.now()

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=data.get("id", ""), channel="mattermost",
            sender=Identity(id=data.get("user_id", "")),
            content=mc, chat_id=channel_id,
            thread_id=data.get("root_id"), reply_to_id=data.get("root_id"),
            raw=data,
        )
        await self._queue.put(msg)
