"""Nextcloud Talk adapter — REST polling.

Requires: pip install httpx
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncIterator

import httpx

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)


class NextcloudTalkAdapter(ChannelAdapter):
    """Nextcloud Talk adapter using polling + REST API."""

    channel_id = "nextcloud-talk"

    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
        *,
        room_tokens: list[str] | None = None,
        poll_interval: float = 3.0,
        command_prefix: str = "/",
    ) -> None:
        self._server = server_url.rstrip("/")
        self._username = username
        self._password = password
        self._rooms = room_tokens or []
        self._poll_interval = poll_interval
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._http: httpx.AsyncClient | None = None
        self._last_known: dict[str, int] = {}
        self._poll_task: asyncio.Task | None = None

    async def connect(self) -> None:
        self._http = httpx.AsyncClient(
            base_url=f"{self._server}/ocs/v2.php/apps/spreed/api/v1",
            auth=(self._username, self._password),
            headers={"OCS-APIRequest": "true", "Accept": "application/json"},
            timeout=30,
        )
        if not self._rooms:
            resp = await self._http.get("/room")
            if resp.status_code == 200:
                for r in resp.json().get("ocs", {}).get("data", []):
                    self._rooms.append(r["token"])

        self._connected = True
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info("nextcloud-talk connected: %d rooms", len(self._rooms))

    async def disconnect(self) -> None:
        self._connected = False
        if self._poll_task:
            self._poll_task.cancel()
        if self._http:
            await self._http.aclose()
        logger.info("nextcloud-talk disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._http:
            raise RuntimeError("nextcloud-talk not connected")
        resp = await self._http.post(
            f"/chat/{msg.chat_id}",
            json={"message": msg.text, "replyTo": msg.reply_to_id or 0},
        )
        self._last_activity = datetime.now()
        if resp.status_code == 201:
            return str(resp.json().get("ocs", {}).get("data", {}).get("id"))
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="nextcloud-talk",
                             account_id=self._username, last_activity=self._last_activity)

    async def _poll_loop(self) -> None:
        while self._connected:
            for token in self._rooms:
                try:
                    await self._poll_room(token)
                except Exception as e:
                    logger.error("nextcloud-talk poll error room=%s: %s", token, e)
            await asyncio.sleep(self._poll_interval)

    async def _poll_room(self, token: str) -> None:
        params = {"lookIntoFuture": 0, "limit": 20}
        last_id = self._last_known.get(token, 0)
        if last_id:
            params["lastKnownMessageId"] = last_id
            params["lookIntoFuture"] = 1

        resp = await self._http.get(f"/chat/{token}", params=params)
        if resp.status_code != 200:
            return

        messages = resp.json().get("ocs", {}).get("data", [])
        for m in messages:
            mid = m.get("id", 0)
            if mid <= last_id:
                continue
            self._last_known[token] = mid
            if m.get("actorId") == self._username:
                continue

            text = m.get("message", "")
            self._last_activity = datetime.now()

            if text.startswith(self._prefix):
                parts = text[len(self._prefix):].split()
                mc = MessageContent(type=ContentType.COMMAND, text=text,
                                    command=parts[0] if parts else "", args=parts[1:])
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)

            msg = UnifiedMessage(
                id=str(mid), channel="nextcloud-talk",
                sender=Identity(id=m.get("actorId", ""), display_name=m.get("actorDisplayName")),
                content=mc, chat_id=token, raw=m,
            )
            await self._queue.put(msg)
