"""QQ Bot (QQ 官方机器人) adapter — bridges QQ Bot API to UnifiedMessage.

Uses the official QQ Bot API:
- WebSocket for receiving events (gateway connection)
- REST API for sending messages

Requires: pip install aiohttp
Reference: https://bot.q.qq.com/wiki/develop/api/
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import AsyncIterator

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

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

QQ_API_BASE = "https://api.sgroup.qq.com"
QQ_SANDBOX_API_BASE = "https://sandbox.api.sgroup.qq.com"


class QQAdapter(ChannelAdapter):
    """
    QQ Bot (QQ 官方机器人) channel adapter.

    Uses the official QQ Bot Platform API:
    - WebSocket gateway for receiving messages/events
    - REST API for sending messages
    - Supports both guild (频道) and group (群) messages

    Config:
        app_id: QQ Bot AppID
        token: QQ Bot Token
        secret: QQ Bot AppSecret (for signature verification)
        sandbox: use sandbox API (default False)
        intents: gateway intents bitmask (default: guilds + guild messages + direct messages)
    """

    channel_id = "qq"

    # Default intents: GUILDS (1<<0) | GUILD_MEMBERS (1<<1) | GUILD_MESSAGES (1<<9) |
    #                  DIRECT_MESSAGE (1<<12) | GROUP_AND_C2C_EVENT (1<<25)
    DEFAULT_INTENTS = (1 << 0) | (1 << 1) | (1 << 9) | (1 << 12) | (1 << 25)

    def __init__(
        self,
        app_id: str,
        token: str,
        *,
        secret: str = "",
        sandbox: bool = False,
        intents: int | None = None,
        command_prefix: str = "/",
    ) -> None:
        self._app_id = app_id
        self._token = token
        self._secret = secret
        self._sandbox = sandbox
        self._intents = intents if intents is not None else self.DEFAULT_INTENTS
        self._prefix = command_prefix
        self._api_base = QQ_SANDBOX_API_BASE if sandbox else QQ_API_BASE

        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._session: aiohttp.ClientSession | None = None  # type: ignore[assignment]
        self._ws: aiohttp.ClientWebSocketResponse | None = None  # type: ignore[assignment]
        self._ws_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._heartbeat_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._session_id: str | None = None
        self._sequence: int | None = None
        self._bot_id: str | None = None
        self._bot_username: str | None = None

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bot {self._app_id}.{self._token}",
            "Content-Type": "application/json",
        }

    async def connect(self) -> None:
        if aiohttp is None:
            raise RuntimeError("aiohttp required: pip install aiohttp")

        self._session = aiohttp.ClientSession()

        # Get WebSocket gateway URL
        gateway_url = await self._get_gateway()
        logger.info("qq: connecting to gateway %s", gateway_url)

        self._ws = await self._session.ws_connect(gateway_url)

        # Wait for Hello (opcode 10)
        hello = await self._ws.receive_json()
        if hello.get("op") != 10:
            raise RuntimeError(f"qq: expected Hello (op=10), got: {hello}")

        heartbeat_interval = hello["d"]["heartbeat_interval"]

        # Send Identify (opcode 2)
        identify = {
            "op": 2,
            "d": {
                "token": f"Bot {self._app_id}.{self._token}",
                "intents": self._intents,
            },
        }
        await self._ws.send_json(identify)

        # Wait for Ready (opcode 0, type READY)
        ready = await self._ws.receive_json()
        if ready.get("op") == 0 and ready.get("t") == "READY":
            ready_data = ready.get("d", {})
            self._session_id = ready_data.get("session_id")
            user = ready_data.get("user", {})
            self._bot_id = user.get("id")
            self._bot_username = user.get("username")
            self._sequence = ready.get("s")
        else:
            raise RuntimeError(f"qq: expected Ready event, got: {ready}")

        self._connected = True

        # Start heartbeat and message loops
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(heartbeat_interval / 1000)
        )
        self._ws_task = asyncio.create_task(self._ws_loop())

        logger.info(
            "qq connected: bot=%s (id=%s), session=%s",
            self._bot_username,
            self._bot_id,
            self._session_id,
        )

    async def disconnect(self) -> None:
        self._connected = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self._ws_task:
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass

        if self._ws and not self._ws.closed:
            await self._ws.close()

        if self._session and not self._session.closed:
            await self._session.close()

        logger.info("qq disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._session:
            raise RuntimeError("qq not connected")

        # Determine endpoint based on chat_id format
        # Guild channel: /channels/{channel_id}/messages
        # DM: /dms/{guild_id}/messages
        # Group: /v2/groups/{group_openid}/messages
        chat_id = msg.chat_id
        reply_ref = None

        if msg.reply_to_id:
            reply_ref = {
                "message_id": msg.reply_to_id,
                "ignore_get_message_error": True,
            }

        if chat_id.startswith("group:"):
            # Group message
            group_openid = chat_id[6:]
            url = f"{self._api_base}/v2/groups/{group_openid}/messages"
            payload: dict = {
                "content": msg.text,
                "msg_type": 0,  # text
            }
            if reply_ref:
                payload["msg_id"] = msg.reply_to_id
        elif chat_id.startswith("dm:"):
            # Direct message
            guild_id = chat_id[3:]
            url = f"{self._api_base}/dms/{guild_id}/messages"
            payload = {"content": msg.text}
            if reply_ref:
                payload["msg_id"] = msg.reply_to_id
                payload["message_reference"] = reply_ref
        else:
            # Guild channel message
            url = f"{self._api_base}/channels/{chat_id}/messages"
            payload = {"content": msg.text}
            if reply_ref:
                payload["msg_id"] = msg.reply_to_id
                payload["message_reference"] = reply_ref

        # Add markdown if specified
        if msg.parse_mode and msg.parse_mode.lower() == "markdown":
            payload["content"] = msg.text  # QQ supports a subset of markdown inline

        try:
            async with self._session.post(
                url, headers=self._headers, json=payload
            ) as resp:
                data = await resp.json()
                self._last_activity = datetime.now()
                if resp.status in (200, 201):
                    return data.get("id")
                logger.error("qq send failed (%d): %s", resp.status, data)
                return None
        except Exception as e:
            logger.error("qq send error: %s", e)
            return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="qq",
            account_id=self._bot_username or self._app_id,
            last_activity=self._last_activity,
        )

    # -- Internal methods --

    async def _get_gateway(self) -> str:
        """Fetch the WebSocket gateway URL from the QQ Bot API."""
        if not self._session:
            raise RuntimeError("session not initialized")

        async with self._session.get(
            f"{self._api_base}/gateway", headers=self._headers
        ) as resp:
            data = await resp.json()
            if resp.status != 200:
                raise RuntimeError(f"qq: failed to get gateway: {data}")
            return data["url"]

    async def _heartbeat_loop(self, interval: float) -> None:
        """Send periodic heartbeats to keep the WebSocket alive."""
        try:
            while self._connected and self._ws and not self._ws.closed:
                await self._ws.send_json({"op": 1, "d": self._sequence})
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("qq heartbeat error: %s", e)

    async def _ws_loop(self) -> None:
        """Read messages from the WebSocket and dispatch events."""
        try:
            while self._connected and self._ws and not self._ws.closed:
                ws_msg = await self._ws.receive()
                if ws_msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(ws_msg.data)
                    await self._dispatch(data)
                elif ws_msg.type in (
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                ):
                    logger.warning("qq: WebSocket closed/error")
                    self._connected = False
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("qq ws_loop error: %s", e)
            self._connected = False

    async def _dispatch(self, payload: dict) -> None:
        """Dispatch a gateway event."""
        op = payload.get("op")
        seq = payload.get("s")
        event_type = payload.get("t")
        data = payload.get("d", {})

        if seq is not None:
            self._sequence = seq

        if op == 11:
            # Heartbeat ACK
            return

        if op == 0:
            # Dispatch event
            if event_type in (
                "MESSAGE_CREATE",
                "AT_MESSAGE_CREATE",
                "DIRECT_MESSAGE_CREATE",
            ):
                await self._process_guild_message(data, event_type)
            elif event_type == "GROUP_AT_MESSAGE_CREATE":
                await self._process_group_message(data)
            elif event_type == "C2C_MESSAGE_CREATE":
                await self._process_c2c_message(data)

    async def _process_guild_message(self, data: dict, event_type: str) -> None:
        """Process a guild channel or DM message."""
        msg_id = data.get("id", "")
        content = data.get("content", "").strip()
        author = data.get("author", {})
        author_id = author.get("id", "")
        author_username = author.get("username", "")
        channel_id = data.get("channel_id", "")
        guild_id = data.get("guild_id", "")
        timestamp_str = data.get("timestamp", "")

        # Skip bot's own messages
        if author.get("bot", False) and author_id == self._bot_id:
            return

        self._last_activity = datetime.now()

        # Remove @mention prefix (QQ bot messages start with <@!bot_id>)
        if self._bot_id and content.startswith(f"<@!{self._bot_id}>"):
            content = content[len(f"<@!{self._bot_id}>") :].strip()

        # Parse content
        mc = self._parse_content(content, data)

        # For DMs, prefix chat_id with "dm:"
        if event_type == "DIRECT_MESSAGE_CREATE":
            chat_id = f"dm:{guild_id}"
        else:
            chat_id = channel_id

        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")) if timestamp_str else datetime.now()
        except (ValueError, OSError):
            ts = datetime.now()

        msg = UnifiedMessage(
            id=msg_id,
            channel="qq",
            sender=Identity(
                id=author_id,
                username=author_username,
                display_name=author.get("username", ""),
            ),
            content=mc,
            timestamp=ts,
            chat_id=chat_id,
            reply_to_id=data.get("message_reference", {}).get("message_id"),
            raw=data,
        )
        await self._queue.put(msg)

    async def _process_group_message(self, data: dict) -> None:
        """Process a group message (@bot in QQ group)."""
        msg_id = data.get("id", "")
        content = data.get("content", "").strip()
        author = data.get("author", {})
        member_openid = author.get("member_openid", "")
        group_openid = data.get("group_openid", "")
        timestamp_str = data.get("timestamp", "")

        self._last_activity = datetime.now()

        mc = self._parse_content(content, data)

        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")) if timestamp_str else datetime.now()
        except (ValueError, OSError):
            ts = datetime.now()

        msg = UnifiedMessage(
            id=msg_id,
            channel="qq",
            sender=Identity(id=member_openid),
            content=mc,
            timestamp=ts,
            chat_id=f"group:{group_openid}",
            raw=data,
        )
        await self._queue.put(msg)

    async def _process_c2c_message(self, data: dict) -> None:
        """Process a C2C (user-to-bot) direct message."""
        msg_id = data.get("id", "")
        content = data.get("content", "").strip()
        author = data.get("author", {})
        user_openid = author.get("user_openid", "")
        timestamp_str = data.get("timestamp", "")

        self._last_activity = datetime.now()

        mc = self._parse_content(content, data)

        try:
            ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")) if timestamp_str else datetime.now()
        except (ValueError, OSError):
            ts = datetime.now()

        msg = UnifiedMessage(
            id=msg_id,
            channel="qq",
            sender=Identity(id=user_openid),
            content=mc,
            timestamp=ts,
            chat_id=user_openid,
            raw=data,
        )
        await self._queue.put(msg)

    def _parse_content(self, text: str, data: dict) -> MessageContent:
        """Parse message text into MessageContent, detecting commands and media."""
        # Check for attachments
        attachments = data.get("attachments", [])
        if attachments:
            attachment = attachments[0]
            return MessageContent(
                type=ContentType.MEDIA,
                text=text,
                media_type=attachment.get("content_type", "unknown"),
                media_url=attachment.get("url", ""),
            )

        # Check for commands
        if text.startswith(self._prefix):
            parts = text[len(self._prefix) :].split()
            cmd = parts[0] if parts else ""
            args = parts[1:]
            return MessageContent(
                type=ContentType.COMMAND, text=text, command=cmd, args=args
            )

        return MessageContent(type=ContentType.TEXT, text=text)
