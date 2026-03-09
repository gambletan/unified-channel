"""DingTalk (钉钉) adapter — bridges DingTalk Bot to UnifiedMessage.

Uses the DingTalk webhook API for sending and an aiohttp callback server for
receiving messages. Supports text, markdown, and action card message types.

Requires: pip install aiohttp requests
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.parse
from datetime import datetime
from typing import AsyncIterator

try:
    import aiohttp
    from aiohttp import web
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    web = None  # type: ignore[assignment]

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

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


class DingTalkAdapter(ChannelAdapter):
    """
    DingTalk (钉钉) channel adapter.

    Two operation modes:
    1. **Webhook bot** (outgoing only): uses a webhook URL + secret to send
       messages to a group chat.
    2. **Enterprise bot** (full duplex): uses app_key/app_secret for API auth
       and a callback server for receiving messages.

    Config (webhook mode):
        webhook_url: 群机器人 Webhook 地址
        secret: 加签密钥 (optional, for signed webhooks)

    Config (enterprise mode):
        app_key: 应用 AppKey
        app_secret: 应用 AppSecret
        port: callback server port (default 9002)
        path: callback URL path (default /dingtalk/callback)
    """

    channel_id = "dingtalk"

    def __init__(
        self,
        *,
        webhook_url: str = "",
        secret: str = "",
        app_key: str = "",
        app_secret: str = "",
        port: int = 9002,
        path: str = "/dingtalk/callback",
        command_prefix: str = "/",
    ) -> None:
        self._webhook_url = webhook_url
        self._secret = secret
        self._app_key = app_key
        self._app_secret = app_secret
        self._port = port
        self._path = path
        self._prefix = command_prefix

        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None  # type: ignore[assignment]
        self._access_token: str | None = None
        self._token_expires: float = 0

    def _sign_webhook(self, timestamp: str) -> str:
        """Generate HMAC-SHA256 signature for DingTalk webhook."""
        string_to_sign = f"{timestamp}\n{self._secret}"
        hmac_code = hmac.new(
            self._secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        return urllib.parse.quote_plus(base64.b64encode(hmac_code).decode("utf-8"))

    def _verify_callback_signature(
        self, timestamp: str, sign: str
    ) -> bool:
        """Verify the signature on an incoming DingTalk callback."""
        if not self._app_secret:
            return True  # No secret configured, skip verification

        string_to_sign = f"{timestamp}\n{self._app_secret}"
        expected = base64.b64encode(
            hmac.new(
                self._app_secret.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
        ).decode("utf-8")
        return hmac.compare_digest(expected, sign)

    def _refresh_access_token(self) -> str:
        """Fetch or refresh the DingTalk API access token (enterprise mode)."""
        if self._access_token and time.time() < self._token_expires:
            return self._access_token

        if requests is None:
            raise RuntimeError("requests required: pip install requests")

        url = "https://oapi.dingtalk.com/gettoken"
        resp = requests.get(
            url,
            params={"appkey": self._app_key, "appsecret": self._app_secret},
            timeout=10,
        )
        data = resp.json()
        if data.get("errcode", 0) != 0:
            raise RuntimeError(f"DingTalk token error: {data}")

        self._access_token = data["access_token"]
        self._token_expires = time.time() + data.get("expires_in", 7200) - 300
        return self._access_token  # type: ignore[return-value]

    async def connect(self) -> None:
        if self._app_key and self._app_secret:
            # Enterprise bot mode — start callback server
            if web is None:
                raise RuntimeError("aiohttp required: pip install aiohttp")

            app = web.Application()
            app.router.add_post(self._path, self._handle_callback)
            self._runner = web.AppRunner(app)
            await self._runner.setup()
            site = web.TCPSite(self._runner, "0.0.0.0", self._port)
            await site.start()
            logger.info(
                "dingtalk connected: callback on port %d%s (enterprise mode)",
                self._port,
                self._path,
            )
        elif self._webhook_url:
            logger.info("dingtalk connected: webhook mode (send only)")
        else:
            raise ValueError(
                "dingtalk: provide either webhook_url or app_key+app_secret"
            )

        self._connected = True

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("dingtalk disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if requests is None:
            raise RuntimeError("requests required: pip install requests")

        # Determine message format
        msg_type = msg.metadata.get("dingtalk_msg_type", "text")
        if msg.parse_mode and msg.parse_mode.lower() == "markdown":
            msg_type = "markdown"

        # Check for action card
        if msg.metadata.get("dingtalk_action_card"):
            msg_type = "actionCard"

        if self._webhook_url:
            return self._send_webhook(msg, msg_type)
        elif self._app_key:
            return await self._send_api(msg, msg_type)
        else:
            logger.error("dingtalk: no send method configured")
            return None

    def _send_webhook(self, msg: OutboundMessage, msg_type: str) -> str | None:
        """Send via webhook URL (group bot)."""
        url = self._webhook_url
        if self._secret:
            timestamp = str(int(time.time() * 1000))
            sign = self._sign_webhook(timestamp)
            url = f"{url}&timestamp={timestamp}&sign={sign}"

        if msg_type == "markdown":
            title = msg.metadata.get("title", "Message")
            payload = {
                "msgtype": "markdown",
                "markdown": {"title": title, "text": msg.text},
            }
        elif msg_type == "actionCard":
            card = msg.metadata.get("dingtalk_action_card", {})
            payload = {
                "msgtype": "actionCard",
                "actionCard": {
                    "title": card.get("title", ""),
                    "text": msg.text,
                    "btnOrientation": card.get("btn_orientation", "0"),
                    "btns": card.get("btns", []),
                },
            }
        else:
            at_mobiles = msg.metadata.get("at_mobiles", [])
            at_all = msg.metadata.get("at_all", False)
            payload = {
                "msgtype": "text",
                "text": {"content": msg.text},
                "at": {"atMobiles": at_mobiles, "isAtAll": at_all},
            }

        resp = requests.post(url, json=payload, timeout=10)
        data = resp.json()
        self._last_activity = datetime.now()

        if data.get("errcode", 0) != 0:
            logger.error("dingtalk webhook send failed: %s", data)
            return None
        return "ok"

    async def _send_api(self, msg: OutboundMessage, msg_type: str) -> str | None:
        """Send via DingTalk API (enterprise bot)."""
        access_token = self._refresh_access_token()
        url = (
            f"https://oapi.dingtalk.com/topapi/message/corpconversation/asyncsend_v2"
            f"?access_token={access_token}"
        )

        if msg_type == "markdown":
            title = msg.metadata.get("title", "Message")
            msg_body = {
                "msgtype": "markdown",
                "markdown": {"title": title, "text": msg.text},
            }
        elif msg_type == "actionCard":
            card = msg.metadata.get("dingtalk_action_card", {})
            msg_body = {
                "msgtype": "action_card",
                "action_card": {
                    "title": card.get("title", ""),
                    "markdown": msg.text,
                    "btn_orientation": card.get("btn_orientation", "0"),
                    "btn_json_list": card.get("btns", []),
                },
            }
        else:
            msg_body = {
                "msgtype": "text",
                "text": {"content": msg.text},
            }

        payload = {
            "agent_id": self._app_key,
            "userid_list": msg.chat_id,
            "msg": msg_body,
        }

        if requests is None:
            raise RuntimeError("requests required: pip install requests")

        resp = requests.post(url, json=payload, timeout=10)
        data = resp.json()
        self._last_activity = datetime.now()

        if data.get("errcode", 0) != 0:
            logger.error("dingtalk api send failed: %s", data)
            return None
        return str(data.get("task_id", ""))

    async def get_status(self) -> ChannelStatus:
        mode = "enterprise" if self._app_key else "webhook"
        account_id = self._app_key if self._app_key else (self._webhook_url[:40] if self._webhook_url else None)
        return ChannelStatus(
            connected=self._connected,
            channel="dingtalk",
            account_id=account_id,
            last_activity=self._last_activity,
        )

    # -- Callback handler --

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """Handle incoming DingTalk bot callback."""
        # Verify signature from headers
        timestamp = request.headers.get("timestamp", "")
        sign = request.headers.get("sign", "")

        if self._app_secret and timestamp and sign:
            if not self._verify_callback_signature(timestamp, sign):
                return web.Response(status=403, text="signature verification failed")

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.Response(status=400, text="invalid JSON")

        await self._process_message(body)
        return web.json_response({"errcode": 0, "errmsg": "ok"})

    async def _process_message(self, body: dict) -> None:
        """Parse a DingTalk callback message and push to queue."""
        msg_type = body.get("msgtype", "text")
        sender_id = body.get("senderStaffId", "") or body.get("senderId", "")
        sender_nick = body.get("senderNick", "")
        conversation_id = body.get("conversationId", "")
        msg_id = body.get("msgId", "")
        conversation_type = body.get("conversationType", "")
        create_time = body.get("createAt", 0)

        self._last_activity = datetime.now()

        if msg_type == "text":
            text_content = body.get("text", {})
            text = text_content.get("content", "").strip()

            if text.startswith(self._prefix):
                parts = text[len(self._prefix) :].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(
                    type=ContentType.COMMAND, text=text, command=cmd, args=args
                )
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)
        elif msg_type == "richText":
            # Rich text contains a list of segments
            rich_text = body.get("content", {}).get("richText", [])
            text_parts = []
            for segment in rich_text:
                if "text" in segment:
                    text_parts.append(segment["text"])
            text = "".join(text_parts)
            mc = MessageContent(type=ContentType.TEXT, text=text)
        elif msg_type == "picture":
            download_code = body.get("content", {}).get("downloadCode", "")
            mc = MessageContent(
                type=ContentType.MEDIA,
                text="",
                media_type="image",
                media_url=download_code,
            )
        elif msg_type == "video":
            mc = MessageContent(type=ContentType.MEDIA, text="", media_type="video")
        elif msg_type == "file":
            mc = MessageContent(type=ContentType.MEDIA, text="", media_type="file")
        else:
            mc = MessageContent(type=ContentType.TEXT, text=f"[{msg_type}]")

        try:
            ts = datetime.fromtimestamp(create_time / 1000) if create_time else datetime.now()
        except (ValueError, OSError):
            ts = datetime.now()

        # For 1:1 chats, chat_id is the sender; for group chats, it's the conversation
        chat_id = (
            sender_id
            if conversation_type == "1"
            else conversation_id
        )

        msg = UnifiedMessage(
            id=msg_id or str(int(time.time() * 1000)),
            channel="dingtalk",
            sender=Identity(
                id=sender_id,
                display_name=sender_nick,
            ),
            content=mc,
            timestamp=ts,
            chat_id=chat_id,
            raw=body,
        )
        await self._queue.put(msg)
