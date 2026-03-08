"""WhatsApp adapter — bridges WhatsApp Business Cloud API to UnifiedMessage.

Requires: pip install httpx
Uses Meta's official Cloud API (webhook for receiving, REST for sending).

Setup:
  1. Create a Meta Business app at developers.facebook.com
  2. Add WhatsApp product
  3. Get a permanent access token and phone number ID
  4. Set webhook URL to your server + verify token
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import AsyncIterator

import httpx
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

GRAPH_API = "https://graph.facebook.com/v21.0"


class WhatsAppAdapter(ChannelAdapter):
    """
    WhatsApp Business Cloud API adapter.

    Uses webhook for inbound messages and REST API for outbound.
    """

    channel_id = "whatsapp"

    def __init__(
        self,
        access_token: str,
        phone_number_id: str,
        verify_token: str,
        *,
        app_secret: str = "",
        port: int = 8443,
        path: str = "/whatsapp/webhook",
        command_prefix: str = "/",
    ) -> None:
        self._access_token = access_token
        self._phone_number_id = phone_number_id
        self._verify_token = verify_token
        self._app_secret = app_secret
        self._port = port
        self._path = path
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None
        self._http: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        self._http = httpx.AsyncClient(
            base_url=GRAPH_API,
            headers={"Authorization": f"Bearer {self._access_token}"},
            timeout=30,
        )

        app = web.Application()
        app.router.add_get(self._path, self._handle_verify)
        app.router.add_post(self._path, self._handle_webhook)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()

        self._connected = True
        logger.info("whatsapp connected: phone=%s webhook port %d", self._phone_number_id, self._port)

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        if self._http:
            await self._http.aclose()
        self._connected = False
        logger.info("whatsapp disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        if not self._http:
            raise RuntimeError("whatsapp not connected")

        payload: dict = {
            "messaging_product": "whatsapp",
            "to": msg.chat_id,
            "type": "text",
            "text": {"body": msg.text},
        }

        if msg.reply_to_id:
            payload["context"] = {"message_id": msg.reply_to_id}

        resp = await self._http.post(
            f"/{self._phone_number_id}/messages",
            json=payload,
        )
        self._last_activity = datetime.now()

        if resp.status_code == 200:
            data = resp.json()
            messages = data.get("messages", [])
            return messages[0]["id"] if messages else None

        logger.error("whatsapp send failed: %d %s", resp.status_code, resp.text)
        return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="whatsapp",
            account_id=self._phone_number_id,
            last_activity=self._last_activity,
        )

    async def _handle_verify(self, request: web.Request) -> web.Response:
        """Webhook verification (GET request from Meta)."""
        mode = request.query.get("hub.mode")
        token = request.query.get("hub.verify_token")
        challenge = request.query.get("hub.challenge")

        if mode == "subscribe" and token == self._verify_token:
            logger.info("whatsapp webhook verified")
            return web.Response(text=challenge or "")
        return web.Response(status=403)

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        """Process incoming webhook events."""
        body_bytes = await request.read()

        # Verify signature if app_secret is set
        if self._app_secret:
            signature = request.headers.get("X-Hub-Signature-256", "")
            expected = "sha256=" + hmac.new(
                self._app_secret.encode(), body_bytes, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return web.Response(status=403)

        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError:
            return web.Response(status=400)

        # Process each entry/change
        for entry in body.get("entry", []):
            for change in entry.get("changes", []):
                if change.get("field") != "messages":
                    continue
                value = change.get("value", {})
                contacts = {c["wa_id"]: c.get("profile", {}).get("name")
                            for c in value.get("contacts", [])}
                for wa_msg in value.get("messages", []):
                    await self._process_message(wa_msg, contacts)

        return web.Response(text="OK")

    async def _process_message(self, wa_msg: dict, contacts: dict) -> None:
        msg_id = wa_msg.get("id", "")
        from_number = wa_msg.get("from", "")
        msg_type = wa_msg.get("type", "")
        timestamp = wa_msg.get("timestamp", "0")
        self._last_activity = datetime.now()

        display_name = contacts.get(from_number)

        if msg_type == "text":
            text = wa_msg.get("text", {}).get("body", "")
            if text.startswith(self._prefix):
                parts = text[len(self._prefix):].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(type=ContentType.COMMAND, text=text, command=cmd, args=args)
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)
        elif msg_type in ("image", "video", "audio", "document"):
            media = wa_msg.get(msg_type, {})
            mc = MessageContent(
                type=ContentType.MEDIA,
                text=media.get("caption", ""),
                media_type=msg_type,
                media_url=media.get("id"),  # media ID, needs download via API
            )
        elif msg_type == "reaction":
            mc = MessageContent(
                type=ContentType.REACTION,
                text=wa_msg.get("reaction", {}).get("emoji", ""),
            )
        else:
            return

        # Context (reply)
        context = wa_msg.get("context", {})
        reply_to = context.get("id")

        try:
            ts = datetime.fromtimestamp(int(timestamp))
        except (ValueError, OSError):
            ts = datetime.now()

        msg = UnifiedMessage(
            id=msg_id,
            channel="whatsapp",
            sender=Identity(id=from_number, display_name=display_name),
            content=mc,
            timestamp=ts,
            chat_id=from_number,
            reply_to_id=reply_to,
            raw=wa_msg,
        )
        await self._queue.put(msg)
