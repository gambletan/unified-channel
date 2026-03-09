"""WeChat Work (企业微信/WeCom) adapter — bridges WeCom Bot to UnifiedMessage.

Uses the WeCom webhook API for sending and an aiohttp callback server for
receiving messages. Supports text and markdown message types.

Requires: pip install aiohttp pycryptodome
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import socket
import struct
import time
import xml.etree.ElementTree as ET
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

try:
    from Crypto.Cipher import AES
except ImportError:
    AES = None  # type: ignore[assignment]

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

# PKCS#7 padding helpers
_BLOCK_SIZE = 32


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = _BLOCK_SIZE - (len(data) % _BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > _BLOCK_SIZE:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


class WeChatCrypto:
    """WeCom message encryption/decryption using AES-CBC with PKCS#7 padding.

    Implements the official WeCom callback encryption scheme:
    https://developer.work.weixin.qq.com/document/path/90968
    """

    def __init__(self, token: str, encoding_aes_key: str, corp_id: str) -> None:
        self._token = token
        self._corp_id = corp_id
        # EncodingAESKey is base64-encoded, 43 chars -> 32 bytes
        self._aes_key = base64.b64decode(encoding_aes_key + "=")

    def verify_signature(
        self, msg_signature: str, timestamp: str, nonce: str, echostr: str
    ) -> bool:
        """Verify the callback URL signature from WeCom."""
        items = sorted([self._token, timestamp, nonce, echostr])
        sha1 = hashlib.sha1("".join(items).encode()).hexdigest()
        return sha1 == msg_signature

    def decrypt(self, encrypted: str) -> str:
        """Decrypt an AES-CBC encrypted message from WeCom."""
        if AES is None:
            raise RuntimeError("pycryptodome required: pip install pycryptodome")
        cipher = AES.new(self._aes_key, AES.MODE_CBC, self._aes_key[:16])
        plain = _pkcs7_unpad(cipher.decrypt(base64.b64decode(encrypted)))
        # Format: 16 random bytes | 4-byte msg length (network order) | msg | corp_id
        msg_len = struct.unpack("!I", plain[16:20])[0]
        msg = plain[20 : 20 + msg_len].decode("utf-8")
        from_corp_id = plain[20 + msg_len :].decode("utf-8")
        if from_corp_id != self._corp_id:
            raise ValueError(
                f"corp_id mismatch: expected {self._corp_id}, got {from_corp_id}"
            )
        return msg

    def encrypt(self, reply_msg: str) -> str:
        """Encrypt a reply message for WeCom."""
        if AES is None:
            raise RuntimeError("pycryptodome required: pip install pycryptodome")
        random_bytes = hashlib.md5(str(time.time()).encode()).digest()
        msg_bytes = reply_msg.encode("utf-8")
        corp_bytes = self._corp_id.encode("utf-8")
        body = (
            random_bytes
            + struct.pack("!I", len(msg_bytes))
            + msg_bytes
            + corp_bytes
        )
        padded = _pkcs7_pad(body)
        cipher = AES.new(self._aes_key, AES.MODE_CBC, self._aes_key[:16])
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode("utf-8")

    def generate_signature(
        self, encrypted: str, timestamp: str, nonce: str
    ) -> str:
        """Generate signature for an encrypted reply."""
        items = sorted([self._token, timestamp, nonce, encrypted])
        return hashlib.sha1("".join(items).encode()).hexdigest()


class WeChatAdapter(ChannelAdapter):
    """
    WeChat Work (企业微信) channel adapter.

    Uses the WeCom API for enterprise bots:
    - Webhook URL for sending messages
    - Callback server (aiohttp) for receiving messages
    - AES encryption/decryption for callback security

    Config:
        corp_id: 企业ID
        corp_secret: 应用Secret
        agent_id: 应用AgentId
        token: 回调Token (for callback URL verification)
        encoding_aes_key: 回调EncodingAESKey (for message encryption)
        port: callback server port (default 9001)
        path: callback URL path (default /wechat/callback)
    """

    channel_id = "wechat"

    def __init__(
        self,
        corp_id: str,
        corp_secret: str,
        agent_id: str,
        *,
        token: str = "",
        encoding_aes_key: str = "",
        port: int = 9001,
        path: str = "/wechat/callback",
        command_prefix: str = "/",
    ) -> None:
        self._corp_id = corp_id
        self._corp_secret = corp_secret
        self._agent_id = agent_id
        self._token = token
        self._encoding_aes_key = encoding_aes_key
        self._port = port
        self._path = path
        self._prefix = command_prefix

        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._runner: web.AppRunner | None = None  # type: ignore[assignment]
        self._access_token: str | None = None
        self._token_expires: float = 0

        self._crypto: WeChatCrypto | None = None
        if token and encoding_aes_key:
            self._crypto = WeChatCrypto(token, encoding_aes_key, corp_id)

    def _refresh_access_token(self) -> str:
        """Fetch or refresh the WeCom API access token."""
        if self._access_token and time.time() < self._token_expires:
            return self._access_token

        if requests is None:
            raise RuntimeError("requests required: pip install requests")

        url = (
            f"https://qyapi.weixin.qq.com/cgi-bin/gettoken"
            f"?corpid={self._corp_id}&corpsecret={self._corp_secret}"
        )
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if data.get("errcode", 0) != 0:
            raise RuntimeError(f"WeCom token error: {data}")

        self._access_token = data["access_token"]
        # Expire 5 minutes early to avoid race conditions
        self._token_expires = time.time() + data.get("expires_in", 7200) - 300
        return self._access_token  # type: ignore[return-value]

    async def connect(self) -> None:
        if web is None:
            raise RuntimeError("aiohttp required: pip install aiohttp")

        app = web.Application()
        app.router.add_get(self._path, self._handle_verify)
        app.router.add_post(self._path, self._handle_callback)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self._port)
        await site.start()
        self._connected = True
        logger.info(
            "wechat connected: callback on port %d%s (corp=%s agent=%s)",
            self._port,
            self._path,
            self._corp_id,
            self._agent_id,
        )

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("wechat disconnected")

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

        access_token = self._refresh_access_token()
        url = (
            f"https://qyapi.weixin.qq.com/cgi-bin/message/send"
            f"?access_token={access_token}"
        )

        # Determine message type from parse_mode
        msg_type = "text"
        if msg.parse_mode and msg.parse_mode.lower() == "markdown":
            msg_type = "markdown"

        if msg_type == "markdown":
            payload = {
                "touser": msg.chat_id,
                "msgtype": "markdown",
                "agentid": int(self._agent_id),
                "markdown": {"content": msg.text},
            }
        else:
            payload = {
                "touser": msg.chat_id,
                "msgtype": "text",
                "agentid": int(self._agent_id),
                "text": {"content": msg.text},
            }

        resp = requests.post(url, json=payload, timeout=10)
        data = resp.json()
        self._last_activity = datetime.now()

        if data.get("errcode", 0) != 0:
            logger.error("wechat send failed: %s", data)
            return None

        return data.get("msgid", "")

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="wechat",
            account_id=f"{self._corp_id}/{self._agent_id}",
            last_activity=self._last_activity,
        )

    # -- Callback handlers --

    async def _handle_verify(self, request: web.Request) -> web.Response:
        """Handle WeCom callback URL verification (GET request)."""
        msg_signature = request.query.get("msg_signature", "")
        timestamp = request.query.get("timestamp", "")
        nonce = request.query.get("nonce", "")
        echostr = request.query.get("echostr", "")

        if not self._crypto:
            return web.Response(status=403, text="encryption not configured")

        if not self._crypto.verify_signature(msg_signature, timestamp, nonce, echostr):
            return web.Response(status=403, text="signature verification failed")

        # Decrypt echostr and return plaintext
        try:
            plaintext = self._crypto.decrypt(echostr)
            return web.Response(text=plaintext)
        except Exception as e:
            logger.error("wechat verify decrypt failed: %s", e)
            return web.Response(status=500, text="decrypt failed")

    async def _handle_callback(self, request: web.Request) -> web.Response:
        """Handle incoming WeCom message callback (POST request)."""
        msg_signature = request.query.get("msg_signature", "")
        timestamp = request.query.get("timestamp", "")
        nonce = request.query.get("nonce", "")

        body = await request.text()

        try:
            xml_tree = ET.fromstring(body)
        except ET.ParseError:
            return web.Response(status=400, text="invalid XML")

        encrypt_elem = xml_tree.find("Encrypt")
        if encrypt_elem is None or encrypt_elem.text is None:
            return web.Response(status=400, text="missing Encrypt element")

        encrypted = encrypt_elem.text

        # Verify signature
        if self._crypto:
            if not self._crypto.verify_signature(
                msg_signature, timestamp, nonce, encrypted
            ):
                return web.Response(status=403, text="signature failed")

            try:
                xml_content = self._crypto.decrypt(encrypted)
            except Exception as e:
                logger.error("wechat decrypt failed: %s", e)
                return web.Response(status=500, text="decrypt failed")
        else:
            # No encryption configured, try plain text
            xml_content = body

        await self._process_message(xml_content)
        return web.Response(text="success")

    async def _process_message(self, xml_content: str) -> None:
        """Parse a decrypted WeCom XML message and push to queue."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            logger.error("wechat: invalid XML in decrypted message")
            return

        msg_type = root.findtext("MsgType", "")
        from_user = root.findtext("FromUserName", "")
        to_user = root.findtext("ToUserName", "")
        msg_id = root.findtext("MsgId", "")
        create_time = root.findtext("CreateTime", "0")
        agent_id = root.findtext("AgentID", "")

        self._last_activity = datetime.now()

        if msg_type == "text":
            text = root.findtext("Content", "")
            if text.startswith(self._prefix):
                parts = text[len(self._prefix) :].split()
                cmd = parts[0] if parts else ""
                args = parts[1:]
                mc = MessageContent(
                    type=ContentType.COMMAND, text=text, command=cmd, args=args
                )
            else:
                mc = MessageContent(type=ContentType.TEXT, text=text)
        elif msg_type == "image":
            mc = MessageContent(
                type=ContentType.MEDIA,
                text="",
                media_type="image",
                media_url=root.findtext("PicUrl", ""),
            )
        elif msg_type == "voice":
            mc = MessageContent(
                type=ContentType.MEDIA,
                text="",
                media_type="voice",
            )
        elif msg_type == "video":
            mc = MessageContent(
                type=ContentType.MEDIA,
                text="",
                media_type="video",
            )
        elif msg_type == "event":
            # WeCom events (subscribe, enter_agent, etc.) — skip for now
            return
        else:
            mc = MessageContent(type=ContentType.TEXT, text=f"[{msg_type}]")

        try:
            ts = datetime.fromtimestamp(int(create_time))
        except (ValueError, OSError):
            ts = datetime.now()

        msg = UnifiedMessage(
            id=msg_id or str(int(time.time() * 1000)),
            channel="wechat",
            sender=Identity(id=from_user),
            content=mc,
            timestamp=ts,
            chat_id=from_user,  # In WeCom, reply target is the sender's userid
            raw={"xml": xml_content, "agent_id": agent_id},
        )
        await self._queue.put(msg)
