"""Nostr adapter — NIP-04 encrypted DMs via relay WebSocket.

Requires: pip install websockets secp256k1 cryptography
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import secrets
import time
from datetime import datetime
from typing import AsyncIterator

import websockets

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus, ContentType, Identity, MessageContent,
    OutboundMessage, UnifiedMessage,
)

logger = logging.getLogger(__name__)


def _compute_pubkey(privkey_hex: str) -> str:
    """Compute public key from private key using secp256k1."""
    from secp256k1 import PrivateKey
    pk = PrivateKey(bytes.fromhex(privkey_hex))
    return pk.pubkey.serialize(compressed=True).hex()[2:]  # x-only


def _nip04_decrypt(privkey_hex: str, pubkey_hex: str, ciphertext: str) -> str:
    """Decrypt NIP-04 encrypted message."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from secp256k1 import PrivateKey, PublicKey
    import base64

    if "?iv=" not in ciphertext:
        return ciphertext

    encrypted_b64, iv_b64 = ciphertext.split("?iv=")
    encrypted = base64.b64decode(encrypted_b64)
    iv = base64.b64decode(iv_b64)

    pk = PrivateKey(bytes.fromhex(privkey_hex))
    pub = PublicKey(bytes.fromhex("02" + pubkey_hex), raw=True)
    shared = pk.ecdh(pub.public_key)
    key = shared[:32]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    # Remove PKCS7 padding
    pad_len = padded[-1]
    return padded[:-pad_len].decode()


def _nip04_encrypt(privkey_hex: str, pubkey_hex: str, plaintext: str) -> str:
    """Encrypt message using NIP-04."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from secp256k1 import PrivateKey, PublicKey
    import base64

    pk = PrivateKey(bytes.fromhex(privkey_hex))
    pub = PublicKey(bytes.fromhex("02" + pubkey_hex), raw=True)
    shared = pk.ecdh(pub.public_key)
    key = shared[:32]

    iv = secrets.token_bytes(16)
    # PKCS7 padding
    pad_len = 16 - (len(plaintext.encode()) % 16)
    padded = plaintext.encode() + bytes([pad_len]) * pad_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(encrypted).decode() + "?iv=" + base64.b64encode(iv).decode()


class NostrAdapter(ChannelAdapter):
    """Nostr adapter for NIP-04 encrypted DMs."""

    channel_id = "nostr"

    def __init__(
        self,
        private_key_hex: str,
        relay_urls: list[str],
        *,
        command_prefix: str = "/",
    ) -> None:
        self._privkey = private_key_hex
        self._pubkey = _compute_pubkey(private_key_hex)
        self._relays = relay_urls
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._ws_connections: list[websockets.WebSocketClientProtocol] = []
        self._tasks: list[asyncio.Task] = []
        self._seen: set[str] = set()

    async def connect(self) -> None:
        for url in self._relays:
            try:
                ws = await websockets.connect(url)
                self._ws_connections.append(ws)
                # Subscribe to DMs (NIP-04, kind 4)
                sub_id = secrets.token_hex(8)
                await ws.send(json.dumps([
                    "REQ", sub_id,
                    {"kinds": [4], "#p": [self._pubkey], "since": int(time.time())},
                ]))
                task = asyncio.create_task(self._listen(ws, url))
                self._tasks.append(task)
                logger.info("nostr connected to relay: %s", url)
            except Exception as e:
                logger.warning("nostr relay connect failed %s: %s", url, e)

        self._connected = bool(self._ws_connections)
        if not self._connected:
            raise RuntimeError("nostr: failed to connect to any relay")
        logger.info("nostr connected: pubkey=%s...%s", self._pubkey[:8], self._pubkey[-4:])

    async def disconnect(self) -> None:
        self._connected = False
        for t in self._tasks:
            t.cancel()
        for ws in self._ws_connections:
            await ws.close()
        self._ws_connections.clear()
        logger.info("nostr disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        recipient_pubkey = msg.chat_id
        encrypted = _nip04_encrypt(self._privkey, recipient_pubkey, msg.text)

        event = {
            "kind": 4, "pubkey": self._pubkey,
            "created_at": int(time.time()),
            "tags": [["p", recipient_pubkey]],
            "content": encrypted,
        }
        event["id"] = self._compute_event_id(event)
        event["sig"] = self._sign_event(event["id"])

        for ws in self._ws_connections:
            try:
                await ws.send(json.dumps(["EVENT", event]))
            except Exception:
                continue

        self._last_activity = datetime.now()
        return event["id"]

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected, channel="nostr",
            account_id=self._pubkey[:16] + "...",
            last_activity=self._last_activity,
        )

    async def _listen(self, ws, relay_url: str) -> None:
        try:
            async for raw in ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if data[0] == "EVENT" and len(data) >= 3:
                    await self._process_event(data[2])
        except (websockets.ConnectionClosed, asyncio.CancelledError):
            pass

    async def _process_event(self, event: dict) -> None:
        event_id = event.get("id", "")
        if event_id in self._seen:
            return
        self._seen.add(event_id)

        sender_pubkey = event.get("pubkey", "")
        if sender_pubkey == self._pubkey:
            return

        try:
            text = _nip04_decrypt(self._privkey, sender_pubkey, event.get("content", ""))
        except Exception as e:
            logger.warning("nostr decrypt failed: %s", e)
            return

        self._last_activity = datetime.now()

        if text.startswith(self._prefix):
            parts = text[len(self._prefix):].split()
            mc = MessageContent(type=ContentType.COMMAND, text=text,
                                command=parts[0] if parts else "", args=parts[1:])
        else:
            mc = MessageContent(type=ContentType.TEXT, text=text)

        msg = UnifiedMessage(
            id=event_id, channel="nostr",
            sender=Identity(id=sender_pubkey),
            content=mc,
            timestamp=datetime.fromtimestamp(event.get("created_at", 0)),
            chat_id=sender_pubkey, raw=event,
        )
        await self._queue.put(msg)

    def _compute_event_id(self, event: dict) -> str:
        serialized = json.dumps([
            0, event["pubkey"], event["created_at"],
            event["kind"], event["tags"], event["content"],
        ], separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def _sign_event(self, event_id: str) -> str:
        from secp256k1 import PrivateKey
        pk = PrivateKey(bytes.fromhex(self._privkey))
        sig = pk.schnorr_sign(bytes.fromhex(event_id), bip340tag=None, raw=True)
        return sig.hex()
