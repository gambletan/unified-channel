"""WebChat adapter — anonymous WebSocket-based chat for customer service.

Users connect via WebSocket without any registration. Each connection
gets a unique session ID. Supports text and media (base64 images/videos).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, AsyncIterator

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


class WebChatAdapter(ChannelAdapter):
    """
    WebSocket-based anonymous chat adapter.

    Each browser tab gets a unique session_id. Messages are routed
    by session_id (used as chat_id in UnifiedMessage).

    Supports two user types:
    - Anonymous: no auth, auto-assigned session ID
    - Authenticated: pass ?token=xxx or ?user_id=xxx&name=xxx in WS URL

    Wire protocol (JSON over WebSocket):

    Client → Server (first message, optional):
        {"type": "auth", "user_id": "C10086", "name": "张三", "phone": "138xxx", "extra": {...}}

    Client → Server:
        {"type": "text", "text": "hello"}
        {"type": "media", "media_type": "image", "data": "<base64>", "text": "caption"}

    Server → Client:
        {"type": "text", "text": "reply from agent"}
        {"type": "media", "media_type": "image", "url": "https://...", "text": "caption"}
        {"type": "system", "text": "connected", "session_id": "abc-123", "user_type": "authenticated|anonymous"}
    """

    channel_id = "webchat"

    def __init__(
        self,
        *,
        host: str = "0.0.0.0",
        port: int = 8081,
        path: str = "/ws",
        cors_origins: list[str] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._path = path
        self._cors_origins = cors_origins or ["*"]
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._sessions: dict[str, web.WebSocketResponse] = {}  # session_id → ws
        self._user_info: dict[str, dict[str, Any]] = {}  # session_id → user info
        self._extra_routes: list[tuple[str, str, Any]] = []
        self._connected = False
        self._last_activity: datetime | None = None

    @property
    def active_sessions(self) -> int:
        return len(self._sessions)

    def get_user_info(self, session_id: str) -> dict[str, Any] | None:
        """Get user info for a session. Returns None for unknown sessions."""
        return self._user_info.get(session_id)

    def add_route(self, method: str, path: str, handler) -> None:
        """Register extra routes before connect(). Also works if app is already created but not yet started."""
        self._extra_routes.append((method, path, handler))
        if self._app:
            self._app.router.add_route(method, path, handler)

    async def connect(self) -> None:
        self._app = web.Application()
        self._app.router.add_get(self._path, self._ws_handler)
        self._app.router.add_get("/health", self._health_handler)
        for method, path, handler in self._extra_routes:
            self._app.router.add_route(method, path, handler)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()
        self._connected = True
        logger.info("webchat listening on %s:%d%s", self._host, self._port, self._path)

    async def disconnect(self) -> None:
        # Close all WebSocket connections
        for sid, ws in list(self._sessions.items()):
            await ws.close()
        self._sessions.clear()

        if self._runner:
            await self._runner.cleanup()
        self._connected = False
        logger.info("webchat disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        """Send a message back to the user's WebSocket by session_id (chat_id)."""
        session_id = msg.chat_id
        ws = self._sessions.get(session_id)
        if not ws or ws.closed:
            logger.warning("webchat session %s not found or closed", session_id)
            return None

        payload: dict[str, Any] = {}
        if msg.media_url:
            payload = {
                "type": "media",
                "media_type": msg.media_type or "image",
                "url": msg.media_url,
                "text": msg.text or "",
            }
        else:
            payload = {
                "type": "text",
                "text": msg.text,
            }

        msg_id = uuid.uuid4().hex[:8]
        payload["id"] = msg_id
        payload["timestamp"] = datetime.now().isoformat()

        await ws.send_json(payload)
        self._last_activity = datetime.now()
        return msg_id

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="webchat",
            account_id=f"{self._host}:{self._port}",
            last_activity=self._last_activity,
        )

    # -- WebSocket handler --

    async def _ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(
            heartbeat=30.0,
            autoping=True,
        )
        await ws.prepare(request)

        # --- Resolve user identity ---
        # Priority: URL params > auth message (handled later)
        query = request.query
        url_user_id = query.get("user_id")
        url_name = query.get("name")
        url_phone = query.get("phone")

        # Allow session resumption via ?session_id=xxx (e.g. from localStorage)
        url_session_id = query.get("session_id")

        if url_user_id:
            # Authenticated user — use their user_id as session key
            session_id = f"u_{url_user_id}"
            user_info: dict[str, Any] = {
                "user_type": "authenticated",
                "user_id": url_user_id,
                "name": url_name or url_user_id,
                "phone": url_phone,
            }
        elif url_session_id:
            # Returning anonymous visitor — reuse previous session
            session_id = url_session_id
            prev_info = self._user_info.get(session_id)
            user_info = prev_info or {
                "user_type": "anonymous",
                "user_id": None,
                "name": None,
                "phone": None,
            }
        else:
            # New anonymous visitor
            session_id = uuid.uuid4().hex[:12]
            user_info = {
                "user_type": "anonymous",
                "user_id": None,
                "name": None,
                "phone": None,
            }

        self._sessions[session_id] = ws
        self._user_info[session_id] = user_info
        logger.info(
            "webchat new session: %s type=%s (total: %d)",
            session_id, user_info["user_type"], len(self._sessions),
        )

        # Send session info to client
        await ws.send_json({
            "type": "system",
            "text": "connected",
            "session_id": session_id,
            "user_type": user_info["user_type"],
        })

        try:
            async for ws_msg in ws:
                if ws_msg.type in (web.WSMsgType.TEXT,):
                    try:
                        data = json.loads(ws_msg.data)

                        # Handle auth message (upgrade anonymous → authenticated)
                        if data.get("type") == "auth":
                            user_info.update({
                                "user_type": "authenticated",
                                "user_id": data.get("user_id"),
                                "name": data.get("name"),
                                "phone": data.get("phone"),
                                "extra": data.get("extra", {}),
                            })
                            self._user_info[session_id] = user_info
                            await ws.send_json({
                                "type": "system",
                                "text": "authenticated",
                                "user_type": "authenticated",
                            })
                            logger.info("webchat session %s upgraded to authenticated: %s", session_id, data.get("user_id"))
                            continue

                        unified = self._parse_message(session_id, data)
                        if unified:
                            await self._queue.put(unified)
                            self._last_activity = datetime.now()
                    except json.JSONDecodeError:
                        logger.debug("webchat invalid JSON from %s", session_id)
                elif ws_msg.type == web.WSMsgType.ERROR:
                    logger.warning(
                        "webchat ws error session=%s: %s",
                        session_id,
                        ws.exception(),
                    )
        finally:
            self._sessions.pop(session_id, None)
            self._user_info.pop(session_id, None)
            logger.info("webchat session closed: %s (remaining: %d)", session_id, len(self._sessions))

        return ws

    async def _health_handler(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "sessions": len(self._sessions),
        })

    def _parse_message(self, session_id: str, data: dict) -> UnifiedMessage | None:
        msg_type = data.get("type", "text")
        text = data.get("text", "")

        if msg_type == "media":
            content = MessageContent(
                type=ContentType.MEDIA,
                text=text,
                media_url=data.get("data"),  # base64 data URI
                media_type=data.get("media_type", "image"),
            )
        elif msg_type == "text" and text:
            content = MessageContent(
                type=ContentType.TEXT,
                text=text,
            )
        else:
            return None

        # Build identity from stored user info
        info = self._user_info.get(session_id, {})
        if info.get("user_type") == "authenticated":
            identity = Identity(
                id=info.get("user_id", session_id),
                username=info.get("user_id"),
                display_name=info.get("name") or info.get("user_id"),
            )
        else:
            identity = Identity(
                id=session_id,
                username=None,
                display_name=f"访客_{session_id[:6]}",
            )

        return UnifiedMessage(
            id=data.get("id", uuid.uuid4().hex[:8]),
            channel="webchat",
            sender=identity,
            content=content,
            chat_id=session_id,
            metadata={"user_info": info},
        )
