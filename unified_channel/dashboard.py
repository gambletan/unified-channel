"""Dashboard — lightweight built-in web UI for monitoring and sending messages."""

from __future__ import annotations

import asyncio
import json
import base64
import logging
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from http import HTTPStatus
from typing import Any

from aiohttp import web

from .manager import ChannelManager
from .middleware import Middleware, Handler
from .types import UnifiedMessage, OutboundMessage

logger = logging.getLogger(__name__)


@dataclass
class StoredMessage:
    id: str
    channel: str
    sender_id: str
    sender_username: str | None
    sender_display_name: str | None
    text: str
    timestamp: str


class Dashboard:
    """
    Web dashboard for unified-channel.

    Usage:
        dashboard = Dashboard(manager, port=8080)
        await dashboard.start()
        # ... later ...
        await dashboard.stop()
    """

    def __init__(
        self,
        manager: ChannelManager,
        *,
        port: int = 8080,
        auth: tuple[str, str] | None = None,
    ) -> None:
        self.manager = manager
        self.port = port
        self.auth = auth  # (username, password)
        self._messages: deque[StoredMessage] = deque(maxlen=100)
        self._app = web.Application(middlewares=[self._auth_middleware])
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

        # Register routes
        self._app.router.add_get("/", self._handle_index)
        self._app.router.add_get("/api/status", self._handle_status)
        self._app.router.add_get("/api/messages", self._handle_messages)
        self._app.router.add_post("/api/send", self._handle_send)

        # Install middleware on manager to capture messages
        manager.add_middleware(_DashboardMiddleware(self._record_message))

    @property
    def messages(self) -> list[StoredMessage]:
        return list(self._messages)

    async def start(self) -> None:
        """Start the HTTP server."""
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await self._site.start()
        logger.info("Dashboard started on port %d", self.port)

    async def stop(self) -> None:
        """Stop the HTTP server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None

    def _record_message(self, msg: UnifiedMessage) -> None:
        stored = StoredMessage(
            id=msg.id,
            channel=msg.channel,
            sender_id=msg.sender.id,
            sender_username=msg.sender.username,
            sender_display_name=msg.sender.display_name,
            text=msg.content.text,
            timestamp=msg.timestamp.isoformat(),
        )
        self._messages.append(stored)

    @web.middleware
    async def _auth_middleware(
        self, request: web.Request, handler: Any
    ) -> web.StreamResponse:
        if self.auth:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Basic "):
                return web.Response(
                    status=401,
                    text="Unauthorized",
                    headers={"WWW-Authenticate": 'Basic realm="Dashboard"'},
                )
            try:
                decoded = base64.b64decode(auth_header[6:]).decode()
                user, password = decoded.split(":", 1)
                if user != self.auth[0] or password != self.auth[1]:
                    return web.Response(
                        status=401,
                        text="Unauthorized",
                        headers={"WWW-Authenticate": 'Basic realm="Dashboard"'},
                    )
            except Exception:
                return web.Response(
                    status=401,
                    text="Unauthorized",
                    headers={"WWW-Authenticate": 'Basic realm="Dashboard"'},
                )
        return await handler(request)

    async def _handle_index(self, request: web.Request) -> web.Response:
        return web.Response(text=_DASHBOARD_HTML, content_type="text/html")

    async def _handle_status(self, request: web.Request) -> web.Response:
        statuses = await self.manager.get_status()
        # Convert ChannelStatus dataclasses to dicts
        result = {}
        for key, val in statuses.items():
            if hasattr(val, "__dict__"):
                d = {k: v for k, v in val.__dict__.items() if v is not None}
                # Convert datetime fields
                for dk, dv in d.items():
                    if isinstance(dv, datetime):
                        d[dk] = dv.isoformat()
                result[key] = d
            else:
                result[key] = val
        return web.json_response(result)

    async def _handle_messages(self, request: web.Request) -> web.Response:
        return web.json_response([asdict(m) for m in self._messages])

    async def _handle_send(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response(
                {"error": "Invalid JSON"}, status=400
            )

        channel = data.get("channel")
        chat_id = data.get("chatId")
        text = data.get("text")

        if not channel or not chat_id or not text:
            return web.json_response(
                {"error": "Missing required fields: channel, chatId, text"},
                status=400,
            )

        try:
            message_id = await self.manager.send(channel, chat_id, text)
            return web.json_response({"ok": True, "messageId": message_id})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)


class _DashboardMiddleware(Middleware):
    """Passively captures incoming messages for the dashboard."""

    def __init__(self, on_msg: Any) -> None:
        self._on_msg = on_msg

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        self._on_msg(msg)
        return await next_handler(msg)


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Unified Channel Dashboard</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', monospace;
    background: #0d1117; color: #c9d1d9;
    line-height: 1.6; padding: 20px;
  }
  h1 { color: #58a6ff; margin-bottom: 24px; font-size: 1.4em; }
  h2 { color: #8b949e; margin-bottom: 12px; font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }

  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }
  @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }

  .card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px;
  }

  .channels { display: flex; flex-wrap: wrap; gap: 12px; }
  .ch-card {
    background: #1c2129; border: 1px solid #30363d; border-radius: 6px;
    padding: 12px 16px; min-width: 140px; flex: 1;
  }
  .ch-name { font-weight: 600; color: #e6edf3; margin-bottom: 4px; }
  .ch-dot {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    margin-right: 6px; vertical-align: middle;
  }
  .ch-dot.on { background: #3fb950; }
  .ch-dot.off { background: #f85149; }

  .msg-list { max-height: 400px; overflow-y: auto; font-size: 0.85em; }
  .msg-item { padding: 8px 0; border-bottom: 1px solid #21262d; }
  .msg-meta { color: #8b949e; font-size: 0.8em; }
  .msg-text { color: #c9d1d9; margin-top: 2px; white-space: pre-wrap; word-break: break-word; }

  .send-form { display: flex; flex-direction: column; gap: 10px; }
  .send-form label { color: #8b949e; font-size: 0.85em; }
  .send-form input, .send-form select, .send-form textarea {
    background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;
    border-radius: 4px; padding: 8px; font-family: inherit; font-size: 0.9em;
  }
  .send-form textarea { min-height: 60px; resize: vertical; }
  .send-form button {
    background: #238636; color: #fff; border: none; border-radius: 4px;
    padding: 10px; cursor: pointer; font-family: inherit; font-weight: 600;
  }
  .send-form button:hover { background: #2ea043; }
  .send-result { font-size: 0.85em; margin-top: 4px; }
  .send-result.ok { color: #3fb950; }
  .send-result.err { color: #f85149; }
  .empty { color: #484f58; font-style: italic; }
</style>
</head>
<body>
<h1>Unified Channel Dashboard</h1>
<div class="grid">
  <div class="card">
    <h2>Channels</h2>
    <div id="channels" class="channels"><span class="empty">Loading...</span></div>
  </div>
  <div class="card">
    <h2>Send Message</h2>
    <div class="send-form" id="sendForm">
      <label>Channel <select id="sendChannel"></select></label>
      <label>Chat ID <input id="sendChatId" type="text" placeholder="e.g. 123456789"></label>
      <label>Message <textarea id="sendText" placeholder="Type your message..."></textarea></label>
      <button onclick="sendMessage()">Send</button>
      <div id="sendResult" class="send-result"></div>
    </div>
  </div>
</div>
<div class="card">
  <h2>Recent Messages</h2>
  <div id="messages" class="msg-list"><span class="empty">No messages yet</span></div>
</div>
<script>
async function fetchStatus(){try{const r=await fetch('/api/status');const d=await r.json();const el=document.getElementById('channels');const sel=document.getElementById('sendChannel');const keys=Object.keys(d);if(!keys.length){el.innerHTML='<span class="empty">No channels</span>';return}el.innerHTML=keys.map(k=>{const s=d[k];const dot=s.connected?'on':'off';const l=s.connected?'Connected':(s.error||'Disconnected');return'<div class="ch-card"><div class="ch-name">'+esc(k)+'</div><span class="ch-dot '+dot+'"></span>'+esc(l)+'</div>'}).join('');sel.innerHTML=keys.map(k=>'<option value="'+esc(k)+'">'+esc(k)+'</option>').join('')}catch(e){console.error(e)}}
async function fetchMessages(){try{const r=await fetch('/api/messages');const d=await r.json();const el=document.getElementById('messages');if(!d.length){el.innerHTML='<span class="empty">No messages yet</span>';return}el.innerHTML=d.slice().reverse().map(m=>{const t=new Date(m.timestamp).toLocaleTimeString();const w=m.sender_display_name||m.sender_username||m.sender_id;return'<div class="msg-item"><div class="msg-meta">['+esc(t)+'] <b>'+esc(m.channel)+'</b> / '+esc(w)+'</div><div class="msg-text">'+esc(m.text)+'</div></div>'}).join('')}catch(e){console.error(e)}}
async function sendMessage(){const ch=document.getElementById('sendChannel').value;const ci=document.getElementById('sendChatId').value;const tx=document.getElementById('sendText').value;const rs=document.getElementById('sendResult');if(!ch||!ci||!tx){rs.className='send-result err';rs.textContent='All fields required';return}try{const r=await fetch('/api/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel:ch,chatId:ci,text:tx})});const d=await r.json();if(d.ok){rs.className='send-result ok';rs.textContent='Sent (id: '+(d.messageId||'n/a')+')';document.getElementById('sendText').value=''}else{rs.className='send-result err';rs.textContent=d.error||'Failed'}}catch(e){rs.className='send-result err';rs.textContent=String(e)}}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
fetchStatus();fetchMessages();setInterval(()=>{fetchStatus();fetchMessages()},5000);
</script>
</body>
</html>"""
