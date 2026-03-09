<div align="center">

[中文文档](README.zh-CN.md)

# unified-channel

### 19 Channels. 1 API. Ship Your AI Agent Everywhere.

[![PyPI](https://img.shields.io/pypi/v/unified-channel?color=blue&label=PyPI)](https://pypi.org/project/unified-channel/)
[![npm](https://img.shields.io/npm/v/unified-channel?color=red&label=npm)](https://www.npmjs.com/package/unified-channel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-284%20passing-brightgreen.svg)]()

**Stop writing platform-specific bot code.** Write your agent once, deploy to every messaging platform your users are on.

[Get Started](#quick-start) | [AI Agent Example](#ai-agent-integration) | [19 Adapters](#channel-adapters) | [API Reference](#api-reference)

</div>

---

### The problem

You build a Telegram bot. Then your team uses Slack. Clients want WhatsApp. Discord community needs it too. Now you're maintaining 4 codebases doing the same thing with 4 different APIs.

### The solution

```
pip install unified-channel[telegram,discord,slack,whatsapp]
```

One `ChannelManager`. One middleware pipeline. One message type. **19 channels.**

```python
manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="..."))
manager.add_channel(DiscordAdapter(token="..."))
manager.add_channel(SlackAdapter(bot_token="...", app_token="..."))

@manager.on_message
async def handle(msg):
    # msg.channel == "telegram" | "discord" | "slack" | ...
    # Same code handles all of them
    return await my_agent.chat(msg.content.text)
```

### Why unified-channel

| | Without | With unified-channel |
|---|---|---|
| **Add a channel** | New SDK, new message format, new auth flow, new deploy | `manager.add_channel(XAdapter(token="..."))` |
| **Auth/rate-limit** | Implement per-platform | `add_middleware(AccessMiddleware(...))` — works everywhere |
| **Send from backend** | Different API per channel | `await manager.send("telegram", chat_id, text)` |
| **New adapter** | Days of work | 1 file, 5 methods |

### Built-in batteries

| Feature | What it does |
|---|---|
| **AccessMiddleware** | Allowlist users across all channels |
| **CommandMiddleware** | `/command` routing with argument parsing |
| **RateLimitMiddleware** | Sliding window per-user rate limiting |
| **ConversationMemory** | Per-chat history (InMemory / SQLite / Redis) |
| **StreamingMiddleware** | Typing indicators + chunked LLM delivery |
| **RichReply** | Tables, buttons, code blocks — auto-degrades per platform |
| **ServiceBridge** | Expose any function as a chat command in 1 line |
| **Scheduler** | Cron + interval periodic tasks |
| **Dashboard** | Built-in web UI with message log + API |
| **I18n** | Locale detection + translation helpers |
| **VoiceMiddleware** | STT/TTS (OpenAI Whisper + TTS) |
| **YAML Config** | Load channels from config file, env var interpolation |

### Supported channels

| Channel | Mode | Public URL needed |
|---|---|---|
| Telegram | Polling / Webhook | No |
| Discord | WebSocket | No |
| Slack | Socket Mode | No |
| WhatsApp | Webhook | Yes |
| iMessage | DB polling (macOS) | No |
| LINE | Webhook | Yes |
| Matrix | Sync | No |
| MS Teams | Webhook | Yes |
| Feishu / Lark | Webhook | Yes |
| Mattermost | WebSocket | No |
| Google Chat | Webhook | Yes |
| Twitch | IRC/WebSocket | No |
| IRC | TCP socket | No |
| Nostr | WebSocket (relay) | No |
| Zalo | Webhook | Yes |
| BlueBubbles | Polling | No |
| Nextcloud Talk | Polling | No |
| Synology Chat | Webhook | Yes |

### Also available in

| Language | Package | Install |
|---|---|---|
| **Python** | [unified-channel](https://pypi.org/project/unified-channel/) | `pip install unified-channel` |
| **TypeScript** | [unified-channel](https://www.npmjs.com/package/unified-channel) | `npm install unified-channel` |
| **Java** | [unified-channel-java](https://github.com/gambletan/unified-channel-java) | Maven / Gradle |

---

## Quick Start

```python
import asyncio
from unified_channel import ChannelManager, TelegramAdapter, CommandMiddleware

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="BOT_TOKEN"))

cmds = CommandMiddleware()
manager.add_middleware(cmds)

@cmds.command("status")
async def status(msg):
    return "All systems operational"

@cmds.command("deploy")
async def deploy(msg):
    env = msg.content.args[0] if msg.content.args else "staging"
    # your_app.deploy(env)
    return f"Deploying to {env}..."

asyncio.run(manager.run())
```

That's it. Your bot is live, responding to `/status` and `/deploy staging`.

---

## Table of Contents

- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Channel Adapters](#channel-adapters)
  - [Telegram](#telegram)
  - [Discord](#discord)
  - [Slack](#slack)
  - [WhatsApp](#whatsapp)
  - [iMessage](#imessage)
  - [LINE](#line)
  - [Matrix](#matrix)
  - [Microsoft Teams](#microsoft-teams)
  - [Feishu / Lark](#feishu--lark)
- [Middleware](#middleware)
  - [Access Control](#access-control)
  - [Command Routing](#command-routing)
  - [Conversation Memory](#conversation-memory)
  - [Streaming and Typing Indicators](#streaming-and-typing-indicators)
  - [Custom Middleware](#custom-middleware)
  - [Middleware Chain Order](#middleware-chain-order)
- [Rich Replies](#rich-replies)
- [Sending Messages](#sending-messages)
- [Multi-Channel Setup](#multi-channel-setup)
- [Message Types](#message-types)
- [Writing a Custom Adapter](#writing-a-custom-adapter)
- [ServiceBridge](#servicebridge)
- [YAML Config](#yaml-config)
- [Real-World Example](#real-world-example)
- [API Reference](#api-reference)

---

## Installation

Install only the adapters you need:

```bash
# Single channel
pip install unified-channel[telegram]
pip install unified-channel[discord]
pip install unified-channel[slack]
pip install unified-channel[whatsapp]
pip install unified-channel[line]
pip install unified-channel[matrix]
pip install unified-channel[msteams]
pip install unified-channel[feishu]
pip install unified-channel[mattermost]
pip install unified-channel[googlechat]
pip install unified-channel[twitch]
pip install unified-channel[nostr]
pip install unified-channel[zalo]
pip install unified-channel[bluebubbles]
pip install unified-channel[nextcloud]
pip install unified-channel[synology]

# No extra deps needed: iMessage, IRC
pip install unified-channel

# Multiple channels
pip install unified-channel[telegram,discord,slack]

# Everything
pip install unified-channel[all]
```

Requires **Python 3.10+**.

---

## Core Concepts

```
Your App
  │
  ├─ ChannelManager              ← orchestrates everything
  │    ├─ Middleware Pipeline     ← shared logic (auth, commands, rate-limit, logging)
  │    │    ├─ AccessMiddleware
  │    │    ├─ CommandMiddleware
  │    │    └─ YourMiddleware
  │    │
  │    ├─ TelegramAdapter        ← 1 file per channel
  │    ├─ DiscordAdapter         ← 1 file
  │    ├─ SlackAdapter           ← 1 file
  │    ├─ WhatsAppAdapter        ← 1 file
  │    ├─ ... (19 adapters)
  │    └─ IRCAdapter             ← 1 file
  │
  └─ UnifiedMessage              ← one type, all channels
```

**ChannelManager** connects adapters to middleware. Messages arrive from any adapter, flow through the middleware pipeline, and replies are sent back through the same adapter.

**UnifiedMessage** is the single message type shared across all channels — your command handlers never need to know which platform the message came from.

**Middleware** is composable. Stack access control, command routing, rate limiting, logging — in any order.

---

## Channel Adapters

### Telegram

Uses [python-telegram-bot](https://python-telegram-bot.org/). Polling mode, no webhook server needed.

```python
from unified_channel import TelegramAdapter

adapter = TelegramAdapter(
    token="123456:ABC-DEF...",
    parse_mode="Markdown",       # default; also supports "HTML"
)
```

**Setup:**
1. Message [@BotFather](https://t.me/BotFather) on Telegram → `/newbot`
2. Copy the token
3. Find your user ID: message [@userinfobot](https://t.me/userinfobot)

---

### Discord

Uses [discord.py](https://discordpy.readthedocs.io/). Connects via Gateway WebSocket.

```python
from unified_channel import DiscordAdapter

adapter = DiscordAdapter(
    token="your-bot-token",
    allowed_channel_ids={123456789},  # optional: restrict to specific channels
    allow_dm=True,                    # accept DMs (default True)
    command_prefix="/",               # default "/"
)
```

**Setup:**
1. Create app at [discord.com/developers](https://discord.com/developers/applications)
2. Bot → enable **Message Content Intent**
3. Copy the bot token
4. Invite URL: `https://discord.com/oauth2/authorize?client_id=APP_ID&scope=bot&permissions=3072`

---

### Slack

Uses [slack-bolt](https://slack.dev/bolt-python/) in Socket Mode (no public URL needed).

```python
from unified_channel import SlackAdapter

adapter = SlackAdapter(
    bot_token="xoxb-...",
    app_token="xapp-...",            # Socket Mode token
    allowed_channel_ids={"C01234"},   # optional
    command_prefix="/",
)
```

**Setup:**
1. Create app at [api.slack.com/apps](https://api.slack.com/apps)
2. Enable **Socket Mode** → generate App-Level Token (`xapp-...`)
3. **OAuth & Permissions** → add scopes: `chat:write`, `channels:history`, `im:history`
4. **Event Subscriptions** → subscribe to `message.channels`, `message.im`
5. Install to workspace → copy Bot Token (`xoxb-...`)

---

### WhatsApp

Uses Meta's [WhatsApp Business Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api). Webhook mode — requires a public URL.

```python
from unified_channel import WhatsAppAdapter

adapter = WhatsAppAdapter(
    access_token="EAABx...",          # permanent token
    phone_number_id="1234567890",
    verify_token="my-verify-token",   # you choose this
    app_secret="abc123",              # optional, for signature verification
    port=8443,
)
```

**Setup:**
1. Create app at [developers.facebook.com](https://developers.facebook.com/)
2. Add **WhatsApp** product
3. Get permanent access token + phone number ID from WhatsApp dashboard
4. Set webhook URL to `https://your-server:8443/whatsapp/webhook`
5. Set verify token to match your `verify_token` parameter

---

### iMessage

**macOS only.** No external dependencies. Polls the Messages SQLite database for incoming messages, sends via AppleScript.

```python
from unified_channel import IMessageAdapter

adapter = IMessageAdapter(
    allowed_numbers={"+1234567890"},  # optional: restrict senders
    poll_interval=3.0,                # seconds between polls (default 3)
)
```

**Requirements:**
- macOS with Messages.app signed in to iMessage
- **Full Disk Access** for your process (System Settings → Privacy → Full Disk Access)
- Messages.app must be running

---

### LINE

Uses the official [LINE Bot SDK v3](https://github.com/line/line-bot-sdk-python). Webhook mode.

```python
from unified_channel import LineAdapter

adapter = LineAdapter(
    channel_secret="your-channel-secret",
    channel_access_token="your-access-token",
    port=8080,
    path="/line/webhook",
)
```

**Setup:**
1. Create a channel at [LINE Developers Console](https://developers.line.biz/)
2. Get Channel Secret + Channel Access Token
3. Set webhook URL to `https://your-server:8080/line/webhook`

---

### Matrix

Uses [matrix-nio](https://github.com/poljar/matrix-nio). Supports E2E encryption.

```python
from unified_channel import MatrixAdapter

adapter = MatrixAdapter(
    homeserver="https://matrix.org",
    user_id="@bot:matrix.org",
    password="your-password",
    # or: access_token="syt_...",
    allowed_room_ids={"!abc:matrix.org"},  # optional
    auto_join=True,                         # auto-accept invites (default True)
)
```

**Setup:**
1. Register a bot account on your Matrix homeserver
2. For E2E encryption: `pip install unified-channel[matrix]` pulls in `matrix-nio[e2e]`

---

### Microsoft Teams

Uses [Bot Framework SDK](https://github.com/microsoft/botbuilder-python). Webhook mode.

```python
from unified_channel import MSTeamsAdapter

adapter = MSTeamsAdapter(
    app_id="your-app-id",
    app_password="your-app-password",
    port=3978,
    path="/api/messages",
)
```

**Setup:**
1. Register bot at [Bot Framework Portal](https://dev.botframework.com/bots/new)
2. Get Microsoft App ID + Password
3. Set messaging endpoint to `https://your-server:3978/api/messages`
4. Add the bot to your Teams workspace

---

### Feishu / Lark

Uses the official [lark-oapi SDK](https://github.com/larksuite/oapi-sdk-python). Webhook mode.

```python
from unified_channel import FeishuAdapter

adapter = FeishuAdapter(
    app_id="cli_xxx",
    app_secret="your-app-secret",
    verification_token="your-verify-token",  # from Event Subscription
    port=9000,
    path="/feishu/webhook",
)
```

**Setup:**
1. Create app at [Feishu Open Platform](https://open.feishu.cn/)
2. Get App ID + App Secret
3. Enable **Event Subscription** → set webhook URL
4. Add `im:message:receive_v1` event

---

### Mattermost

Uses WebSocket for events + REST API for sending.

```python
from unified_channel import MattermostAdapter

adapter = MattermostAdapter(
    url="https://mattermost.example.com",
    token="your-bot-token",
    allowed_channel_ids={"channel-id"},  # optional
)
```

---

### Google Chat

Uses Google service account + webhook.

```python
from unified_channel import GoogleChatAdapter

adapter = GoogleChatAdapter(
    service_account_file="service-account.json",
    port=8090,
)
```

---

### Twitch

IRC over WebSocket. Default command prefix is `!` (Twitch convention).

```python
from unified_channel import TwitchAdapter

adapter = TwitchAdapter(
    oauth_token="oauth:your-token",
    bot_username="mybotname",
    channels=["#yourchannel"],
    command_prefix="!",
)
```

**Setup:** Generate token at [twitchapps.com/tmi](https://twitchapps.com/tmi/).

---

### IRC

Pure asyncio — no external dependencies.

```python
from unified_channel import IRCAdapter

adapter = IRCAdapter(
    server="irc.libera.chat",
    port=6697,
    nickname="mybot",
    channels=["#mychannel"],
    use_ssl=True,
    command_prefix="!",
)
```

---

### Nostr

NIP-04 encrypted DMs via relay WebSocket.

```python
from unified_channel import NostrAdapter

adapter = NostrAdapter(
    private_key_hex="your-hex-private-key",
    relay_urls=["wss://relay.damus.io", "wss://nos.lol"],
)
```

---

### BlueBubbles

iMessage via [BlueBubbles](https://bluebubbles.app/) macOS server REST API.

```python
from unified_channel import BlueBubblesAdapter

adapter = BlueBubblesAdapter(
    server_url="http://localhost:1234",
    password="your-server-password",
)
```

---

### Zalo

Zalo Official Account API (Vietnam).

```python
from unified_channel import ZaloAdapter

adapter = ZaloAdapter(
    access_token="your-oa-access-token",
    port=8060,
)
```

---

### Nextcloud Talk

REST polling — self-hosted.

```python
from unified_channel import NextcloudTalkAdapter

adapter = NextcloudTalkAdapter(
    server_url="https://nextcloud.example.com",
    username="botuser",
    password="app-password",
    room_tokens=["room-token"],  # optional; auto-discovers if empty
)
```

---

### Synology Chat

Incoming/outgoing webhook — NAS-based chat.

```python
from unified_channel import SynologyChatAdapter

adapter = SynologyChatAdapter(
    incoming_webhook_url="https://your-nas/webapi/entry.cgi?...",
    outgoing_token="your-outgoing-token",
    port=8070,
)
```

---

## Middleware

### Access Control

Restrict who can interact with your bot:

```python
from unified_channel import AccessMiddleware

# Only these user IDs can send commands
manager.add_middleware(AccessMiddleware(
    allowed_user_ids={"123456", "789012"}
))

# No allowlist = allow everyone
manager.add_middleware(AccessMiddleware())
```

Blocked messages are silently dropped (no reply sent).

### Command Routing

Register handlers for `/commands`:

```python
from unified_channel import CommandMiddleware

cmds = CommandMiddleware()
manager.add_middleware(cmds)

# Decorator style
@cmds.command("help")
async def help_cmd(msg):
    return "Available: /status, /deploy, /logs"

# Programmatic registration
async def status_handler(msg):
    return "OK"
cmds.register("status", status_handler)

# Access command arguments
@cmds.command("deploy")
async def deploy(msg):
    # /deploy staging → msg.content.args = ["staging"]
    env = msg.content.args[0] if msg.content.args else "production"
    return f"Deploying to {env}"

# List registered commands
print(cmds.registered_commands)  # ["help", "status", "deploy"]
```

Non-command messages pass through to the next middleware or fallback handler.

### Custom Middleware

Implement the `Middleware` base class:

```python
from unified_channel import Middleware, UnifiedMessage

class LoggingMiddleware(Middleware):
    async def process(self, msg, next_handler):
        print(f"[{msg.channel}] {msg.sender.id}: {msg.content.text}")
        result = await next_handler(msg)
        print(f"[{msg.channel}] reply: {result}")
        return result

class RateLimitMiddleware(Middleware):
    def __init__(self, max_per_minute=10):
        self._counts = {}
        self._max = max_per_minute

    async def process(self, msg, next_handler):
        uid = msg.sender.id
        # ... check rate limit ...
        if self._is_limited(uid):
            return "Too many requests. Please wait."
        return await next_handler(msg)

class AdminOnlyMiddleware(Middleware):
    """Different behavior for admin vs regular users."""
    def __init__(self, admin_ids):
        self._admins = admin_ids

    async def process(self, msg, next_handler):
        if msg.content.command in ("shutdown", "restart"):
            if msg.sender.id not in self._admins:
                return "Admin only."
        return await next_handler(msg)
```

### Middleware Chain Order

Middleware runs **in the order you add it**. First-added runs first:

```python
manager.add_middleware(LoggingMiddleware())      # 1st: log everything
manager.add_middleware(AccessMiddleware({...}))   # 2nd: check access
manager.add_middleware(RateLimitMiddleware())      # 3rd: rate limit
manager.add_middleware(cmds)                       # 4th: route commands
```

Each middleware calls `next_handler(msg)` to pass to the next one, or returns a string/`None` to short-circuit.

### Conversation Memory

Automatically maintain per-chat conversation history and inject it into every message. Perfect for LLM-backed agents that need context:

```python
from unified_channel import ConversationMemory, InMemoryStore, SQLiteStore

# In-memory (default) — fast, lost on restart
manager.add_middleware(ConversationMemory(max_turns=50))

# SQLite — persistent across restarts
manager.add_middleware(ConversationMemory(
    store=SQLiteStore("memory.db"),
    max_turns=100,
))

# Access history in your handler
@manager.on_message
async def chat(msg):
    history = msg.metadata["history"]  # list of {"role", "content", "timestamp", ...}
    # Pass history to your LLM
    response = await llm.chat(messages=history + [{"role": "user", "content": msg.content.text}])
    return response
```

**Storage backends:**

| Backend | Persistence | Use case |
|---------|-------------|----------|
| `InMemoryStore()` | No | Development, testing, stateless bots |
| `SQLiteStore(path)` | Yes | Single-server production deployments |
| `RedisStore(url)` | Yes | Multi-server / distributed deployments |

Implement `MemoryStore` to add your own backend (DynamoDB, Postgres, etc.).

### Streaming and Typing Indicators

Show typing indicators while your handler processes, and stream LLM responses chunk-by-chunk:

```python
from unified_channel import StreamingMiddleware, StreamingReply

# Add to pipeline — typing indicators sent automatically
manager.add_middleware(StreamingMiddleware(
    typing_interval=3.0,  # seconds between typing pings
    chunk_delay=0.5,      # delay between streamed chunks
))

# Regular handlers get typing indicators for free
@cmds.command("slow")
async def slow_command(msg):
    result = await expensive_computation()
    return result  # typing indicator shown while computing

# Return StreamingReply for progressive delivery
@manager.on_message
async def chat(msg):
    stream = llm.stream_chat(msg.content.text)
    return StreamingReply.from_llm(stream)
```

---

## Rich Replies

Build platform-agnostic rich messages with a fluent API. Tables, buttons, images, and code blocks auto-degrade to plain text on unsupported channels:

```python
from unified_channel import RichReply, Button

reply = (
    RichReply("Server Status")
    .add_table(
        headers=["Service", "Status", "Uptime"],
        rows=[
            ["API", "OK", "99.9%"],
            ["DB", "OK", "99.7%"],
            ["Cache", "WARN", "98.2%"],
        ],
    )
    .add_divider()
    .add_code("$ systemctl status api\n  Active: running", language="bash")
    .add_buttons([[
        Button(label="Restart API", callback_data="restart_api"),
        Button(label="View Logs", url="https://logs.example.com"),
    ]])
)

# Auto-select best format per channel
outbound = reply.to_outbound("telegram")  # Markdown + inline_keyboard
outbound = reply.to_outbound("discord")   # Embeds + components
outbound = reply.to_outbound("slack")     # Blocks
outbound = reply.to_outbound("irc")       # Plain text fallback

# Or render directly
reply.to_plain_text()   # ASCII table, plain buttons
reply.to_telegram()     # {"text": "...", "parse_mode": "Markdown", "reply_markup": {...}}
reply.to_discord()      # {"embeds": [...], "components": [...]}
reply.to_slack()        # {"blocks": [...]}
```

Use inside any handler:

```python
@cmds.command("status")
async def status(msg):
    reply = RichReply("All systems operational").add_table(
        ["Metric", "Value"],
        [["Latency", "12ms"], ["Queue", "0"]],
    )
    return reply.to_outbound(msg.channel)
```

---

## Sending Messages

### Reply (automatic)

Command handlers return a string → it's sent back to the same chat:

```python
@cmds.command("ping")
async def ping(msg):
    return "pong"  # auto-replied to the sender's chat
```

### Push (proactive)

Send messages from anywhere in your app:

```python
# Send to a specific channel + chat
await manager.send("telegram", chat_id="123456", text="Job complete!")

# With options
await manager.send(
    "telegram",
    chat_id="123456",
    text="*Alert*: disk usage 95%",
    parse_mode="Markdown",
)

# Broadcast to multiple channels
await manager.broadcast(
    "Deploy v2.1.0 complete",
    chat_ids={
        "telegram": "123456",
        "discord": "987654321",
        "slack": "C01ABCDEF",
    }
)
```

### Return OutboundMessage for full control

```python
from unified_channel import OutboundMessage, Button

@cmds.command("confirm")
async def confirm(msg):
    return OutboundMessage(
        chat_id=msg.chat_id,
        text="Are you sure?",
        buttons=[[
            Button(label="Yes", callback_data="confirm_yes"),
            Button(label="No", callback_data="confirm_no"),
        ]],
        parse_mode="Markdown",
    )
```

---

## Multi-Channel Setup

Run multiple channels simultaneously — same commands, same middleware:

```python
from unified_channel import (
    ChannelManager, TelegramAdapter, DiscordAdapter, SlackAdapter,
    AccessMiddleware, CommandMiddleware,
)

manager = ChannelManager()

# Add all channels
manager.add_channel(TelegramAdapter(token="tg-token"))
manager.add_channel(DiscordAdapter(token="dc-token"))
manager.add_channel(SlackAdapter(bot_token="xoxb-...", app_token="xapp-..."))

# Shared middleware — works across all channels
manager.add_middleware(AccessMiddleware(allowed_user_ids={"tg_123", "dc_456", "U0SLACK"}))

cmds = CommandMiddleware()
manager.add_middleware(cmds)

@cmds.command("status")
async def status(msg):
    # msg.channel tells you where it came from
    return f"OK (via {msg.channel})"

asyncio.run(manager.run())
```

All channels share the same command handlers and middleware pipeline. A `/status` command works identically whether sent from Telegram, Discord, or Slack.

---

## Message Types

### UnifiedMessage (incoming)

Every incoming message, regardless of channel, becomes a `UnifiedMessage`:

```python
@manager.on_message
async def handler(msg):
    msg.id           # "12345" — platform message ID
    msg.channel      # "telegram", "discord", "slack", ...
    msg.sender.id    # sender's platform user ID
    msg.sender.username
    msg.sender.display_name
    msg.content.type # ContentType.TEXT, COMMAND, MEDIA, CALLBACK, REACTION
    msg.content.text # raw text
    msg.content.command  # "status" (for /status)
    msg.content.args     # ["arg1", "arg2"] (for /status arg1 arg2)
    msg.chat_id      # chat/channel/room ID
    msg.thread_id    # thread ID (if applicable)
    msg.reply_to_id  # ID of message being replied to
    msg.timestamp    # datetime
    msg.raw          # original platform object (for advanced use)
    msg.metadata     # dict for custom data
```

### ContentType enum

```python
from unified_channel import ContentType

ContentType.TEXT      # regular text message
ContentType.COMMAND   # /command with parsed args
ContentType.MEDIA     # image, video, file
ContentType.CALLBACK  # inline button press
ContentType.REACTION  # emoji reaction
ContentType.EDIT      # edited message
```

---

## Writing a Custom Adapter

Add a new channel by implementing `ChannelAdapter` — 5 methods, 1 file:

```python
from unified_channel import ChannelAdapter, UnifiedMessage, OutboundMessage, ChannelStatus

class MyAdapter(ChannelAdapter):
    channel_id = "mychannel"

    async def connect(self) -> None:
        """Start connection (WebSocket, polling, webhook server, etc.)."""
        ...

    async def disconnect(self) -> None:
        """Clean shutdown."""
        ...

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        """Yield incoming messages as UnifiedMessage."""
        while self._connected:
            raw = await self._get_next_message()
            yield UnifiedMessage(
                id=raw["id"],
                channel="mychannel",
                sender=Identity(id=raw["user_id"]),
                content=MessageContent(type=ContentType.TEXT, text=raw["text"]),
                chat_id=raw["chat_id"],
            )

    async def send(self, msg: OutboundMessage) -> str | None:
        """Send a message. Return message ID if available."""
        result = await self._api.send(msg.chat_id, msg.text)
        return result.id

    async def get_status(self) -> ChannelStatus:
        """Return connection health."""
        return ChannelStatus(connected=self._connected, channel="mychannel")
```

Then register it:

```python
manager.add_channel(MyAdapter(...))
```

---

## ServiceBridge

`ServiceBridge` is the fastest way to expose any service as a chat-controllable interface. Instead of wiring up `CommandMiddleware` by hand, you call `expose()` and get automatic `/help`, argument parsing, error handling, and sync-function support for free.

```python
import asyncio
from unified_channel import ChannelManager, TelegramAdapter, ServiceBridge

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="BOT_TOKEN"))

bridge = ServiceBridge(manager)

# Expose any function as a chat command
bridge.expose("deploy", lambda args: f"Deploying to {args[0] if args else 'staging'}...",
              description="Deploy the app", params=["env"])

# Sync or async — both work
def disk_usage(args):
    import shutil
    total, used, free = shutil.disk_usage("/")
    return f"Disk: {used // (1 << 30)}G / {total // (1 << 30)}G"

bridge.expose("disk", disk_usage, description="Check disk usage")

# Built-in /status and /logs shortcuts
bridge.expose_status(lambda args: "All systems operational")
bridge.expose_logs(lambda args: open("app.log").readlines()[-10:])

# Handlers can receive the full UnifiedMessage
async def whoami(args, msg):
    return f"You are {msg.sender.username} on {msg.channel}"

bridge.expose("whoami", whoami, description="Show caller info")

asyncio.run(bridge.run())
```

This gives you `/help`, `/deploy`, `/disk`, `/status`, `/logs`, and `/whoami` — all with automatic error handling. If a command throws, the user gets a friendly error message instead of silence.

### Flag parsing

Arguments like `--force` and `--count 3` are automatically parsed:

```python
async def restart(args, msg):
    flags = msg.metadata.get("_flags", {})
    force = flags.get("force") == "true"
    service = args[0] if args else "all"
    return f"Restarting {service} (force={force})"

bridge.expose("restart", restart, description="Restart services", params=["service"])
# /restart nginx --force  →  "Restarting nginx (force=True)"
```

---

## YAML Config

Load channels and middleware from a config file instead of writing Python:

```yaml
# unified-channel.yaml
channels:
  telegram:
    token: "${UC_TELEGRAM_TOKEN}"
  discord:
    token: "${UC_DISCORD_TOKEN}"
  slack:
    bot_token: "${UC_SLACK_BOT_TOKEN}"
    app_token: "${UC_SLACK_APP_TOKEN}"

middleware:
  access:
    allowed_users: ["admin_id_1", "admin_id_2"]

settings:
  command_prefix: "/"
```

```python
from unified_channel import load_config, ServiceBridge

manager = load_config("unified-channel.yaml")
bridge = ServiceBridge(manager)
bridge.expose("status", lambda args: "OK")
asyncio.run(bridge.run())
```

Environment variables are interpolated with `${VAR}` syntax. Adapters are auto-detected by name. Returns a fully configured `ChannelManager` ready to use.

---

## Real-World Example

A complete remote management bot for a job queue system:

```python
import asyncio
import os
from unified_channel import (
    ChannelManager, TelegramAdapter,
    AccessMiddleware, CommandMiddleware, UnifiedMessage,
)

# Your app's imports
from myapp.jobs import JobQueue
from myapp.metrics import get_metrics
from myapp.accounts import list_accounts

queue = JobQueue("data/jobs.db")

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token=os.environ["TELEGRAM_TOKEN"]))
manager.add_middleware(AccessMiddleware(allowed_user_ids={os.environ["ADMIN_ID"]}))

cmds = CommandMiddleware()
manager.add_middleware(cmds)


@cmds.command("start")
async def start(msg: UnifiedMessage) -> str:
    return "\n".join(f"/{c}" for c in sorted(cmds.registered_commands))


@cmds.command("status")
async def status(msg: UnifiedMessage) -> str:
    m = get_metrics()
    return (
        f"*System Status*\n"
        f"Queued: {m['queued']} | Running: {m['running']}\n"
        f"Completed: {m['completed']} | Failed: {m['failed']}"
    )


@cmds.command("accounts")
async def accounts(msg: UnifiedMessage) -> str:
    accs = list_accounts()
    lines = [f"  {a.name}: {a.status}" for a in accs]
    return "*Accounts*\n" + "\n".join(lines)


@cmds.command("run")
async def run_job(msg: UnifiedMessage) -> str:
    if len(msg.content.args) < 2:
        return "Usage: /run <account> <job_type>"
    account, job_type = msg.content.args[0], msg.content.args[1]
    job_id = queue.enqueue(account, job_type)
    return f"Enqueued: `{account}.{job_type}` (ID: `{job_id[:8]}...`)"


@cmds.command("logs")
async def logs(msg: UnifiedMessage) -> str:
    n = int(msg.content.args[0]) if msg.content.args else 10
    lines = open(f"logs/app.log").readlines()[-n:]
    return f"```\n{''.join(lines)}```"


# Push notifications from your app
async def on_job_failed(job_name, error):
    await manager.send("telegram", chat_id=os.environ["ADMIN_ID"], text=f"Job failed: {job_name}\n{error}")


@manager.on_message
async def fallback(msg: UnifiedMessage) -> str:
    return "Unknown command. Send /start for help."


if __name__ == "__main__":
    asyncio.run(manager.run())
```

---

## AI Agent Integration

Connect Claude (or any LLM) to your Telegram bot — users chat naturally, and the agent can read/edit your project files:

```python
import asyncio
import os
from unified_channel import (
    ChannelManager, TelegramAdapter,
    AccessMiddleware, CommandMiddleware, RateLimitMiddleware,
    ConversationMemory, Scheduler, Dashboard, UnifiedMessage,
)

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token=os.environ["TELEGRAM_TOKEN"]))

# Security: admin-only + rate limiting
manager.add_middleware(AccessMiddleware(allowed_user_ids={os.environ["ADMIN_ID"]}))
manager.add_middleware(RateLimitMiddleware(max_messages=30, window_seconds=60))
manager.add_middleware(ConversationMemory(max_turns=50))

cmds = CommandMiddleware()
manager.add_middleware(cmds)

# Per-chat history for LLM context
chat_histories: dict[str, list[dict]] = {}
active_tasks: dict[str, asyncio.subprocess.Process] = {}

ALLOWED_MODELS = {"claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-6"}
model = "claude-sonnet-4-20250514"
work_dir = os.environ.get("CLAUDE_WORK_DIR", os.getcwd())


async def call_claude_cli(text: str, history: list, chat_id: str) -> str:
    """Run Claude Code CLI with project context."""
    import shutil
    claude_bin = shutil.which("claude")
    if not claude_bin:
        return "Claude CLI not found."

    # Build prompt with conversation history
    parts = []
    for entry in history[:-1]:
        role = "Human" if entry["role"] == "user" else "Assistant"
        parts.append(f"{role}: {entry['content']}")

    prompt = text
    if parts:
        prompt = "Previous conversation:\n" + "\n".join(parts[-10:]) + f"\n\nHuman: {text}"

    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    proc = await asyncio.create_subprocess_exec(
        claude_bin, "--print", "--model", model,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        cwd=work_dir,  # Claude works in your project directory
    )
    active_tasks[chat_id] = proc
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(input=prompt.encode()), timeout=120)
    finally:
        active_tasks.pop(chat_id, None)

    return stdout.decode().strip() if proc.returncode == 0 else "Claude encountered an error."


@cmds.command("stop")
async def stop_cmd(msg: UnifiedMessage) -> str:
    proc = active_tasks.get(msg.chat_id)
    if proc and proc.returncode is None:
        proc.kill()
        return "Stopped."
    return "No active task."


@cmds.command("model")
async def model_cmd(msg: UnifiedMessage) -> str:
    global model
    if msg.content.args:
        if msg.content.args[0] not in ALLOWED_MODELS:
            return f"Allowed: {', '.join(ALLOWED_MODELS)}"
        model = msg.content.args[0]
        return f"Model: `{model}`"
    return f"Current: `{model}`"


@cmds.command("clear")
async def clear_cmd(msg: UnifiedMessage) -> str:
    chat_histories.pop(msg.chat_id, None)
    return "History cleared."


@manager.on_message
async def on_message(msg: UnifiedMessage) -> str:
    text = msg.content.text
    if not text or not text.strip():
        return "Send a message to chat with Claude."

    chat_id = msg.chat_id or "default"
    history = chat_histories.setdefault(chat_id, [])
    history.append({"role": "user", "content": text})

    if len(history) > 40:
        chat_histories[chat_id] = history[-40:]
        history = chat_histories[chat_id]

    # Show thinking indicator
    try:
        await manager.send("telegram", chat_id, "💭 Thinking...")
    except Exception:
        pass

    reply = await call_claude_cli(text, history, chat_id)
    history.append({"role": "assistant", "content": reply})
    return reply


# Optional: scheduled reports + web dashboard
scheduler = Scheduler(manager)
dashboard = Dashboard(manager, port=8080)


async def main():
    await dashboard.start()
    scheduler.every(3600, "telegram", os.environ["ADMIN_ID"],
                    lambda: "Hourly: all systems operational")
    await manager.run()

asyncio.run(main())
```

**What this gives you:**
- Chat with Claude naturally via Telegram — Claude can read your project files
- `/stop` kills a long-running Claude task
- `/model claude-opus-4-6` switches models (whitelisted)
- `/clear` resets conversation history
- Rate limiting + access control built in
- `CLAUDE_WORK_DIR` sets which project Claude works in
- Hourly status reports + web dashboard at `localhost:8080`

---

## API Reference

### ChannelManager

| Method | Description |
|--------|-------------|
| `add_channel(adapter)` | Register a channel adapter |
| `add_middleware(mw)` | Add middleware to the pipeline |
| `on_message(handler)` | Set fallback handler (decorator) |
| `await send(channel, chat_id, text, ...)` | Send to specific channel + chat |
| `await broadcast(text, chat_ids)` | Send to multiple channels |
| `await get_status()` | Get status of all channels |
| `await run()` | Start all channels (blocks) |
| `await shutdown()` | Stop all channels |

### CommandMiddleware

| Method | Description |
|--------|-------------|
| `@command(name)` | Decorator to register a command handler |
| `register(name, handler)` | Register handler programmatically |
| `registered_commands` | List of registered command names |

### AccessMiddleware

| Parameter | Description |
|-----------|-------------|
| `allowed_user_ids` | `set[str]` of allowed sender IDs. `None` = allow all |

### ConversationMemory

| Parameter | Description |
|-----------|-------------|
| `store` | `MemoryStore` backend (`InMemoryStore`, `SQLiteStore`, `RedisStore`). Default: `InMemoryStore()` |
| `max_turns` | Max history entries to keep per chat. Default: `50` |

### RichReply

| Method | Description |
|--------|-------------|
| `add_text(text)` | Append a text section |
| `add_table(headers, rows)` | Append an ASCII/rich table |
| `add_buttons(buttons)` | Append a button grid (`list[list[Button]]`) |
| `add_image(url, alt)` | Append an image |
| `add_code(code, language)` | Append a code block |
| `add_divider()` | Append a visual divider |
| `to_plain_text()` | Render as plain text (universal fallback) |
| `to_telegram()` | Render as Telegram Markdown + inline_keyboard |
| `to_discord()` | Render as Discord embeds + components |
| `to_slack()` | Render as Slack blocks |
| `to_outbound(channel)` | Auto-select best format for the channel |

### StreamingMiddleware

| Parameter | Description |
|-----------|-------------|
| `typing_interval` | Seconds between typing indicator pings. Default: `3.0` |
| `chunk_delay` | Seconds between streamed chunks. Default: `0.5` |

### StreamingReply

| Method | Description |
|--------|-------------|
| `StreamingReply(chunks)` | Wrap an `AsyncIterator[str]` |
| `StreamingReply.from_llm(stream)` | Wrap an LLM streaming response |

### ServiceBridge

| Method | Description |
|--------|-------------|
| `ServiceBridge(manager, prefix="/")` | Create a bridge wrapping a `ChannelManager` |
| `expose(name, handler, description, params)` | Expose a function as a chat command |
| `expose_status(handler)` | Register `/status` command |
| `expose_logs(handler)` | Register `/logs` command |
| `await run()` | Start the bridge (delegates to `manager.run()`) |

### load_config

| Function | Description |
|----------|-------------|
| `load_config(path)` | Load a YAML config file, return a configured `ChannelManager` |

### Adapters

| Adapter | Install Extra | Mode | Needs Public URL |
|---------|--------------|------|-----------------|
| `TelegramAdapter` | `telegram` | Polling | No |
| `DiscordAdapter` | `discord` | WebSocket | No |
| `SlackAdapter` | `slack` | Socket Mode | No |
| `WhatsAppAdapter` | `whatsapp` | Webhook | **Yes** |
| `IMessageAdapter` | *(none)* | DB polling | No (macOS only) |
| `LineAdapter` | `line` | Webhook | **Yes** |
| `MatrixAdapter` | `matrix` | Sync | No |
| `MSTeamsAdapter` | `msteams` | Webhook | **Yes** |
| `FeishuAdapter` | `feishu` | Webhook | **Yes** |
| `MattermostAdapter` | `mattermost` | WebSocket | No |
| `GoogleChatAdapter` | `googlechat` | Webhook | **Yes** |
| `NextcloudTalkAdapter` | `nextcloud` | Polling | No |
| `SynologyChatAdapter` | `synology` | Webhook | **Yes** |
| `ZaloAdapter` | `zalo` | Webhook | **Yes** |
| `NostrAdapter` | `nostr` | WebSocket (relay) | No |
| `BlueBubblesAdapter` | `bluebubbles` | Polling | No |
| `TwitchAdapter` | `twitch` | IRC/WebSocket | No |
| `IRCAdapter` | *(none)* | TCP socket | No |

---

## Testing

127 tests covering every layer of the stack. Run with:

```bash
pip install -e ".[dev]"
pytest -v
```

### Test Structure

| File | Tests | What it covers |
|------|-------|----------------|
| `test_types.py` | 14 | All data types — `ContentType`, `Identity`, `MessageContent`, `UnifiedMessage`, `OutboundMessage`, `Button`, `ChannelStatus`. Defaults, full construction, edge cases. |
| `test_adapter.py` | 5 | `ChannelAdapter` base class — connect/disconnect lifecycle, `receive()` async iterator, `send()` return value, `run_forever()` cancel behavior, abstract instantiation guard. |
| `test_middleware.py` | 7 | `AccessMiddleware` — allow, block, no-allowlist passthrough. `CommandMiddleware` — routing, passthrough, args parsing, `registered_commands` property. |
| `test_manager.py` | 4 | Core `ChannelManager` pipeline — command end-to-end, access control blocking, fallback handler, `get_status()`. |
| `test_manager_advanced.py` | 14 | Multi-channel routing, `OutboundMessage` return, `send()` direct push, unknown channel error, `broadcast()`, middleware chain order verification, short-circuit, no-reply/null-reply cases, auth+commands combo, fluent API chaining, no-channels guard. |
| `test_adapters_unit.py` | 32 | Per-adapter unit tests with mocked SDKs: **IRC** (PRIVMSG parsing, commands, self-ignore, DM routing), **iMessage** (macOS-only), **WhatsApp** (text/command/image/reaction/reply-context), **Mattermost** (text/command/self-ignore/threads), **Twitch** (text/commands/self-ignore/IRC tags), **Zalo** (text/commands), **BlueBubbles/Synology/Nextcloud** (channel_id, status). Lazy import verification for all 18 adapter names. |
| `test_bridge.py` | 12 | `ServiceBridge` — expose commands, sync/async handlers, args/flag parsing, `/help` generation, `/status` + `/logs` shortcuts, error handling, handler signature detection. |
| `test_config.py` | 8 | YAML config loading — env var interpolation (basic, embedded, missing, non-string), nested dict interpolation, full config parse with mocked adapter, empty file error, missing PyYAML error. |
| `test_memory.py` | 12 | `InMemoryStore` CRUD (empty, append, trim, clear, isolation). `ConversationMemory` middleware (history injection, user+reply saving, no-reply, max_turns trimming, separate chats). `SQLiteStore` (CRUD, persistence across reopens). |
| `test_rich.py` | 12 | Fluent API chaining, plain text rendering (basic, table, buttons, code), Telegram output (Markdown + inline_keyboard), Discord embeds, Slack blocks, `to_outbound` channel selection (telegram, discord, unknown), empty reply. |
| `test_streaming.py` | 7 | `StreamingReply` chunk collection and `from_llm`. `StreamingMiddleware` typing task lifecycle (creation, cancellation, exception safety), streaming reply assembly, no-adapter fallback, adapter typing during chunks. |

### What's tested per adapter

Adapters that require external SDKs (Telegram, Discord, Slack, LINE, Matrix, MS Teams, Feishu, Google Chat, Nostr) are tested through:
1. **Lazy import** — verified they're registered in `__all__` and loadable via `__getattr__`
2. **Message parsing** — tested where possible without SDK (WhatsApp, Mattermost, Zalo parse raw dicts)
3. **Integration** — the `MockAdapter` in manager tests validates the full adapter protocol

Adapters with no external deps (IRC, iMessage) have **direct unit tests** for message parsing, command detection, self-message filtering, and DM routing.

### Running specific tests

```bash
# Just adapter tests
pytest tests/test_adapters_unit.py -v

# Just manager pipeline
pytest tests/test_manager.py tests/test_manager_advanced.py -v

# Single test
pytest tests/test_adapters_unit.py::TestTwitchParsing::test_process_command -v
```

---

## License

MIT
