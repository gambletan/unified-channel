# unified-channel

### The missing messaging layer for AI Agents

Give your AI agent a voice on **every platform** — Telegram, Discord, Slack, WhatsApp, and 15 more — with a single unified API. No per-platform glue code. No message format translation. Just plug in your agent and go.

Built for the agent era: connect your LLM, autonomous agent, or copilot to real users on the channels they already use. Ship once, deploy everywhere.

**Unified message middleware for Python.** One API to receive and send messages across **19 channels** — Telegram, Discord, Slack, WhatsApp, iMessage, LINE, Matrix, MS Teams, Feishu, Mattermost, Google Chat, Twitch, IRC, Nostr, Zalo, BlueBubbles, Nextcloud Talk, and Synology Chat.

Middleware pipeline, access control, and command routing — all built in. Adding a new channel = **1 file**, implementing 5 methods.

```
pip install unified-channel[telegram]
```

## Architecture

```
                         +-----------------------+
                         |    Your AI Agent /    |
                         |    Application        |
                         +-----------+-----------+
                                     |
                                     v
                         +-----------+-----------+
                         |   ChannelManager      |
                         |   (orchestrator)      |
                         +-----------+-----------+
                                     |
                     +---------------+---------------+
                     |               |               |
                     v               v               v
              +------+------+ +-----+-----+ +-------+------+
              | Middleware   | | Middleware | | Middleware    |
              | (Auth)      | | (Commands) | | (Rate Limit) |
              +------+------+ +-----+-----+ +-------+------+
                     |               |               |
                     +-------+-------+-------+-------+
                             |               |
          +------------------+------------------+------------------+
          |          |           |          |           |          |
          v          v           v          v           v          v
     +--------+ +--------+ +-------+ +--------+ +--------+ +-----+
     |Telegram| |Discord | | Slack | |WhatsApp| | Matrix | | ... |
     +--------+ +--------+ +-------+ +--------+ +--------+ +-----+
```

Messages flow in from any adapter, pass through the middleware pipeline, and replies route back through the same adapter. Your agent code never touches platform-specific APIs.

## Also Available In

| Language | Repository | Status |
|----------|-----------|--------|
| **Python** | [gambletan/unified-channel](https://github.com/gambletan/unified-channel) | Active |
| TypeScript | *Coming soon* | Planned |
| Java | *Coming soon* | Planned |

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
  - [Custom Middleware](#custom-middleware)
  - [Middleware Chain Order](#middleware-chain-order)
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

96 tests covering every layer of the stack. Run with:

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
