"""
unified-channel MCP Server (Python)

Exposes messaging channels as MCP tools for AI agents.
Uses the unified_channel Python package for channel adapters.

Supports 18 channels: Telegram, Discord, Slack, Mattermost, IRC,
WhatsApp, LINE, Feishu/Lark, MS Teams, Google Chat, Synology Chat,
Zalo, Nostr, Twitch, BlueBubbles, Nextcloud Talk, iMessage, Matrix.

Usage:
    UC_TELEGRAM_TOKEN=... unified-channel-mcp
    UC_CONFIG_PATH=./unified-channel.yaml unified-channel-mcp
    UC_TELEGRAM_TOKEN=... python -m unified_channel_mcp
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from unified_channel import ChannelManager, ChannelStatus, OutboundMessage
from unified_channel.config import _ADAPTER_MAP, _interpolate_dict, _make_adapter

logger = logging.getLogger("unified-channel-mcp")

# All 18 supported channels
ALL_CHANNELS = [
    "telegram", "discord", "slack", "mattermost", "irc",
    "whatsapp", "line", "feishu", "msteams", "googlechat",
    "synology", "zalo", "nostr", "twitch",
    "bluebubbles", "nextcloud", "imessage", "matrix",
]

# Environment variable mapping: channel -> list of (env_var, kwarg_name) pairs
# When all required env vars are present, the adapter is created with these kwargs.
_ENV_CHANNEL_MAP: dict[str, list[tuple[str, str]]] = {
    "telegram": [("UC_TELEGRAM_TOKEN", "token")],
    "discord": [("UC_DISCORD_TOKEN", "token")],
    "slack": [("UC_SLACK_BOT_TOKEN", "bot_token"), ("UC_SLACK_APP_TOKEN", "app_token")],
    "mattermost": [("UC_MATTERMOST_URL", "url"), ("UC_MATTERMOST_TOKEN", "token")],
    "irc": [("UC_IRC_SERVER", "server"), ("UC_IRC_NICK", "nick"), ("UC_IRC_CHANNELS", "channels")],
    "whatsapp": [("UC_WHATSAPP_TOKEN", "token"), ("UC_WHATSAPP_PHONE_ID", "phone_id")],
    "line": [("UC_LINE_CHANNEL_SECRET", "channel_secret"), ("UC_LINE_CHANNEL_ACCESS_TOKEN", "channel_access_token")],
    "feishu": [("UC_FEISHU_APP_ID", "app_id"), ("UC_FEISHU_APP_SECRET", "app_secret")],
    "msteams": [("UC_MSTEAMS_APP_ID", "app_id"), ("UC_MSTEAMS_APP_PASSWORD", "app_password")],
    "googlechat": [("UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY", "service_account_key_path")],
    "synology": [("UC_SYNOLOGY_URL", "url"), ("UC_SYNOLOGY_INCOMING_TOKEN", "incoming_token"), ("UC_SYNOLOGY_OUTGOING_URL", "outgoing_url")],
    "zalo": [("UC_ZALO_ACCESS_TOKEN", "access_token")],
    "nostr": [("UC_NOSTR_PRIVATE_KEY", "private_key"), ("UC_NOSTR_RELAYS", "relays")],
    "twitch": [("UC_TWITCH_USERNAME", "username"), ("UC_TWITCH_OAUTH", "oauth"), ("UC_TWITCH_CHANNELS", "channels")],
    "bluebubbles": [("UC_BLUEBUBBLES_URL", "url"), ("UC_BLUEBUBBLES_PASSWORD", "password")],
    "nextcloud": [("UC_NEXTCLOUD_URL", "url"), ("UC_NEXTCLOUD_USER", "user"), ("UC_NEXTCLOUD_PASSWORD", "password"), ("UC_NEXTCLOUD_ROOMS", "rooms")],
    "imessage": [("UC_IMESSAGE_ENABLED", "_enabled")],
    "matrix": [("UC_MATRIX_HOMESERVER", "homeserver"), ("UC_MATRIX_TOKEN", "token")],
}

# Optional extra env vars per channel (env_var, kwarg_name, default, type)
_ENV_OPTIONAL: dict[str, list[tuple[str, str, str, type]]] = {
    "irc": [("UC_IRC_PORT", "port", "6667", int)],
    "whatsapp": [
        ("UC_WHATSAPP_VERIFY_TOKEN", "verify_token", "verify", str),
        ("UC_WHATSAPP_PORT", "port", "9000", int),
    ],
    "line": [("UC_LINE_PORT", "port", "9001", int)],
    "feishu": [("UC_FEISHU_PORT", "port", "9002", int)],
    "msteams": [("UC_MSTEAMS_PORT", "port", "9003", int)],
    "googlechat": [("UC_GOOGLECHAT_PORT", "port", "9004", int)],
    "synology": [("UC_SYNOLOGY_PORT", "port", "9005", int)],
    "zalo": [("UC_ZALO_PORT", "port", "9006", int)],
}


@dataclass
class BufferedMessage:
    id: str
    channel: str
    sender: str
    text: str
    timestamp: str
    chat_id: str


class UnifiedChannelMCP:
    """MCP server wrapping the unified-channel ChannelManager."""

    def __init__(self) -> None:
        self.manager = ChannelManager()
        self.message_buffer: deque[BufferedMessage] = deque(maxlen=200)
        self.server = Server("unified-channel")
        self._register_handlers()

    def _register_handlers(self) -> None:
        server = self.server

        @server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="send_message",
                    description=(
                        "Send a message to a user/chat on any connected channel "
                        "(Telegram, Discord, Slack, WhatsApp, Matrix, etc.)"
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "channel": {
                                "type": "string",
                                "description": f"Channel to send on: {', '.join(ALL_CHANNELS)}",
                            },
                            "chat_id": {
                                "type": "string",
                                "description": "Chat/channel/room ID to send the message to",
                            },
                            "text": {
                                "type": "string",
                                "description": "Message text to send",
                            },
                            "reply_to_id": {
                                "type": "string",
                                "description": "Optional message ID to reply to",
                            },
                        },
                        "required": ["channel", "chat_id", "text"],
                    },
                ),
                Tool(
                    name="broadcast_message",
                    description="Send the same message to multiple channels at once",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Message text to broadcast",
                            },
                            "targets": {
                                "type": "object",
                                "description": (
                                    "Map of channel name to chat ID, "
                                    "e.g. {\"telegram\": \"123\", \"discord\": \"456\"}"
                                ),
                                "additionalProperties": {"type": "string"},
                            },
                        },
                        "required": ["text", "targets"],
                    },
                ),
                Tool(
                    name="get_channel_status",
                    description="Check the connection status of all configured channels",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="list_channels",
                    description="List all 18 supported channel types and which ones are currently connected",
                    inputSchema={"type": "object", "properties": {}},
                ),
                Tool(
                    name="get_recent_messages",
                    description="Get recent messages received across all connected channels",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "number",
                                "description": "Max messages to return (default 20)",
                            },
                            "channel": {
                                "type": "string",
                                "description": "Filter by channel name",
                            },
                        },
                    },
                ),
                Tool(
                    name="load_config",
                    description="Load channel configuration from a YAML file",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to unified-channel.yaml config file",
                            },
                        },
                        "required": ["path"],
                    },
                ),
            ]

        @server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            try:
                match name:
                    case "send_message":
                        return await self._handle_send_message(arguments)
                    case "broadcast_message":
                        return await self._handle_broadcast_message(arguments)
                    case "get_channel_status":
                        return await self._handle_get_channel_status()
                    case "list_channels":
                        return await self._handle_list_channels()
                    case "get_recent_messages":
                        return await self._handle_get_recent_messages(arguments)
                    case "load_config":
                        return await self._handle_load_config(arguments)
                    case _:
                        return [TextContent(type="text", text=f"Unknown tool: {name}")]
            except Exception as e:
                return [TextContent(type="text", text=f"Error: {e}")]

    @property
    def _connected_channels(self) -> list[str]:
        return list(self.manager._channels.keys())

    async def _handle_send_message(self, args: dict[str, Any]) -> list[TextContent]:
        channel = args["channel"]
        chat_id = args["chat_id"]
        text = args["text"]
        reply_to_id = args.get("reply_to_id")

        if channel not in self.manager._channels:
            connected = ", ".join(self._connected_channels) or "none"
            return [TextContent(
                type="text",
                text=f'Channel "{channel}" is not connected. Connected: {connected}',
            )]

        try:
            msg_id = await self.manager.send(
                channel, chat_id, text, reply_to_id=reply_to_id,
            )
            return [TextContent(
                type="text",
                text=f"Sent on {channel} to {chat_id}. ID: {msg_id or 'unknown'}",
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed: {e}")]

    async def _handle_broadcast_message(self, args: dict[str, Any]) -> list[TextContent]:
        text = args["text"]
        targets: dict[str, str] = args["targets"]
        results: list[str] = []

        for ch, chat_id in targets.items():
            if ch not in self.manager._channels:
                results.append(f"{ch}: not connected")
                continue
            try:
                await self.manager.send(ch, chat_id, text)
                results.append(f"{ch}: sent")
            except Exception as e:
                results.append(f"{ch}: failed ({e})")

        return [TextContent(type="text", text="\n".join(results))]

    async def _handle_get_channel_status(self) -> list[TextContent]:
        if not self.manager._channels:
            return [TextContent(
                type="text",
                text=(
                    "No channels configured. Set UC_TELEGRAM_TOKEN, "
                    "UC_DISCORD_TOKEN, etc. or use load_config."
                ),
            )]

        lines: list[str] = []
        statuses = await self.manager.get_status()
        for name, status in statuses.items():
            if isinstance(status, ChannelStatus):
                marker = "\u25cf" if status.connected else "\u25cb"
                account = f" ({status.account_id})" if status.account_id else ""
                last = f" -- last: {status.last_activity.isoformat()}" if status.last_activity else ""
                lines.append(f"{marker} {name}{account}{last}")
            elif isinstance(status, dict):
                connected = status.get("connected", False)
                marker = "\u25cf" if connected else "\u25cb"
                error = status.get("error", "")
                lines.append(f"{marker} {name}" + (f": {error}" if error else ""))
            else:
                lines.append(f"? {name}")

        return [TextContent(type="text", text="\n".join(lines))]

    async def _handle_list_channels(self) -> list[TextContent]:
        connected = set(self._connected_channels)
        lines = []
        for ch in ALL_CHANNELS:
            marker = "\u25cf" if ch in connected else "\u25cb"
            suffix = " (connected)" if ch in connected else ""
            lines.append(f"{marker} {ch}{suffix}")
        summary = f"\nConnected: {len(connected)}/{len(ALL_CHANNELS)}"
        return [TextContent(type="text", text="Channels:\n" + "\n".join(lines) + summary)]

    async def _handle_get_recent_messages(self, args: dict[str, Any]) -> list[TextContent]:
        limit = int(args.get("limit", 20))
        channel_filter = args.get("channel")

        msgs = list(self.message_buffer)
        if channel_filter:
            msgs = [m for m in msgs if m.channel == channel_filter]
        msgs = msgs[-limit:]

        if not msgs:
            return [TextContent(type="text", text="No recent messages.")]

        formatted = "\n".join(
            f"[{m.timestamp}] {m.channel}/{m.chat_id} @{m.sender}: {m.text}"
            for m in msgs
        )
        return [TextContent(type="text", text=formatted)]

    async def _handle_load_config(self, args: dict[str, Any]) -> list[TextContent]:
        config_path = args["path"]
        try:
            import yaml
        except ImportError:
            return [TextContent(
                type="text",
                text="PyYAML is required: pip install pyyaml",
            )]

        try:
            with open(config_path) as f:
                raw = yaml.safe_load(f)

            if not raw:
                return [TextContent(type="text", text="No channels found in config file.")]

            channels_cfg = raw.get("channels", {})
            if not channels_cfg:
                return [TextContent(type="text", text="No channels found in config file.")]

            count = 0
            for name, adapter_cfg in channels_cfg.items():
                if name in self.manager._channels:
                    logger.info("Skipping %s (already connected)", name)
                    continue
                try:
                    resolved = _interpolate_dict(adapter_cfg or {})
                    adapter = _make_adapter(name, resolved)
                    self.manager.add_channel(adapter)
                    await adapter.connect()
                    count += 1
                    logger.info("%s connected", name)
                except Exception as e:
                    logger.error("Failed to connect %s: %s", name, e)

            connected = ", ".join(self._connected_channels) or "none"
            return [TextContent(
                type="text",
                text=f"Loaded {len(channels_cfg)} channel(s) from {config_path}. Connected: {connected}",
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Failed to load config: {e}")]

    def _create_adapters_from_env(self) -> list[tuple[str, dict[str, Any]]]:
        """Parse UC_* environment variables and return adapter configs."""
        result: list[tuple[str, dict[str, Any]]] = []

        for channel, env_pairs in _ENV_CHANNEL_MAP.items():
            # Special case: iMessage needs UC_IMESSAGE_ENABLED=1
            if channel == "imessage":
                if os.environ.get("UC_IMESSAGE_ENABLED") == "1":
                    result.append((channel, {}))
                continue

            # Check all required env vars
            kwargs: dict[str, Any] = {}
            all_present = True
            for env_var, kwarg_name in env_pairs:
                value = os.environ.get(env_var)
                if not value:
                    all_present = False
                    break
                # Handle comma-separated list values
                if kwarg_name in ("channels", "rooms", "relays"):
                    kwargs[kwarg_name] = value.split(",")
                else:
                    kwargs[kwarg_name] = value

            if not all_present:
                continue

            # Add optional env vars
            for env_var, kwarg_name, default, cast in _ENV_OPTIONAL.get(channel, []):
                value = os.environ.get(env_var, default)
                kwargs[kwarg_name] = cast(value)

            result.append((channel, kwargs))

        return result

    async def connect_from_env(self) -> None:
        """Auto-connect channels configured via UC_* environment variables."""
        # Load from UC_CONFIG_PATH first
        config_path = os.environ.get("UC_CONFIG_PATH")
        if config_path:
            try:
                import yaml
                with open(config_path) as f:
                    raw = yaml.safe_load(f)
                channels_cfg = (raw or {}).get("channels", {})
                for name, adapter_cfg in channels_cfg.items():
                    if name in self.manager._channels:
                        continue
                    try:
                        resolved = _interpolate_dict(adapter_cfg or {})
                        adapter = _make_adapter(name, resolved)
                        self.manager.add_channel(adapter)
                        await adapter.connect()
                        logger.info("%s connected (from config)", name)
                    except Exception as e:
                        logger.error("Failed to connect %s: %s", name, e)
            except Exception as e:
                logger.error("Failed to load config from %s: %s", config_path, e)

        # Then load from env vars
        for channel, kwargs in self._create_adapters_from_env():
            if channel in self.manager._channels:
                logger.info("Skipping %s (already connected)", channel)
                continue
            try:
                adapter = _make_adapter(channel, kwargs)
                self.manager.add_channel(adapter)
                await adapter.connect()
                logger.info("%s connected (from env)", channel)
            except Exception as e:
                logger.error("Failed to connect %s: %s", channel, e)

        if not self.manager._channels:
            logger.warning(
                "No channels configured. Set UC_TELEGRAM_TOKEN, "
                "UC_DISCORD_TOKEN, etc. or UC_CONFIG_PATH."
            )

    async def _start_message_consumers(self) -> None:
        """Start background tasks to consume messages from connected channels."""
        for channel_id, adapter in self.manager._channels.items():
            asyncio.create_task(
                self._consume_messages(channel_id, adapter),
                name=f"consume:{channel_id}",
            )

    async def _consume_messages(self, channel_id: str, adapter: Any) -> None:
        """Consume messages from one adapter and buffer them."""
        try:
            async for msg in adapter.receive():
                sender = msg.sender.username or msg.sender.id or "unknown"
                self.message_buffer.append(BufferedMessage(
                    id=msg.id,
                    channel=msg.channel,
                    sender=sender,
                    text=msg.content.text or "",
                    timestamp=datetime.now().isoformat(),
                    chat_id=msg.chat_id or "",
                ))
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Message consumer for %s crashed", channel_id)

    async def run(self) -> None:
        """Start the MCP server with stdio transport."""
        # Connect channels from environment
        await self.connect_from_env()

        # Start message consumers for connected channels
        await self._start_message_consumers()

        channel_count = len(self.manager._channels)
        logger.info("MCP server running (%d channels)", channel_count)

        # Run MCP server via stdio
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


def main() -> None:
    """Entry point for the MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="[unified-channel] %(message)s",
        stream=sys.stderr,
    )
    asyncio.run(_async_main())


async def _async_main() -> None:
    mcp = UnifiedChannelMCP()
    await mcp.run()
