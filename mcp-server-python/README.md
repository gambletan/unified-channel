# unified-channel MCP Server (Python)

MCP (Model Context Protocol) server that exposes unified-channel messaging as tools for AI agents.

Supports 18 channels: Telegram, Discord, Slack, Mattermost, IRC, WhatsApp, LINE, Feishu/Lark, MS Teams, Google Chat, Synology Chat, Zalo, Nostr, Twitch, BlueBubbles, Nextcloud Talk, iMessage, Matrix.

## Installation

```bash
cd mcp-server-python
pip install -e .
```

For specific channel adapters, also install the channel's dependencies:

```bash
pip install unified-channel[telegram]   # Telegram
pip install unified-channel[discord]    # Discord
pip install unified-channel[slack]      # Slack
pip install unified-channel[all]        # All channels
```

## Usage

### Via environment variables

```bash
UC_TELEGRAM_TOKEN=your-bot-token unified-channel-mcp
```

### Via YAML config

```bash
UC_CONFIG_PATH=./unified-channel.yaml unified-channel-mcp
```

### As a Python module

```bash
UC_TELEGRAM_TOKEN=your-bot-token python -m unified_channel_mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unified-channel": {
      "command": "unified-channel-mcp",
      "env": {
        "UC_TELEGRAM_TOKEN": "your-bot-token",
        "UC_DISCORD_TOKEN": "your-discord-token"
      }
    }
  }
}
```

Or with a config file:

```json
{
  "mcpServers": {
    "unified-channel": {
      "command": "unified-channel-mcp",
      "env": {
        "UC_CONFIG_PATH": "/path/to/unified-channel.yaml"
      }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `send_message` | Send a message to a user/chat on any connected channel |
| `broadcast_message` | Send the same message to multiple channels at once |
| `get_channel_status` | Check connection status of all configured channels |
| `list_channels` | List all 18 supported channels and connection status |
| `get_recent_messages` | Get recent messages (with optional limit and channel filter) |
| `load_config` | Load channel config from a YAML file at runtime |

## Environment Variables

| Variable | Channel | Description |
|----------|---------|-------------|
| `UC_TELEGRAM_TOKEN` | Telegram | Bot token from @BotFather |
| `UC_DISCORD_TOKEN` | Discord | Bot token |
| `UC_SLACK_BOT_TOKEN` | Slack | Bot token (xoxb-...) |
| `UC_SLACK_APP_TOKEN` | Slack | App token (xapp-...) |
| `UC_MATTERMOST_URL` | Mattermost | Server URL |
| `UC_MATTERMOST_TOKEN` | Mattermost | Access token |
| `UC_IRC_SERVER` | IRC | Server hostname |
| `UC_IRC_NICK` | IRC | Nickname |
| `UC_IRC_CHANNELS` | IRC | Comma-separated channels |
| `UC_IRC_PORT` | IRC | Port (default 6667) |
| `UC_WHATSAPP_TOKEN` | WhatsApp | Cloud API token |
| `UC_WHATSAPP_PHONE_ID` | WhatsApp | Phone number ID |
| `UC_WHATSAPP_VERIFY_TOKEN` | WhatsApp | Webhook verify token |
| `UC_WHATSAPP_PORT` | WhatsApp | Webhook port (default 9000) |
| `UC_LINE_CHANNEL_SECRET` | LINE | Channel secret |
| `UC_LINE_CHANNEL_ACCESS_TOKEN` | LINE | Channel access token |
| `UC_LINE_PORT` | LINE | Webhook port (default 9001) |
| `UC_FEISHU_APP_ID` | Feishu | App ID |
| `UC_FEISHU_APP_SECRET` | Feishu | App secret |
| `UC_FEISHU_PORT` | Feishu | Webhook port (default 9002) |
| `UC_MSTEAMS_APP_ID` | MS Teams | App ID |
| `UC_MSTEAMS_APP_PASSWORD` | MS Teams | App password |
| `UC_MSTEAMS_PORT` | MS Teams | Webhook port (default 9003) |
| `UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY` | Google Chat | Path to service account JSON |
| `UC_GOOGLECHAT_PORT` | Google Chat | Webhook port (default 9004) |
| `UC_SYNOLOGY_URL` | Synology | Server URL |
| `UC_SYNOLOGY_INCOMING_TOKEN` | Synology | Incoming webhook token |
| `UC_SYNOLOGY_OUTGOING_URL` | Synology | Outgoing webhook URL |
| `UC_SYNOLOGY_PORT` | Synology | Webhook port (default 9005) |
| `UC_ZALO_ACCESS_TOKEN` | Zalo | OA access token |
| `UC_ZALO_PORT` | Zalo | Webhook port (default 9006) |
| `UC_NOSTR_PRIVATE_KEY` | Nostr | Private key (hex) |
| `UC_NOSTR_RELAYS` | Nostr | Comma-separated relay URLs |
| `UC_TWITCH_USERNAME` | Twitch | Username |
| `UC_TWITCH_OAUTH` | Twitch | OAuth token |
| `UC_TWITCH_CHANNELS` | Twitch | Comma-separated channels |
| `UC_BLUEBUBBLES_URL` | BlueBubbles | Server URL |
| `UC_BLUEBUBBLES_PASSWORD` | BlueBubbles | Server password |
| `UC_NEXTCLOUD_URL` | Nextcloud | Server URL |
| `UC_NEXTCLOUD_USER` | Nextcloud | Username |
| `UC_NEXTCLOUD_PASSWORD` | Nextcloud | Password/app token |
| `UC_NEXTCLOUD_ROOMS` | Nextcloud | Comma-separated room tokens |
| `UC_IMESSAGE_ENABLED` | iMessage | Set to "1" (macOS only) |
| `UC_MATRIX_HOMESERVER` | Matrix | Homeserver URL |
| `UC_MATRIX_TOKEN` | Matrix | Access token |
| `UC_CONFIG_PATH` | (all) | Path to YAML config file |
