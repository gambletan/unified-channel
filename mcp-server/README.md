# unified-channel MCP Server

> Let AI agents send and receive messages across 18 channels via MCP protocol.

This MCP server wraps [unified-channel](https://github.com/gambletan/unified-channel) to expose messaging capabilities as tools that any MCP-compatible AI agent can use.

## Quick Setup

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unified-channel": {
      "command": "npx",
      "args": ["@unified-channel/mcp-server"],
      "env": {
        "UC_TELEGRAM_TOKEN": "your-telegram-bot-token",
        "UC_DISCORD_TOKEN": "your-discord-bot-token"
      }
    }
  }
}
```

### Any MCP Client

```bash
UC_TELEGRAM_TOKEN=... npx @unified-channel/mcp-server
```

### YAML Config

Create a `unified-channel.yaml` file:

```yaml
channels:
  telegram:
    token: "BOT_TOKEN"
  discord:
    token: "BOT_TOKEN"
  slack:
    bot_token: "xoxb-..."
    app_token: "xapp-..."
  matrix:
    homeserver: "https://matrix.org"
    token: "syt_..."
```

Then either:
- Set `UC_CONFIG_PATH=./unified-channel.yaml` to load at startup
- Use the `load_config` tool to load dynamically at runtime

## Available Tools

| Tool | Description |
|------|-------------|
| `send_message` | Send a message to a specific channel/chat |
| `broadcast_message` | Send the same message to multiple channels |
| `get_channel_status` | Check connection status of all channels |
| `list_channels` | List all 18 supported channels and their status |
| `get_recent_messages` | Get recent messages received across channels |
| `load_config` | Load channel configuration from a YAML file |

## Supported Channels (18)

| Channel | Type | Required Env Vars |
|---------|------|-------------------|
| Telegram | Bot API (grammy) | `UC_TELEGRAM_TOKEN` |
| Discord | Bot (discord.js) | `UC_DISCORD_TOKEN` |
| Slack | Socket Mode (@slack/bolt) | `UC_SLACK_BOT_TOKEN` + `UC_SLACK_APP_TOKEN` |
| Mattermost | WebSocket + REST | `UC_MATTERMOST_URL` + `UC_MATTERMOST_TOKEN` |
| IRC | Raw socket | `UC_IRC_SERVER` + `UC_IRC_NICK` + `UC_IRC_CHANNELS` (+ optional `UC_IRC_PORT`) |
| WhatsApp | Meta Cloud API webhook | `UC_WHATSAPP_TOKEN` + `UC_WHATSAPP_PHONE_ID` (+ optional `UC_WHATSAPP_VERIFY_TOKEN`, `UC_WHATSAPP_PORT` default 9000) |
| LINE | Webhook + REST | `UC_LINE_CHANNEL_SECRET` + `UC_LINE_CHANNEL_ACCESS_TOKEN` (+ optional `UC_LINE_PORT` default 9001) |
| Feishu/Lark | Webhook + REST | `UC_FEISHU_APP_ID` + `UC_FEISHU_APP_SECRET` (+ optional `UC_FEISHU_PORT` default 9002) |
| MS Teams | Bot Framework webhook | `UC_MSTEAMS_APP_ID` + `UC_MSTEAMS_APP_PASSWORD` (+ optional `UC_MSTEAMS_PORT` default 9003) |
| Google Chat | Webhook + service account | `UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY` (path to JSON) (+ optional `UC_GOOGLECHAT_PORT` default 9004) |
| Synology Chat | Webhook | `UC_SYNOLOGY_URL` + `UC_SYNOLOGY_INCOMING_TOKEN` + `UC_SYNOLOGY_OUTGOING_URL` (+ optional `UC_SYNOLOGY_PORT` default 9005) |
| Zalo | Webhook + REST | `UC_ZALO_ACCESS_TOKEN` (+ optional `UC_ZALO_PORT` default 9006) |
| Nostr | WebSocket relay | `UC_NOSTR_PRIVATE_KEY` + `UC_NOSTR_RELAYS` (comma-separated) |
| Twitch | IRC over WebSocket | `UC_TWITCH_USERNAME` + `UC_TWITCH_OAUTH` + `UC_TWITCH_CHANNELS` (comma-separated) |
| BlueBubbles | REST polling | `UC_BLUEBUBBLES_URL` + `UC_BLUEBUBBLES_PASSWORD` |
| Nextcloud Talk | REST polling | `UC_NEXTCLOUD_URL` + `UC_NEXTCLOUD_USER` + `UC_NEXTCLOUD_PASSWORD` + `UC_NEXTCLOUD_ROOMS` (comma-separated) |
| iMessage | macOS sqlite3 + osascript | `UC_IMESSAGE_ENABLED=1` (macOS only, no other env vars needed) |
| Matrix | HTTP long-poll /sync | `UC_MATRIX_HOMESERVER` + `UC_MATRIX_TOKEN` |

Set `UC_CONFIG_PATH` to load channels from a YAML file instead of (or in addition to) env vars.

## Environment Variables (Full Reference)

| Variable | Description |
|----------|-------------|
| `UC_CONFIG_PATH` | Path to `unified-channel.yaml` config file (loaded at startup) |
| **Telegram** | |
| `UC_TELEGRAM_TOKEN` | Telegram Bot API token |
| **Discord** | |
| `UC_DISCORD_TOKEN` | Discord bot token |
| **Slack** | |
| `UC_SLACK_BOT_TOKEN` | Slack bot token (`xoxb-...`) |
| `UC_SLACK_APP_TOKEN` | Slack app-level token (`xapp-...`) for Socket Mode |
| **Mattermost** | |
| `UC_MATTERMOST_URL` | Mattermost server URL |
| `UC_MATTERMOST_TOKEN` | Mattermost personal access token |
| **IRC** | |
| `UC_IRC_SERVER` | IRC server hostname |
| `UC_IRC_NICK` | IRC nickname |
| `UC_IRC_CHANNELS` | Comma-separated IRC channels (e.g. `#general,#dev`) |
| `UC_IRC_PORT` | IRC port (default `6667`) |
| **WhatsApp** | |
| `UC_WHATSAPP_TOKEN` | Meta Cloud API access token |
| `UC_WHATSAPP_PHONE_ID` | WhatsApp phone number ID |
| `UC_WHATSAPP_VERIFY_TOKEN` | Webhook verification token (default `verify`) |
| `UC_WHATSAPP_PORT` | Webhook server port (default `9000`) |
| **LINE** | |
| `UC_LINE_CHANNEL_SECRET` | LINE channel secret |
| `UC_LINE_CHANNEL_ACCESS_TOKEN` | LINE channel access token |
| `UC_LINE_PORT` | Webhook server port (default `9001`) |
| **Feishu/Lark** | |
| `UC_FEISHU_APP_ID` | Feishu app ID |
| `UC_FEISHU_APP_SECRET` | Feishu app secret |
| `UC_FEISHU_PORT` | Webhook server port (default `9002`) |
| **MS Teams** | |
| `UC_MSTEAMS_APP_ID` | Azure Bot app ID |
| `UC_MSTEAMS_APP_PASSWORD` | Azure Bot app password |
| `UC_MSTEAMS_PORT` | Webhook server port (default `9003`) |
| **Google Chat** | |
| `UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY` | Path to service account JSON key file |
| `UC_GOOGLECHAT_PORT` | Webhook server port (default `9004`) |
| **Synology Chat** | |
| `UC_SYNOLOGY_URL` | Synology Chat server URL |
| `UC_SYNOLOGY_INCOMING_TOKEN` | Incoming webhook token |
| `UC_SYNOLOGY_OUTGOING_URL` | Outgoing webhook URL |
| `UC_SYNOLOGY_PORT` | Webhook server port (default `9005`) |
| **Zalo** | |
| `UC_ZALO_ACCESS_TOKEN` | Zalo Official Account access token |
| `UC_ZALO_PORT` | Webhook server port (default `9006`) |
| **Nostr** | |
| `UC_NOSTR_PRIVATE_KEY` | Nostr private key (hex) |
| `UC_NOSTR_RELAYS` | Comma-separated relay WebSocket URLs |
| **Twitch** | |
| `UC_TWITCH_USERNAME` | Twitch bot username |
| `UC_TWITCH_OAUTH` | Twitch OAuth token (`oauth:...`) |
| `UC_TWITCH_CHANNELS` | Comma-separated Twitch channels |
| **BlueBubbles** | |
| `UC_BLUEBUBBLES_URL` | BlueBubbles server URL |
| `UC_BLUEBUBBLES_PASSWORD` | BlueBubbles server password |
| **Nextcloud Talk** | |
| `UC_NEXTCLOUD_URL` | Nextcloud server URL |
| `UC_NEXTCLOUD_USER` | Nextcloud username |
| `UC_NEXTCLOUD_PASSWORD` | Nextcloud password or app token |
| `UC_NEXTCLOUD_ROOMS` | Comma-separated room tokens |
| **iMessage** | |
| `UC_IMESSAGE_ENABLED` | Set to `1` to enable (macOS only) |
| **Matrix** | |
| `UC_MATRIX_HOMESERVER` | Matrix homeserver URL |
| `UC_MATRIX_TOKEN` | Matrix access token |

## YAML Config Format

```yaml
channels:
  telegram:
    token: "BOT_TOKEN"
  discord:
    token: "BOT_TOKEN"
  slack:
    bot_token: "xoxb-..."
    app_token: "xapp-..."
  mattermost:
    url: "https://mattermost.example.com"
    token: "ACCESS_TOKEN"
  irc:
    server: "irc.libera.chat"
    nick: "mybot"
    channels: "#general,#dev"
    port: "6667"
  whatsapp:
    token: "CLOUD_API_TOKEN"
    phone_id: "PHONE_NUMBER_ID"
    verify_token: "my-verify-token"
    port: "9000"
  line:
    channel_secret: "SECRET"
    channel_access_token: "TOKEN"
  feishu:
    app_id: "cli_..."
    app_secret: "SECRET"
  msteams:
    app_id: "APP_ID"
    app_password: "APP_PASSWORD"
  googlechat:
    service_account_key: "/path/to/key.json"
  synology:
    url: "https://nas.example.com:5001"
    incoming_token: "TOKEN"
    outgoing_url: "https://nas.example.com:5001/webapi/entry.cgi?..."
  zalo:
    access_token: "TOKEN"
  nostr:
    private_key: "HEX_PRIVATE_KEY"
    relays: "wss://relay.damus.io,wss://nos.lol"
  twitch:
    username: "mybot"
    oauth: "oauth:..."
    channels: "channel1,channel2"
  bluebubbles:
    url: "http://localhost:1234"
    password: "PASSWORD"
  nextcloud:
    url: "https://cloud.example.com"
    user: "bot"
    password: "APP_TOKEN"
    rooms: "room1,room2"
  imessage:
    enabled: "1"
  matrix:
    homeserver: "https://matrix.org"
    token: "syt_..."
```

## Example Agent Interaction

```
Agent: I need to notify the team about the deployment.

→ calls list_channels
← telegram (connected), discord (connected), slack (not connected), ...

→ calls broadcast_message { text: "Deploy v2.1 complete ✅", targets: { telegram: "-100123", discord: "456789" } }
← telegram: sent, discord: sent

→ calls get_recent_messages { limit: 5 }
← [2026-03-08T15:30:00Z] telegram/-100123 @alice: looks good!
```

## License

MIT
