#!/usr/bin/env node

/**
 * unified-channel MCP Server
 *
 * Exposes messaging channels as MCP tools for AI agents.
 * Self-contained — no dependency on the unified-channel npm package.
 *
 * Supports 18 channels: Telegram, Discord, Slack, Mattermost, IRC,
 * WhatsApp, LINE, Feishu/Lark, MS Teams, Google Chat, Synology Chat,
 * Zalo, Nostr, Twitch, BlueBubbles, Nextcloud Talk, iMessage, Matrix.
 *
 * Usage:
 *   UC_TELEGRAM_TOKEN=... npx @unified-channel/mcp-server
 *   UC_CONFIG_PATH=./unified-channel.yaml npx @unified-channel/mcp-server
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";

// ---- Minimal adapter types (self-contained) ----

interface OutboundMessage {
  chatId: string;
  text: string;
  replyToId?: string;
}

interface ChannelStatus {
  connected: boolean;
  channel: string;
  accountId?: string;
  lastActivity?: Date;
}

interface ChannelAdapter {
  readonly channelId: string;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  onMessage(handler: (msg: any) => void): void;
  send(msg: OutboundMessage): Promise<string | undefined>;
  getStatus(): Promise<ChannelStatus>;
}

// ---- Simple YAML parser (line-by-line, no deps) ----

interface YamlConfig {
  channels: Record<string, Record<string, string>>;
}

function parseSimpleYaml(text: string): YamlConfig {
  const result: YamlConfig = { channels: {} };
  let currentChannel: string | null = null;
  let inChannels = false;

  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    const trimmed = line.trimStart();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const indent = line.length - trimmed.length;

    if (trimmed === "channels:" || trimmed === "channels: ") {
      inChannels = true;
      currentChannel = null;
      continue;
    }

    if (!inChannels) continue;

    // Channel name line (indent=2): "  telegram:"
    if (indent === 2 && trimmed.endsWith(":")) {
      currentChannel = trimmed.slice(0, -1).trim();
      result.channels[currentChannel] = {};
      continue;
    }

    // Key-value line (indent=4): '    token: "value"'
    if (indent >= 4 && currentChannel) {
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx > 0) {
        const key = trimmed.slice(0, colonIdx).trim();
        let value = trimmed.slice(colonIdx + 1).trim();
        // Strip surrounding quotes
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        result.channels[currentChannel][key] = value;
      }
    }
  }

  return result;
}

// ---- Telegram Adapter (grammy) ----

class TelegramAdapter implements ChannelAdapter {
  readonly channelId = "telegram";
  private connected = false;
  private lastActivity?: Date;
  private bot: any;
  private handler?: (msg: any) => void;
  private botUsername?: string;

  constructor(private token: string) {}

  async connect(): Promise<void> {
    let Bot: any;
    try {
      ({ Bot } = await import("grammy"));
    } catch {
      throw new Error("Install grammy to use Telegram: npm install grammy");
    }
    this.bot = new Bot(this.token);

    this.bot.on("message:text", (ctx: any) => {
      if (!this.handler) return;
      const text: string = ctx.message.text;
      const isCmd = text.startsWith("/");
      const parts = isCmd ? text.slice(1).split(/\s+/) : [];
      this.lastActivity = new Date();

      this.handler({
        id: String(ctx.message.message_id), channel: "telegram",
        sender: { id: String(ctx.from.id), username: ctx.from.username, displayName: [ctx.from.first_name, ctx.from.last_name].filter(Boolean).join(" ") },
        content: { type: isCmd ? "command" : "text", text, command: isCmd ? parts[0]?.split("@")[0] : undefined, args: isCmd ? parts.slice(1) : undefined },
        timestamp: new Date(ctx.message.date * 1000), chatId: String(ctx.chat.id), raw: ctx,
      });
    });

    const me = await this.bot.api.getMe();
    this.botUsername = me.username;
    this.bot.start({ drop_pending_updates: true });
    this.connected = true;
  }

  async disconnect(): Promise<void> { await this.bot?.stop(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const opts: any = {};
    if (msg.replyToId) opts.reply_to_message_id = Number(msg.replyToId);
    const sent = await this.bot.api.sendMessage(Number(msg.chatId), msg.text, opts);
    this.lastActivity = new Date();
    return String(sent.message_id);
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "telegram", accountId: this.botUsername, lastActivity: this.lastActivity };
  }
}

// ---- Discord Adapter (discord.js) ----

class DiscordAdapter implements ChannelAdapter {
  readonly channelId = "discord";
  private connected = false;
  private lastActivity?: Date;
  private client: any;
  private handler?: (msg: any) => void;
  private botUsername?: string;

  constructor(private token: string) {}

  async connect(): Promise<void> {
    let Client: any, GatewayIntentBits: any, Events: any;
    try {
      ({ Client, GatewayIntentBits, Events } = await import("discord.js"));
    } catch {
      throw new Error("Install discord.js to use Discord: npm install discord.js");
    }
    this.client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });

    this.client.on(Events.MessageCreate, (message: any) => {
      if (message.author.bot || !this.handler) return;
      const text: string = message.content;
      const isCmd = text.startsWith("!");
      const parts = isCmd ? text.slice(1).split(/\s+/) : [];
      this.lastActivity = new Date();

      this.handler({
        id: message.id, channel: "discord",
        sender: { id: message.author.id, username: message.author.username, displayName: message.author.displayName },
        content: { type: isCmd ? "command" : "text", text, command: isCmd ? parts[0] : undefined, args: isCmd ? parts.slice(1) : undefined },
        timestamp: message.createdAt, chatId: message.channelId, threadId: message.thread?.id, raw: message,
      });
    });

    await this.client.login(this.token);
    this.botUsername = this.client.user?.username;
    this.connected = true;
  }

  async disconnect(): Promise<void> { await this.client?.destroy(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const channel = await this.client.channels.fetch(msg.chatId);
    if (!channel?.isTextBased()) throw new Error(`Channel ${msg.chatId} is not text-based`);
    const opts: any = { content: msg.text };
    if (msg.replyToId) opts.reply = { messageReference: msg.replyToId };
    const sent = await channel.send(opts);
    this.lastActivity = new Date();
    return sent.id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "discord", accountId: this.botUsername, lastActivity: this.lastActivity };
  }
}

// ---- Slack Adapter (@slack/bolt) ----

class SlackAdapter implements ChannelAdapter {
  readonly channelId = "slack";
  private connected = false;
  private lastActivity?: Date;
  private app: any;
  private handler?: (msg: any) => void;
  private botUserId?: string;

  constructor(private botToken: string, private appToken: string) {}

  async connect(): Promise<void> {
    let App: any;
    try {
      ({ App } = await import("@slack/bolt"));
    } catch {
      throw new Error("Install @slack/bolt to use Slack: npm install @slack/bolt");
    }
    this.app = new App({ token: this.botToken, appToken: this.appToken, socketMode: true });

    this.app.message(async ({ message }: any) => {
      if (message.subtype || !this.handler) return;
      const text: string = message.text || "";
      const isCmd = text.startsWith("/");
      const parts = isCmd ? text.slice(1).split(/\s+/) : [];
      this.lastActivity = new Date();

      this.handler({
        id: message.ts, channel: "slack",
        sender: { id: message.user },
        content: { type: isCmd ? "command" : "text", text, command: isCmd ? parts[0] : undefined, args: isCmd ? parts.slice(1) : undefined },
        timestamp: new Date(parseFloat(message.ts) * 1000), chatId: message.channel, threadId: message.thread_ts, raw: message,
      });
    });

    await this.app.start();
    const auth = await this.app.client.auth.test({ token: this.botToken });
    this.botUserId = auth.user_id;
    this.connected = true;
  }

  async disconnect(): Promise<void> { await this.app?.stop(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const result = await this.app.client.chat.postMessage({ token: this.botToken, channel: msg.chatId, text: msg.text, thread_ts: msg.replyToId });
    this.lastActivity = new Date();
    return result.ts;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "slack", accountId: this.botUserId, lastActivity: this.lastActivity };
  }
}

// ---- Mattermost Adapter (WebSocket + REST) ----

class MattermostAdapter implements ChannelAdapter {
  readonly channelId = "mattermost";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private ws: any;
  private botUserId?: string;

  constructor(private url: string, private token: string) {}

  async connect(): Promise<void> {
    const baseUrl = this.url.replace(/\/$/, "");
    const meResp = await fetch(`${baseUrl}/api/v4/users/me`, { headers: { Authorization: `Bearer ${this.token}` } });
    const me = await meResp.json() as any;
    this.botUserId = me.id;

    let WebSocket: any;
    try {
      ({ default: WebSocket } = await import("ws"));
    } catch {
      throw new Error("Install ws to use Mattermost: npm install ws");
    }
    const wsUrl = baseUrl.replace(/^http/, "ws") + "/api/v4/websocket";
    this.ws = new WebSocket(wsUrl);

    this.ws.on("open", () => {
      this.ws.send(JSON.stringify({ seq: 1, action: "authentication_challenge", data: { token: this.token } }));
      this.connected = true;
    });

    this.ws.on("message", (raw: string) => {
      const event = JSON.parse(raw);
      if (event.event !== "posted" || !this.handler) return;
      const post = JSON.parse(event.data?.post || "{}");
      if (post.user_id === this.botUserId) return;
      const text: string = post.message || "";
      this.lastActivity = new Date();

      this.handler({
        id: post.id, channel: "mattermost",
        sender: { id: post.user_id },
        content: { type: "text", text },
        timestamp: new Date(post.create_at), chatId: post.channel_id, threadId: post.root_id || undefined, raw: post,
      });
    });

    await new Promise<void>((resolve) => this.ws.once("open", resolve));
  }

  async disconnect(): Promise<void> { this.ws?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const resp = await fetch(`${this.url.replace(/\/$/, "")}/api/v4/posts`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ channel_id: msg.chatId, message: msg.text, root_id: msg.replyToId }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "mattermost", accountId: this.botUserId, lastActivity: this.lastActivity };
  }
}

// ---- IRC Adapter (net.Socket, zero deps) ----

class IRCAdapter implements ChannelAdapter {
  readonly channelId = "irc";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private socket: any;
  private msgCounter = 0;

  constructor(private server: string, private nickname: string, private channels: string[], private port = 6667) {}

  async connect(): Promise<void> {
    const net = await import("net");
    this.socket = net.createConnection(this.port, this.server);
    let buffer = "";

    this.socket.on("data", (data: Buffer) => {
      buffer += data.toString();
      const lines = buffer.split("\r\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("PING")) {
          this.socket.write(`PONG ${line.slice(5)}\r\n`);
          continue;
        }
        const match = line.match(/^:(\S+?)!\S+ PRIVMSG (\S+) :(.*)$/);
        if (match && this.handler) {
          const [, nick, target, text] = match;
          if (nick === this.nickname) continue;
          this.msgCounter++;
          this.lastActivity = new Date();
          this.handler({
            id: String(this.msgCounter), channel: "irc",
            sender: { id: nick, username: nick },
            content: { type: "text", text },
            timestamp: new Date(), chatId: target, raw: line,
          });
        }
      }
    });

    this.socket.on("connect", () => {
      this.socket.write(`NICK ${this.nickname}\r\n`);
      this.socket.write(`USER ${this.nickname} 0 * :unified-channel\r\n`);
      for (const ch of this.channels) this.socket.write(`JOIN ${ch}\r\n`);
      this.connected = true;
    });

    await new Promise<void>((resolve) => this.socket.once("connect", resolve));
  }

  async disconnect(): Promise<void> { this.socket?.write("QUIT :bye\r\n"); this.socket?.destroy(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    for (const line of msg.text.split("\n")) {
      if (line.trim()) this.socket.write(`PRIVMSG ${msg.chatId} :${line}\r\n`);
    }
    this.lastActivity = new Date();
    return undefined;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "irc", accountId: `${this.nickname}@${this.server}`, lastActivity: this.lastActivity };
  }
}

// ---- WhatsApp Adapter (Meta Cloud API, webhook) ----

class WhatsAppAdapter implements ChannelAdapter {
  readonly channelId = "whatsapp";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private phoneId: string;
  private verifyToken: string;
  private msgCounter = 0;

  constructor(private token: string, phoneId: string, verifyToken: string, private port = 9000) {
    this.phoneId = phoneId;
    this.verifyToken = verifyToken;
  }

  async connect(): Promise<void> {
    this.server = http.createServer((req, res) => {
      if (req.method === "GET") {
        // Webhook verification
        const url = new URL(req.url || "/", `http://localhost:${this.port}`);
        const mode = url.searchParams.get("hub.mode");
        const token = url.searchParams.get("hub.verify_token");
        const challenge = url.searchParams.get("hub.challenge");
        if (mode === "subscribe" && token === this.verifyToken) {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end(challenge);
        } else {
          res.writeHead(403);
          res.end();
        }
        return;
      }

      if (req.method === "POST") {
        let body = "";
        req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
        req.on("end", () => {
          res.writeHead(200);
          res.end("OK");
          try {
            const data = JSON.parse(body);
            const entries = data.entry || [];
            for (const entry of entries) {
              for (const change of entry.changes || []) {
                const messages = change.value?.messages || [];
                for (const m of messages) {
                  if (m.type !== "text" || !this.handler) continue;
                  this.msgCounter++;
                  this.lastActivity = new Date();
                  this.handler({
                    id: m.id || String(this.msgCounter), channel: "whatsapp",
                    sender: { id: m.from, username: m.from },
                    content: { type: "text", text: m.text?.body || "" },
                    timestamp: new Date(Number(m.timestamp) * 1000), chatId: m.from, raw: m,
                  });
                }
              }
            }
          } catch (_) { /* ignore malformed */ }
        });
        return;
      }

      res.writeHead(405);
      res.end();
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const resp = await fetch(`https://graph.facebook.com/v18.0/${this.phoneId}/messages`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        to: msg.chatId,
        type: "text",
        text: { body: msg.text },
      }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.messages?.[0]?.id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "whatsapp", accountId: this.phoneId, lastActivity: this.lastActivity };
  }
}

// ---- LINE Adapter (webhook + REST) ----

class LINEAdapter implements ChannelAdapter {
  readonly channelId = "line";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private msgCounter = 0;

  constructor(private channelSecret: string, private channelAccessToken: string, private port = 9001) {}

  async connect(): Promise<void> {
    this.server = http.createServer((req, res) => {
      if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        res.writeHead(200);
        res.end("OK");
        try {
          const data = JSON.parse(body);
          for (const event of data.events || []) {
            if (event.type !== "message" || event.message.type !== "text" || !this.handler) continue;
            this.msgCounter++;
            this.lastActivity = new Date();
            this.handler({
              id: event.message.id || String(this.msgCounter), channel: "line",
              sender: { id: event.source?.userId || "unknown" },
              content: { type: "text", text: event.message.text },
              timestamp: new Date(event.timestamp), chatId: event.source?.userId || event.source?.groupId || "unknown",
              raw: event,
            });
          }
        } catch (_) { /* ignore */ }
      });
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const resp = await fetch("https://api.line.me/v2/bot/message/push", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.channelAccessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ to: msg.chatId, messages: [{ type: "text", text: msg.text }] }),
    });
    this.lastActivity = new Date();
    const data = await resp.json() as any;
    return data.sentMessages?.[0]?.id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "line", lastActivity: this.lastActivity };
  }
}

// ---- Feishu/Lark Adapter (webhook + REST) ----

class FeishuAdapter implements ChannelAdapter {
  readonly channelId = "feishu";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private tenantAccessToken?: string;
  private msgCounter = 0;

  constructor(private appId: string, private appSecret: string, private port = 9002) {}

  private async refreshToken(): Promise<void> {
    const resp = await fetch("https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ app_id: this.appId, app_secret: this.appSecret }),
    });
    const data = await resp.json() as any;
    this.tenantAccessToken = data.tenant_access_token;
  }

  async connect(): Promise<void> {
    await this.refreshToken();

    this.server = http.createServer((req, res) => {
      if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        try {
          const data = JSON.parse(body);

          // URL verification challenge
          if (data.challenge) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ challenge: data.challenge }));
            return;
          }

          res.writeHead(200);
          res.end("OK");

          const event = data.event;
          if (!event || !this.handler) return;
          const msgType = event.message?.message_type;
          if (msgType !== "text") return;

          this.msgCounter++;
          this.lastActivity = new Date();
          let text = "";
          try { text = JSON.parse(event.message.content).text || ""; } catch (_) { /* ignore */ }

          this.handler({
            id: event.message?.message_id || String(this.msgCounter), channel: "feishu",
            sender: { id: event.sender?.sender_id?.user_id || "unknown" },
            content: { type: "text", text },
            timestamp: new Date(Number(event.message?.create_time || 0) * 1000),
            chatId: event.message?.chat_id || "unknown", raw: event,
          });
        } catch (_) {
          res.writeHead(200);
          res.end("OK");
        }
      });
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    if (!this.tenantAccessToken) await this.refreshToken();
    const resp = await fetch("https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id", {
      method: "POST",
      headers: { Authorization: `Bearer ${this.tenantAccessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        receive_id: msg.chatId,
        msg_type: "text",
        content: JSON.stringify({ text: msg.text }),
      }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.data?.message_id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "feishu", accountId: this.appId, lastActivity: this.lastActivity };
  }
}

// ---- MS Teams Adapter (Bot Framework webhook) ----

class MSTeamsAdapter implements ChannelAdapter {
  readonly channelId = "msteams";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private accessToken?: string;
  private msgCounter = 0;

  constructor(private appId: string, private appPassword: string, private port = 9003) {}

  private async refreshToken(): Promise<void> {
    const resp = await fetch("https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=client_credentials&client_id=${encodeURIComponent(this.appId)}&client_secret=${encodeURIComponent(this.appPassword)}&scope=https%3A%2F%2Fapi.botframework.com%2F.default`,
    });
    const data = await resp.json() as any;
    this.accessToken = data.access_token;
  }

  async connect(): Promise<void> {
    await this.refreshToken();

    this.server = http.createServer((req, res) => {
      if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        res.writeHead(200);
        res.end();
        try {
          const activity = JSON.parse(body);
          if (activity.type !== "message" || !this.handler) return;
          this.msgCounter++;
          this.lastActivity = new Date();

          this.handler({
            id: activity.id || String(this.msgCounter), channel: "msteams",
            sender: { id: activity.from?.id || "unknown", displayName: activity.from?.name },
            content: { type: "text", text: activity.text || "" },
            timestamp: new Date(activity.timestamp || Date.now()),
            chatId: activity.conversation?.id || "unknown", raw: activity,
          });
        } catch (_) { /* ignore */ }
      });
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    if (!this.accessToken) await this.refreshToken();
    // Teams requires serviceUrl from the activity; use generic endpoint
    const serviceUrl = "https://smba.trafficmanager.net/teams";
    const resp = await fetch(`${serviceUrl}/v3/conversations/${encodeURIComponent(msg.chatId)}/activities`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ type: "message", text: msg.text }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "msteams", accountId: this.appId, lastActivity: this.lastActivity };
  }
}

// ---- Google Chat Adapter (webhook + service account) ----

class GoogleChatAdapter implements ChannelAdapter {
  readonly channelId = "googlechat";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private serviceAccountKey: any;
  private msgCounter = 0;

  constructor(private keyPath: string, private port = 9004) {}

  async connect(): Promise<void> {
    this.serviceAccountKey = JSON.parse(fs.readFileSync(this.keyPath, "utf-8"));

    this.server = http.createServer((req, res) => {
      if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        res.writeHead(200);
        res.end();
        try {
          const event = JSON.parse(body);
          if (event.type !== "MESSAGE" || !this.handler) return;
          this.msgCounter++;
          this.lastActivity = new Date();

          this.handler({
            id: event.message?.name || String(this.msgCounter), channel: "googlechat",
            sender: { id: event.user?.name || "unknown", displayName: event.user?.displayName },
            content: { type: "text", text: event.message?.text || "" },
            timestamp: new Date(event.eventTime || Date.now()),
            chatId: event.space?.name || "unknown", raw: event,
          });
        } catch (_) { /* ignore */ }
      });
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    // Google Chat requires OAuth2 with service account; simplified version using webhook URL pattern
    // In production, you'd use google-auth-library for proper JWT signing
    const resp = await fetch(`https://chat.googleapis.com/v1/${msg.chatId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: msg.text }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.name;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "googlechat", accountId: this.serviceAccountKey?.client_email, lastActivity: this.lastActivity };
  }
}

// ---- Synology Chat Adapter (webhook) ----

class SynologyChatAdapter implements ChannelAdapter {
  readonly channelId = "synology";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private msgCounter = 0;

  constructor(private synologyUrl: string, private incomingToken: string, private outgoingUrl: string, private port = 9005) {}

  async connect(): Promise<void> {
    this.server = http.createServer((req, res) => {
      if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        res.writeHead(200);
        res.end("OK");
        try {
          // Synology sends URL-encoded or JSON payload
          let data: any;
          try { data = JSON.parse(body); } catch (_) {
            data = Object.fromEntries(new URLSearchParams(body));
          }

          if (data.token !== this.incomingToken || !this.handler) return;
          this.msgCounter++;
          this.lastActivity = new Date();

          this.handler({
            id: String(this.msgCounter), channel: "synology",
            sender: { id: data.user_id?.toString() || "unknown", username: data.username },
            content: { type: "text", text: data.text || "" },
            timestamp: new Date(), chatId: data.channel_id?.toString() || "unknown", raw: data,
          });
        } catch (_) { /* ignore */ }
      });
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const payload = `payload=${encodeURIComponent(JSON.stringify({ text: msg.text }))}`;
    await fetch(this.outgoingUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: payload,
    });
    this.lastActivity = new Date();
    return undefined;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "synology", lastActivity: this.lastActivity };
  }
}

// ---- Zalo Adapter (webhook + REST) ----

class ZaloAdapter implements ChannelAdapter {
  readonly channelId = "zalo";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private server?: http.Server;
  private msgCounter = 0;

  constructor(private accessToken: string, private port = 9006) {}

  async connect(): Promise<void> {
    this.server = http.createServer((req, res) => {
      if (req.method !== "POST") { res.writeHead(405); res.end(); return; }

      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        res.writeHead(200);
        res.end("OK");
        try {
          const data = JSON.parse(body);
          if (data.event_name !== "user_send_text" || !this.handler) return;
          this.msgCounter++;
          this.lastActivity = new Date();

          this.handler({
            id: data.message?.msg_id || String(this.msgCounter), channel: "zalo",
            sender: { id: data.sender?.id || "unknown" },
            content: { type: "text", text: data.message?.text || "" },
            timestamp: new Date(data.timestamp || Date.now()),
            chatId: data.sender?.id || "unknown", raw: data,
          });
        } catch (_) { /* ignore */ }
      });
    });

    await new Promise<void>((resolve) => { this.server!.listen(this.port, () => resolve()); });
    this.connected = true;
  }

  async disconnect(): Promise<void> { this.server?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const resp = await fetch("https://openapi.zalo.me/v3.0/oa/message/cs", {
      method: "POST",
      headers: { access_token: this.accessToken, "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: { user_id: msg.chatId },
        message: { text: msg.text },
      }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.data?.message_id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "zalo", lastActivity: this.lastActivity };
  }
}

// ---- Nostr Adapter (WebSocket relay) ----
// NOTE: This is a stub implementation. Event signing is not implemented.
// A full implementation requires nostr-tools for proper NIP-01 event signing.

class NostrAdapter implements ChannelAdapter {
  readonly channelId = "nostr";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private sockets: any[] = [];
  private msgCounter = 0;

  constructor(private privateKey: string, private relays: string[]) {}

  async connect(): Promise<void> {
    let WebSocket: any;
    try {
      ({ default: WebSocket } = await import("ws"));
    } catch {
      throw new Error("Install ws to use Nostr: npm install ws");
    }

    for (const relay of this.relays) {
      try {
        const ws = new WebSocket(relay);
        ws.on("open", () => {
          // Subscribe to kind 4 (DM) and kind 1 (text notes) mentioning us
          ws.send(JSON.stringify(["REQ", "sub1", { kinds: [1, 4], limit: 10 }]));
        });

        ws.on("message", (raw: string) => {
          try {
            const msg = JSON.parse(raw.toString());
            if (msg[0] !== "EVENT" || !this.handler) return;
            const event = msg[2];
            if (!event || !event.content) return;
            this.msgCounter++;
            this.lastActivity = new Date();

            this.handler({
              id: event.id || String(this.msgCounter), channel: "nostr",
              sender: { id: event.pubkey || "unknown" },
              content: { type: "text", text: event.content },
              timestamp: new Date((event.created_at || 0) * 1000),
              chatId: event.pubkey || "unknown", raw: event,
            });
          } catch (_) { /* ignore */ }
        });

        this.sockets.push(ws);
      } catch (_) { /* skip failed relay */ }
    }

    this.connected = true;
  }

  async disconnect(): Promise<void> {
    for (const ws of this.sockets) ws.close();
    this.sockets = [];
    this.connected = false;
  }

  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    // Simplified: broadcast a kind 1 text note to all relays
    // In production, you'd sign the event with the private key using nostr-tools
    const event = {
      kind: 1,
      content: msg.text,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["p", msg.chatId]],
      pubkey: this.privateKey.slice(0, 64), // placeholder
    };

    for (const ws of this.sockets) {
      if (ws.readyState === 1) {
        ws.send(JSON.stringify(["EVENT", event]));
      }
    }

    this.lastActivity = new Date();
    return undefined;
  }

  async getStatus(): Promise<ChannelStatus> {
    const connectedRelays = this.sockets.filter(ws => ws.readyState === 1).length;
    return { connected: this.connected, channel: "nostr", accountId: `stub - requires nostr-tools for signing (${connectedRelays}/${this.relays.length} relays)`, lastActivity: this.lastActivity };
  }
}

// ---- Twitch Adapter (IRC over WebSocket) ----

class TwitchAdapter implements ChannelAdapter {
  readonly channelId = "twitch";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private ws: any;
  private msgCounter = 0;

  constructor(private username: string, private oauth: string, private channels: string[]) {}

  async connect(): Promise<void> {
    let WebSocket: any;
    try {
      ({ default: WebSocket } = await import("ws"));
    } catch {
      throw new Error("Install ws to use Twitch: npm install ws");
    }
    this.ws = new WebSocket("wss://irc-ws.chat.twitch.tv:443");

    this.ws.on("open", () => {
      this.ws.send(`PASS ${this.oauth.startsWith("oauth:") ? this.oauth : "oauth:" + this.oauth}`);
      this.ws.send(`NICK ${this.username}`);
      for (const ch of this.channels) {
        this.ws.send(`JOIN ${ch.startsWith("#") ? ch : "#" + ch}`);
      }
      this.connected = true;
    });

    this.ws.on("message", (raw: string) => {
      const data = raw.toString();
      for (const line of data.split("\r\n")) {
        if (!line) continue;
        if (line.startsWith("PING")) {
          this.ws.send(`PONG ${line.slice(5)}`);
          continue;
        }

        // :nick!nick@nick.tmi.twitch.tv PRIVMSG #channel :message
        const match = line.match(/^:(\w+)!\S+ PRIVMSG (#\w+) :(.*)$/);
        if (match && this.handler) {
          const [, nick, channel, text] = match;
          if (nick.toLowerCase() === this.username.toLowerCase()) continue;
          this.msgCounter++;
          this.lastActivity = new Date();
          this.handler({
            id: String(this.msgCounter), channel: "twitch",
            sender: { id: nick, username: nick },
            content: { type: "text", text },
            timestamp: new Date(), chatId: channel, raw: line,
          });
        }
      }
    });

    await new Promise<void>((resolve) => this.ws.once("open", resolve));
  }

  async disconnect(): Promise<void> { this.ws?.close(); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const target = msg.chatId.startsWith("#") ? msg.chatId : `#${msg.chatId}`;
    this.ws.send(`PRIVMSG ${target} :${msg.text}`);
    this.lastActivity = new Date();
    return undefined;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "twitch", accountId: this.username, lastActivity: this.lastActivity };
  }
}

// ---- BlueBubbles Adapter (REST polling) ----

class BlueBubblesAdapter implements ChannelAdapter {
  readonly channelId = "bluebubbles";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private pollTimer?: ReturnType<typeof setInterval>;
  private lastPollTime = Date.now();

  constructor(private url: string, private password: string) {}

  async connect(): Promise<void> {
    const baseUrl = this.url.replace(/\/$/, "");

    // Poll for new messages every 5 seconds
    this.pollTimer = setInterval(async () => {
      try {
        const resp = await fetch(`${baseUrl}/api/v1/message?password=${encodeURIComponent(this.password)}&after=${this.lastPollTime}&limit=50&sort=asc`);
        const data = await resp.json() as any;
        this.lastPollTime = Date.now();

        for (const msg of data.data || []) {
          if (msg.isFromMe || !this.handler) continue;
          this.lastActivity = new Date();
          this.handler({
            id: msg.guid || msg.id?.toString(), channel: "bluebubbles",
            sender: { id: msg.handle?.address || "unknown", username: msg.handle?.address },
            content: { type: "text", text: msg.text || "" },
            timestamp: new Date(msg.dateCreated || Date.now()),
            chatId: msg.chats?.[0]?.guid || msg.handle?.address || "unknown", raw: msg,
          });
        }
      } catch (_) { /* ignore poll errors */ }
    }, 5000);

    this.connected = true;
  }

  async disconnect(): Promise<void> { if (this.pollTimer) clearInterval(this.pollTimer); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const baseUrl = this.url.replace(/\/$/, "");
    const resp = await fetch(`${baseUrl}/api/v1/message/text?password=${encodeURIComponent(this.password)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chatGuid: msg.chatId, message: msg.text }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.data?.guid;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "bluebubbles", accountId: this.url, lastActivity: this.lastActivity };
  }
}

// ---- Nextcloud Talk Adapter (REST polling) ----

class NextcloudTalkAdapter implements ChannelAdapter {
  readonly channelId = "nextcloud";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private pollTimer?: ReturnType<typeof setInterval>;
  private lastKnownId: Record<string, number> = {};

  constructor(private url: string, private user: string, private password: string, private rooms: string[]) {}

  private get authHeader(): string {
    return `Basic ${Buffer.from(`${this.user}:${this.password}`).toString("base64")}`;
  }

  async connect(): Promise<void> {
    const baseUrl = this.url.replace(/\/$/, "");

    this.pollTimer = setInterval(async () => {
      for (const room of this.rooms) {
        try {
          const lookAfter = this.lastKnownId[room] || 0;
          const resp = await fetch(`${baseUrl}/ocs/v2.php/apps/spreed/api/v1/chat/${room}?lookIntoFuture=0&limit=20${lookAfter ? `&lastKnownMessageId=${lookAfter}` : ""}`, {
            headers: { Authorization: this.authHeader, "OCS-APIRequest": "true", Accept: "application/json" },
          });
          const data = await resp.json() as any;
          const messages = data.ocs?.data || [];

          for (const m of messages) {
            if (m.actorId === this.user || m.systemMessage) continue;
            if (m.id <= (this.lastKnownId[room] || 0)) continue;
            this.lastKnownId[room] = m.id;
            if (!this.handler) continue;
            this.lastActivity = new Date();

            this.handler({
              id: String(m.id), channel: "nextcloud",
              sender: { id: m.actorId, displayName: m.actorDisplayName },
              content: { type: "text", text: m.message || "" },
              timestamp: new Date(m.timestamp * 1000), chatId: room, raw: m,
            });
          }
        } catch (_) { /* ignore */ }
      }
    }, 5000);

    this.connected = true;
  }

  async disconnect(): Promise<void> { if (this.pollTimer) clearInterval(this.pollTimer); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const baseUrl = this.url.replace(/\/$/, "");
    const resp = await fetch(`${baseUrl}/ocs/v2.php/apps/spreed/api/v1/chat/${msg.chatId}`, {
      method: "POST",
      headers: { Authorization: this.authHeader, "OCS-APIRequest": "true", "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ message: msg.text, replyTo: msg.replyToId ? Number(msg.replyToId) : undefined }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return String(data.ocs?.data?.id || "");
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "nextcloud", accountId: `${this.user}@${this.url}`, lastActivity: this.lastActivity };
  }
}

// ---- iMessage Adapter (macOS only, sqlite3 + osascript) ----

class IMessageAdapter implements ChannelAdapter {
  readonly channelId = "imessage";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private pollTimer?: ReturnType<typeof setInterval>;
  private lastRowId = 0;

  async connect(): Promise<void> {
    if (process.platform !== "darwin") {
      throw new Error("iMessage adapter is only available on macOS");
    }

    const { execSync } = await import("child_process");
    const homeDir = process.env.HOME || os.homedir();
    const chatDbPath = path.join(homeDir, "Library", "Messages", "chat.db");

    // Get the latest ROWID to avoid replaying old messages
    try {
      const result = execSync(`sqlite3 ${JSON.stringify(chatDbPath)} 'SELECT MAX(ROWID) FROM message'`, { encoding: "utf-8" }).trim();
      this.lastRowId = parseInt(result, 10) || 0;
    } catch (_) { /* ignore */ }

    this.pollTimer = setInterval(async () => {
      try {
        const { execSync: exec } = await import("child_process");
        const query = `SELECT m.ROWID, m.text, m.is_from_me, h.id as sender, m.date, c.chat_identifier FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID LEFT JOIN chat_message_join cmj ON m.ROWID = cmj.message_id LEFT JOIN chat c ON cmj.chat_id = c.ROWID WHERE m.ROWID > ${this.lastRowId} AND m.is_from_me = 0 ORDER BY m.ROWID ASC LIMIT 20`;
        // Use JSON.stringify to safely quote the db path; pass query via -cmd to avoid shell metacharacter issues
        const result = exec(`sqlite3 -separator '|' ${JSON.stringify(chatDbPath)} ${JSON.stringify(query)}`, { encoding: "utf-8" }).trim();

        if (!result) return;
        for (const line of result.split("\n")) {
          const [rowId, text, , sender, , chatId] = line.split("|");
          if (!text || !this.handler) continue;
          this.lastRowId = Math.max(this.lastRowId, parseInt(rowId, 10));
          this.lastActivity = new Date();

          this.handler({
            id: rowId, channel: "imessage",
            sender: { id: sender || "unknown", username: sender },
            content: { type: "text", text },
            timestamp: new Date(), chatId: chatId || sender || "unknown", raw: line,
          });
        }
      } catch (_) { /* ignore */ }
    }, 3000);

    this.connected = true;
  }

  async disconnect(): Promise<void> { if (this.pollTimer) clearInterval(this.pollTimer); this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const { execSync } = await import("child_process");
    // Escape for AppleScript string literals: backslashes first, then double quotes
    const escapeAppleScript = (s: string) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r/g, "\\r").replace(/\n/g, "\\n");
    const escapedText = escapeAppleScript(msg.text);
    const escapedId = escapeAppleScript(msg.chatId);

    // Determine if chatId is a phone/email or group chat
    const script = `tell application "Messages"
  set targetService to 1st service whose service type = iMessage
  set targetBuddy to buddy "${escapedId}" of targetService
  send "${escapedText}" to targetBuddy
end tell`;

    try {
      // Use stdin via -s flag to avoid shell escaping issues with osascript
      execSync("osascript -", { input: script, encoding: "utf-8" });
    } catch (_) {
      // Fallback: try sending via chat identifier
      const fallbackScript = `tell application "Messages" to send "${escapedText}" to chat id "${escapedId}"`;
      execSync("osascript -", { input: fallbackScript, encoding: "utf-8" });
    }

    this.lastActivity = new Date();
    return undefined;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "imessage", accountId: "local", lastActivity: this.lastActivity };
  }
}

// ---- Matrix Adapter (HTTP long-poll /sync) ----

class MatrixAdapter implements ChannelAdapter {
  readonly channelId = "matrix";
  private connected = false;
  private lastActivity?: Date;
  private handler?: (msg: any) => void;
  private syncToken?: string;
  private polling = false;
  private userId?: string;

  constructor(private homeserver: string, private token: string) {}

  async connect(): Promise<void> {
    const baseUrl = this.homeserver.replace(/\/$/, "");

    // Get our own user ID
    const whoami = await fetch(`${baseUrl}/_matrix/client/v3/account/whoami`, {
      headers: { Authorization: `Bearer ${this.token}` },
    });
    const me = await whoami.json() as any;
    this.userId = me.user_id;

    this.polling = true;
    this.connected = true;

    // Start long-poll loop (runs in background)
    this.pollLoop(baseUrl).catch(() => { this.connected = false; });
  }

  private async pollLoop(baseUrl: string): Promise<void> {
    while (this.polling) {
      try {
        const params = new URLSearchParams({ timeout: "30000", filter: '{"room":{"timeline":{"limit":10}}}' });
        if (this.syncToken) params.set("since", this.syncToken);

        const resp = await fetch(`${baseUrl}/_matrix/client/v3/sync?${params}`, {
          headers: { Authorization: `Bearer ${this.token}` },
        });
        const data = await resp.json() as any;
        this.syncToken = data.next_batch;

        // Process room events
        for (const [roomId, room] of Object.entries(data.rooms?.join || {}) as [string, any][]) {
          for (const event of room.timeline?.events || []) {
            if (event.type !== "m.room.message" || event.sender === this.userId || !this.handler) continue;
            if (event.content?.msgtype !== "m.text") continue;
            this.lastActivity = new Date();

            this.handler({
              id: event.event_id, channel: "matrix",
              sender: { id: event.sender, username: event.sender },
              content: { type: "text", text: event.content.body || "" },
              timestamp: new Date(event.origin_server_ts), chatId: roomId, raw: event,
            });
          }
        }
      } catch (_) {
        // Wait before retrying on error
        await new Promise(r => setTimeout(r, 5000));
      }
    }
  }

  async disconnect(): Promise<void> { this.polling = false; this.connected = false; }
  onMessage(handler: (msg: any) => void): void { this.handler = handler; }

  async send(msg: OutboundMessage): Promise<string | undefined> {
    const baseUrl = this.homeserver.replace(/\/$/, "");
    const txnId = `m${Date.now()}`;
    const resp = await fetch(`${baseUrl}/_matrix/client/v3/rooms/${encodeURIComponent(msg.chatId)}/send/m.room.message/${txnId}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ msgtype: "m.text", body: msg.text }),
    });
    const data = await resp.json() as any;
    this.lastActivity = new Date();
    return data.event_id;
  }

  async getStatus(): Promise<ChannelStatus> {
    return { connected: this.connected, channel: "matrix", accountId: this.userId, lastActivity: this.lastActivity };
  }
}

// ---- MCP Server ----

interface BufferedMessage {
  id: string;
  channel: string;
  sender: string;
  text: string;
  timestamp: string;
  chatId: string;
}

const messageBuffer: BufferedMessage[] = [];
const MAX_BUFFER = 100;
const adapters = new Map<string, ChannelAdapter>();

const ALL_CHANNELS = [
  "telegram", "discord", "slack", "mattermost", "irc",
  "whatsapp", "line", "feishu", "msteams", "googlechat",
  "synology", "zalo", "nostr", "twitch",
  "bluebubbles", "nextcloud", "imessage", "matrix",
] as const;

function parseAndCreateAdapters(): { type: string; create: () => ChannelAdapter }[] {
  const result: { type: string; create: () => ChannelAdapter }[] = [];

  if (process.env.UC_TELEGRAM_TOKEN) {
    result.push({ type: "telegram", create: () => new TelegramAdapter(process.env.UC_TELEGRAM_TOKEN!) });
  }
  if (process.env.UC_DISCORD_TOKEN) {
    result.push({ type: "discord", create: () => new DiscordAdapter(process.env.UC_DISCORD_TOKEN!) });
  }
  if (process.env.UC_SLACK_BOT_TOKEN && process.env.UC_SLACK_APP_TOKEN) {
    result.push({ type: "slack", create: () => new SlackAdapter(process.env.UC_SLACK_BOT_TOKEN!, process.env.UC_SLACK_APP_TOKEN!) });
  }
  if (process.env.UC_MATTERMOST_URL && process.env.UC_MATTERMOST_TOKEN) {
    result.push({ type: "mattermost", create: () => new MattermostAdapter(process.env.UC_MATTERMOST_URL!, process.env.UC_MATTERMOST_TOKEN!) });
  }
  if (process.env.UC_IRC_SERVER && process.env.UC_IRC_NICK && process.env.UC_IRC_CHANNELS) {
    result.push({ type: "irc", create: () => new IRCAdapter(process.env.UC_IRC_SERVER!, process.env.UC_IRC_NICK!, process.env.UC_IRC_CHANNELS!.split(","), Number(process.env.UC_IRC_PORT) || 6667) });
  }
  if (process.env.UC_WHATSAPP_TOKEN && process.env.UC_WHATSAPP_PHONE_ID) {
    result.push({ type: "whatsapp", create: () => new WhatsAppAdapter(process.env.UC_WHATSAPP_TOKEN!, process.env.UC_WHATSAPP_PHONE_ID!, process.env.UC_WHATSAPP_VERIFY_TOKEN || "verify", Number(process.env.UC_WHATSAPP_PORT) || 9000) });
  }
  if (process.env.UC_LINE_CHANNEL_SECRET && process.env.UC_LINE_CHANNEL_ACCESS_TOKEN) {
    result.push({ type: "line", create: () => new LINEAdapter(process.env.UC_LINE_CHANNEL_SECRET!, process.env.UC_LINE_CHANNEL_ACCESS_TOKEN!, Number(process.env.UC_LINE_PORT) || 9001) });
  }
  if (process.env.UC_FEISHU_APP_ID && process.env.UC_FEISHU_APP_SECRET) {
    result.push({ type: "feishu", create: () => new FeishuAdapter(process.env.UC_FEISHU_APP_ID!, process.env.UC_FEISHU_APP_SECRET!, Number(process.env.UC_FEISHU_PORT) || 9002) });
  }
  if (process.env.UC_MSTEAMS_APP_ID && process.env.UC_MSTEAMS_APP_PASSWORD) {
    result.push({ type: "msteams", create: () => new MSTeamsAdapter(process.env.UC_MSTEAMS_APP_ID!, process.env.UC_MSTEAMS_APP_PASSWORD!, Number(process.env.UC_MSTEAMS_PORT) || 9003) });
  }
  if (process.env.UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY) {
    result.push({ type: "googlechat", create: () => new GoogleChatAdapter(process.env.UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY!, Number(process.env.UC_GOOGLECHAT_PORT) || 9004) });
  }
  if (process.env.UC_SYNOLOGY_URL && process.env.UC_SYNOLOGY_INCOMING_TOKEN && process.env.UC_SYNOLOGY_OUTGOING_URL) {
    result.push({ type: "synology", create: () => new SynologyChatAdapter(process.env.UC_SYNOLOGY_URL!, process.env.UC_SYNOLOGY_INCOMING_TOKEN!, process.env.UC_SYNOLOGY_OUTGOING_URL!, Number(process.env.UC_SYNOLOGY_PORT) || 9005) });
  }
  if (process.env.UC_ZALO_ACCESS_TOKEN) {
    result.push({ type: "zalo", create: () => new ZaloAdapter(process.env.UC_ZALO_ACCESS_TOKEN!, Number(process.env.UC_ZALO_PORT) || 9006) });
  }
  if (process.env.UC_NOSTR_PRIVATE_KEY && process.env.UC_NOSTR_RELAYS) {
    result.push({ type: "nostr", create: () => new NostrAdapter(process.env.UC_NOSTR_PRIVATE_KEY!, process.env.UC_NOSTR_RELAYS!.split(",")) });
  }
  if (process.env.UC_TWITCH_USERNAME && process.env.UC_TWITCH_OAUTH && process.env.UC_TWITCH_CHANNELS) {
    result.push({ type: "twitch", create: () => new TwitchAdapter(process.env.UC_TWITCH_USERNAME!, process.env.UC_TWITCH_OAUTH!, process.env.UC_TWITCH_CHANNELS!.split(",")) });
  }
  if (process.env.UC_BLUEBUBBLES_URL && process.env.UC_BLUEBUBBLES_PASSWORD) {
    result.push({ type: "bluebubbles", create: () => new BlueBubblesAdapter(process.env.UC_BLUEBUBBLES_URL!, process.env.UC_BLUEBUBBLES_PASSWORD!) });
  }
  if (process.env.UC_NEXTCLOUD_URL && process.env.UC_NEXTCLOUD_USER && process.env.UC_NEXTCLOUD_PASSWORD && process.env.UC_NEXTCLOUD_ROOMS) {
    result.push({ type: "nextcloud", create: () => new NextcloudTalkAdapter(process.env.UC_NEXTCLOUD_URL!, process.env.UC_NEXTCLOUD_USER!, process.env.UC_NEXTCLOUD_PASSWORD!, process.env.UC_NEXTCLOUD_ROOMS!.split(",")) });
  }
  if (process.env.UC_IMESSAGE_ENABLED === "1") {
    result.push({ type: "imessage", create: () => new IMessageAdapter() });
  }
  if (process.env.UC_MATRIX_HOMESERVER && process.env.UC_MATRIX_TOKEN) {
    result.push({ type: "matrix", create: () => new MatrixAdapter(process.env.UC_MATRIX_HOMESERVER!, process.env.UC_MATRIX_TOKEN!) });
  }

  return result;
}

/** Create adapters from YAML config entries */
function createAdaptersFromConfig(channels: Record<string, Record<string, string>>): { type: string; create: () => ChannelAdapter }[] {
  const result: { type: string; create: () => ChannelAdapter }[] = [];

  for (const [name, cfg] of Object.entries(channels)) {
    switch (name) {
      case "telegram":
        if (cfg.token) result.push({ type: "telegram", create: () => new TelegramAdapter(cfg.token) });
        break;
      case "discord":
        if (cfg.token) result.push({ type: "discord", create: () => new DiscordAdapter(cfg.token) });
        break;
      case "slack":
        if (cfg.bot_token && cfg.app_token) result.push({ type: "slack", create: () => new SlackAdapter(cfg.bot_token, cfg.app_token) });
        break;
      case "mattermost":
        if (cfg.url && cfg.token) result.push({ type: "mattermost", create: () => new MattermostAdapter(cfg.url, cfg.token) });
        break;
      case "irc":
        if (cfg.server && cfg.nick && cfg.channels) result.push({ type: "irc", create: () => new IRCAdapter(cfg.server, cfg.nick, cfg.channels.split(","), Number(cfg.port) || 6667) });
        break;
      case "whatsapp":
        if (cfg.token && cfg.phone_id) result.push({ type: "whatsapp", create: () => new WhatsAppAdapter(cfg.token, cfg.phone_id, cfg.verify_token || "verify", Number(cfg.port) || 9000) });
        break;
      case "line":
        if (cfg.channel_secret && cfg.channel_access_token) result.push({ type: "line", create: () => new LINEAdapter(cfg.channel_secret, cfg.channel_access_token, Number(cfg.port) || 9001) });
        break;
      case "feishu":
        if (cfg.app_id && cfg.app_secret) result.push({ type: "feishu", create: () => new FeishuAdapter(cfg.app_id, cfg.app_secret, Number(cfg.port) || 9002) });
        break;
      case "msteams":
        if (cfg.app_id && cfg.app_password) result.push({ type: "msteams", create: () => new MSTeamsAdapter(cfg.app_id, cfg.app_password, Number(cfg.port) || 9003) });
        break;
      case "googlechat":
        if (cfg.service_account_key) result.push({ type: "googlechat", create: () => new GoogleChatAdapter(cfg.service_account_key, Number(cfg.port) || 9004) });
        break;
      case "synology":
        if (cfg.url && cfg.incoming_token && cfg.outgoing_url) result.push({ type: "synology", create: () => new SynologyChatAdapter(cfg.url, cfg.incoming_token, cfg.outgoing_url, Number(cfg.port) || 9005) });
        break;
      case "zalo":
        if (cfg.access_token) result.push({ type: "zalo", create: () => new ZaloAdapter(cfg.access_token, Number(cfg.port) || 9006) });
        break;
      case "nostr":
        if (cfg.private_key && cfg.relays) result.push({ type: "nostr", create: () => new NostrAdapter(cfg.private_key, cfg.relays.split(",")) });
        break;
      case "twitch":
        if (cfg.username && cfg.oauth && cfg.channels) result.push({ type: "twitch", create: () => new TwitchAdapter(cfg.username, cfg.oauth, cfg.channels.split(",")) });
        break;
      case "bluebubbles":
        if (cfg.url && cfg.password) result.push({ type: "bluebubbles", create: () => new BlueBubblesAdapter(cfg.url, cfg.password) });
        break;
      case "nextcloud":
        if (cfg.url && cfg.user && cfg.password && cfg.rooms) result.push({ type: "nextcloud", create: () => new NextcloudTalkAdapter(cfg.url, cfg.user, cfg.password, cfg.rooms.split(",")) });
        break;
      case "imessage":
        if (cfg.enabled === "1" || cfg.enabled === "true") result.push({ type: "imessage", create: () => new IMessageAdapter() });
        break;
      case "matrix":
        if (cfg.homeserver && cfg.token) result.push({ type: "matrix", create: () => new MatrixAdapter(cfg.homeserver, cfg.token) });
        break;
    }
  }

  return result;
}

async function connectAdapters(configs: { type: string; create: () => ChannelAdapter }[]): Promise<void> {
  for (const { type, create } of configs) {
    if (adapters.has(type)) {
      console.error(`[unified-channel] Skipping ${type} (already connected)`);
      continue;
    }
    try {
      const adapter = create();
      adapter.onMessage((msg: any) => {
        messageBuffer.push({
          id: msg.id, channel: msg.channel,
          sender: msg.sender?.username || msg.sender?.id || "unknown",
          text: msg.content?.text || "", timestamp: new Date().toISOString(),
          chatId: msg.chatId || "",
        });
        if (messageBuffer.length > MAX_BUFFER) messageBuffer.splice(0, messageBuffer.length - MAX_BUFFER);
      });
      await adapter.connect();
      adapters.set(type, adapter);
      console.error(`[unified-channel] ● ${type} connected`);
    } catch (e: any) {
      console.error(`[unified-channel] ✗ ${type}: ${e.message}`);
    }
  }
}

async function main() {
  const server = new McpServer({
    name: "unified-channel",
    version: "0.1.0",
  });

  // ---- Tools ----

  server.tool(
    "send_message",
    "Send a message to a user/chat on any connected channel (Telegram, Discord, Slack, WhatsApp, Matrix, etc.)",
    {
      channel: z.string().describe("Channel to send on: " + ALL_CHANNELS.join(", ")),
      chat_id: z.string().describe("Chat/channel/room ID to send the message to"),
      text: z.string().describe("Message text to send"),
      reply_to_id: z.string().optional().describe("Optional message ID to reply to"),
    },
    async ({ channel, chat_id, text, reply_to_id }) => {
      const adapter = adapters.get(channel);
      if (!adapter) {
        return { content: [{ type: "text" as const, text: `Channel "${channel}" is not connected. Connected: ${[...adapters.keys()].join(", ") || "none"}` }] };
      }
      try {
        const msgId = await adapter.send({ chatId: chat_id, text, replyToId: reply_to_id });
        return { content: [{ type: "text" as const, text: `Sent on ${channel} to ${chat_id}. ID: ${msgId ?? "unknown"}` }] };
      } catch (e: any) {
        return { content: [{ type: "text" as const, text: `Failed: ${e.message}` }], isError: true };
      }
    }
  );

  server.tool(
    "broadcast_message",
    "Send the same message to multiple channels at once",
    {
      text: z.string().describe("Message text to broadcast"),
      targets: z.record(z.string(), z.string()).describe("Map of channel name to chat ID, e.g. { telegram: '123', discord: '456' }"),
    },
    async ({ text, targets }) => {
      const results: string[] = [];
      for (const [ch, chatId] of Object.entries(targets)) {
        const adapter = adapters.get(ch);
        if (!adapter) { results.push(`${ch}: not connected`); continue; }
        try { await adapter.send({ chatId, text }); results.push(`${ch}: sent`); }
        catch (e: any) { results.push(`${ch}: failed (${e.message})`); }
      }
      return { content: [{ type: "text" as const, text: results.join("\n") }] };
    }
  );

  server.tool(
    "get_channel_status",
    "Check the connection status of all configured channels",
    {},
    async () => {
      if (adapters.size === 0) {
        return { content: [{ type: "text" as const, text: "No channels configured. Set UC_TELEGRAM_TOKEN, UC_DISCORD_TOKEN, etc. or use load_config." }] };
      }
      const lines: string[] = [];
      for (const [name, adapter] of adapters) {
        try {
          const s = await adapter.getStatus();
          lines.push(`${s.connected ? "●" : "○"} ${name}${s.accountId ? ` (${s.accountId})` : ""}${s.lastActivity ? ` — last: ${s.lastActivity.toISOString()}` : ""}`);
        } catch (e: any) { lines.push(`✗ ${name}: ${e.message}`); }
      }
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    }
  );

  server.tool(
    "list_channels",
    "List all 18 supported channel types and which ones are currently connected",
    {},
    async () => {
      const lines = ALL_CHANNELS.map(ch => `${adapters.has(ch) ? "●" : "○"} ${ch}${adapters.has(ch) ? " (connected)" : ""}`);
      return { content: [{ type: "text" as const, text: `Channels:\n${lines.join("\n")}\n\nConnected: ${adapters.size}/${ALL_CHANNELS.length}` }] };
    }
  );

  server.tool(
    "get_recent_messages",
    "Get recent messages received across all connected channels",
    {
      limit: z.number().optional().describe("Max messages to return (default 20)"),
      channel: z.string().optional().describe("Filter by channel name"),
    },
    async ({ limit, channel }) => {
      let msgs = [...messageBuffer];
      if (channel) msgs = msgs.filter(m => m.channel === channel);
      msgs = msgs.slice(-(limit ?? 20));
      if (msgs.length === 0) return { content: [{ type: "text" as const, text: "No recent messages." }] };
      const formatted = msgs.map(m => `[${m.timestamp}] ${m.channel}/${m.chatId} @${m.sender}: ${m.text}`).join("\n");
      return { content: [{ type: "text" as const, text: formatted }] };
    }
  );

  server.tool(
    "load_config",
    "Load channel configuration from a YAML file",
    { path: z.string().describe("Path to unified-channel.yaml config file") },
    async ({ path }) => {
      try {
        const content = fs.readFileSync(path, "utf-8");
        const config = parseSimpleYaml(content);
        const channelCount = Object.keys(config.channels).length;
        if (channelCount === 0) {
          return { content: [{ type: "text" as const, text: "No channels found in config file." }] };
        }

        const configs = createAdaptersFromConfig(config.channels);
        await connectAdapters(configs);

        const connected = [...adapters.keys()];
        return { content: [{ type: "text" as const, text: `Loaded ${channelCount} channel(s) from ${path}. Connected: ${connected.join(", ") || "none"}` }] };
      } catch (e: any) {
        return { content: [{ type: "text" as const, text: `Failed to load config: ${e.message}` }], isError: true };
      }
    }
  );

  // ---- Resource ----

  server.resource(
    "channels-config",
    "unified-channel://config",
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: JSON.stringify({
          connected: [...adapters.keys()],
          env_vars: {
            UC_TELEGRAM_TOKEN: "Telegram bot token",
            UC_DISCORD_TOKEN: "Discord bot token",
            UC_SLACK_BOT_TOKEN: "Slack bot token (xoxb-...)",
            UC_SLACK_APP_TOKEN: "Slack app token (xapp-...)",
            UC_MATTERMOST_URL: "Mattermost server URL",
            UC_MATTERMOST_TOKEN: "Mattermost access token",
            UC_IRC_SERVER: "IRC server hostname",
            UC_IRC_NICK: "IRC nickname",
            UC_IRC_CHANNELS: "Comma-separated IRC channels",
            UC_IRC_PORT: "IRC port (default 6667)",
            UC_WHATSAPP_TOKEN: "WhatsApp Cloud API token",
            UC_WHATSAPP_PHONE_ID: "WhatsApp phone number ID",
            UC_WHATSAPP_VERIFY_TOKEN: "WhatsApp webhook verify token",
            UC_WHATSAPP_PORT: "WhatsApp webhook port (default 9000)",
            UC_LINE_CHANNEL_SECRET: "LINE channel secret",
            UC_LINE_CHANNEL_ACCESS_TOKEN: "LINE channel access token",
            UC_LINE_PORT: "LINE webhook port (default 9001)",
            UC_FEISHU_APP_ID: "Feishu/Lark app ID",
            UC_FEISHU_APP_SECRET: "Feishu/Lark app secret",
            UC_FEISHU_PORT: "Feishu webhook port (default 9002)",
            UC_MSTEAMS_APP_ID: "MS Teams app ID",
            UC_MSTEAMS_APP_PASSWORD: "MS Teams app password",
            UC_MSTEAMS_PORT: "MS Teams webhook port (default 9003)",
            UC_GOOGLECHAT_SERVICE_ACCOUNT_KEY: "Path to Google Chat service account JSON",
            UC_GOOGLECHAT_PORT: "Google Chat webhook port (default 9004)",
            UC_SYNOLOGY_URL: "Synology Chat server URL",
            UC_SYNOLOGY_INCOMING_TOKEN: "Synology incoming webhook token",
            UC_SYNOLOGY_OUTGOING_URL: "Synology outgoing webhook URL",
            UC_SYNOLOGY_PORT: "Synology webhook port (default 9005)",
            UC_ZALO_ACCESS_TOKEN: "Zalo OA access token",
            UC_ZALO_PORT: "Zalo webhook port (default 9006)",
            UC_NOSTR_PRIVATE_KEY: "Nostr private key (hex)",
            UC_NOSTR_RELAYS: "Comma-separated Nostr relay URLs",
            UC_TWITCH_USERNAME: "Twitch username",
            UC_TWITCH_OAUTH: "Twitch OAuth token",
            UC_TWITCH_CHANNELS: "Comma-separated Twitch channels",
            UC_BLUEBUBBLES_URL: "BlueBubbles server URL",
            UC_BLUEBUBBLES_PASSWORD: "BlueBubbles server password",
            UC_NEXTCLOUD_URL: "Nextcloud server URL",
            UC_NEXTCLOUD_USER: "Nextcloud username",
            UC_NEXTCLOUD_PASSWORD: "Nextcloud password/app token",
            UC_NEXTCLOUD_ROOMS: "Comma-separated Nextcloud Talk room tokens",
            UC_IMESSAGE_ENABLED: "Set to 1 to enable iMessage (macOS only)",
            UC_MATRIX_HOMESERVER: "Matrix homeserver URL",
            UC_MATRIX_TOKEN: "Matrix access token",
            UC_CONFIG_PATH: "Path to unified-channel.yaml config file",
          },
        }, null, 2),
        mimeType: "application/json",
      }],
    })
  );

  // ---- Load config from UC_CONFIG_PATH at startup ----

  if (process.env.UC_CONFIG_PATH) {
    try {
      const content = fs.readFileSync(process.env.UC_CONFIG_PATH, "utf-8");
      const config = parseSimpleYaml(content);
      const yamlConfigs = createAdaptersFromConfig(config.channels);
      await connectAdapters(yamlConfigs);
      console.error(`[unified-channel] Loaded config from ${process.env.UC_CONFIG_PATH}`);
    } catch (e: any) {
      console.error(`[unified-channel] Failed to load config from ${process.env.UC_CONFIG_PATH}: ${e.message}`);
    }
  }

  // ---- Connect channels from env vars ----

  const envConfigs = parseAndCreateAdapters();
  await connectAdapters(envConfigs);

  if (adapters.size === 0) {
    console.error("[unified-channel] No channels configured. Set UC_TELEGRAM_TOKEN, UC_DISCORD_TOKEN, etc. or UC_CONFIG_PATH.");
  }

  // ---- Start ----

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[unified-channel] MCP server running (${adapters.size} channels)`);
}

main().catch((e) => {
  console.error("[unified-channel] Fatal:", e);
  process.exit(1);
});
