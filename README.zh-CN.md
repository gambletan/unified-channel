<div align="center">

# unified-channel

### 19 个频道，1 套 API，将你的 AI Agent 部署到任何平台

[![PyPI](https://img.shields.io/pypi/v/unified-channel?color=blue&label=PyPI)](https://pypi.org/project/unified-channel/)
[![npm](https://img.shields.io/npm/v/unified-channel?color=red&label=npm)](https://www.npmjs.com/package/unified-channel)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-284%20passing-brightgreen.svg)]()

**告别平台专属机器人代码。** 只写一次 Agent 逻辑，部署到用户所在的每一个消息平台。

[快速开始](#快速开始) | [AI Agent 示例](#ai-agent-集成) | [19 个适配器](#频道适配器) | [API 参考](#api-参考)

</div>

---

### 问题

你开发了一个 Telegram 机器人。然后你的团队用 Slack，客户想要 WhatsApp，Discord 社群也需要。现在你得维护 4 套代码，做同样的事情，对接 4 套不同的 API。

### 解决方案

```
pip install unified-channel[telegram,discord,slack,whatsapp]
```

一个 `ChannelManager`，一条中间件管道，一种消息类型。**19 个频道。**

```python
manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="..."))
manager.add_channel(DiscordAdapter(token="..."))
manager.add_channel(SlackAdapter(bot_token="...", app_token="..."))

@manager.on_message
async def handle(msg):
    # msg.channel == "telegram" | "discord" | "slack" | ...
    # 同一段代码处理所有平台
    return await my_agent.chat(msg.content.text)
```

### 为什么选择 unified-channel

| | 没有 unified-channel | 使用 unified-channel |
|---|---|---|
| **添加频道** | 新 SDK、新消息格式、新认证流程、新部署 | `manager.add_channel(XAdapter(token="..."))` |
| **认证/限流** | 每个平台单独实现 | `add_middleware(AccessMiddleware(...))` — 全平台通用 |
| **后端发送** | 每个频道一套 API | `await manager.send("telegram", chat_id, text)` |
| **新增适配器** | 几天的工作量 | 1 个文件，5 个方法 |

### 内置功能

| 功能 | 说明 |
|---|---|
| **AccessMiddleware** | 跨频道用户白名单 |
| **CommandMiddleware** | `/command` 路由，带参数解析 |
| **RateLimitMiddleware** | 滑动窗口用户级限流 |
| **ConversationMemory** | 按会话保存历史（InMemory / SQLite / Redis） |
| **StreamingMiddleware** | 输入指示器 + LLM 分块推送 |
| **RichReply** | 表格、按钮、代码块 — 按平台自动降级 |
| **ServiceBridge** | 一行代码将任意函数暴露为聊天命令 |
| **Scheduler** | Cron + 定时周期任务 |
| **Dashboard** | 内置 Web 管理界面，含消息日志 + API |
| **I18n** | 语言检测 + 翻译辅助 |
| **VoiceMiddleware** | 语音转文字 / 文字转语音（OpenAI Whisper + TTS） |
| **YAML Config** | 从配置文件加载频道，支持环境变量插值 |

### 支持的频道

| 频道 | 模式 | 需要公网 URL |
|---|---|---|
| Telegram | 轮询 / Webhook | 否 |
| Discord | WebSocket | 否 |
| Slack | Socket Mode | 否 |
| WhatsApp | Webhook | 是 |
| iMessage | 数据库轮询 (macOS) | 否 |
| LINE | Webhook | 是 |
| Matrix | 同步 | 否 |
| MS Teams | Webhook | 是 |
| 飞书 / Lark | Webhook | 是 |
| Mattermost | WebSocket | 否 |
| Google Chat | Webhook | 是 |
| Twitch | IRC/WebSocket | 否 |
| IRC | TCP socket | 否 |
| Nostr | WebSocket (中继) | 否 |
| Zalo | Webhook | 是 |
| BlueBubbles | 轮询 | 否 |
| Nextcloud Talk | 轮询 | 否 |
| Synology Chat | Webhook | 是 |

### 中国平台支持（规划中）

unified-channel 计划支持以下中国主流消息平台：

| 平台 | 状态 | 说明 |
|---|---|---|
| **微信企业版（企业微信）** | 规划中 | 通过企业微信开放 API 接入 |
| **钉钉（DingTalk）** | 规划中 | 支持钉钉机器人 Webhook + Stream 模式 |
| **飞书（Feishu / Lark）** | 已支持 | 使用官方 lark-oapi SDK |
| **QQ** | 规划中 | 通过 QQ 机器人开放平台接入 |

欢迎社区贡献中国平台适配器！详见[编写自定义适配器](#编写自定义适配器)。

### 中国 AI 大模型支持

unified-channel 与 AI Agent 集成时，支持对接国产大模型：

| 模型 | 说明 | 示例用法 |
|---|---|---|
| **DeepSeek** | DeepSeek-V3 / DeepSeek-R1，兼容 OpenAI API | `openai.OpenAI(base_url="https://api.deepseek.com/v1")` |
| **通义千问（Qwen）** | 阿里云百炼平台，兼容 OpenAI API | `openai.OpenAI(base_url="https://dashscope.aliyuncs.com/compatible-mode/v1")` |
| **智谱 GLM（ChatGLM）** | 智谱 AI 开放平台 | `zhipuai.ZhipuAI(api_key="...")` |
| **百度文心一言（ERNIE）** | 百度千帆大模型平台 | 使用千帆 SDK |
| **讯飞星火（Spark）** | 科大讯飞星火大模型 | 使用讯飞开放平台 SDK |

示例：使用 DeepSeek 构建聊天 Agent：

```python
import openai
from unified_channel import ChannelManager, TelegramAdapter

# 使用 DeepSeek API（兼容 OpenAI 接口）
client = openai.OpenAI(
    api_key="your-deepseek-api-key",
    base_url="https://api.deepseek.com/v1",
)

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="BOT_TOKEN"))

@manager.on_message
async def handle(msg):
    # 调用 DeepSeek 模型
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": msg.content.text}],
    )
    return response.choices[0].message.content
```

### 多语言版本

| 语言 | 包名 | 安装 |
|---|---|---|
| **Python** | [unified-channel](https://pypi.org/project/unified-channel/) | `pip install unified-channel` |
| **TypeScript** | [unified-channel](https://www.npmjs.com/package/unified-channel) | `npm install unified-channel` |
| **Java** | [unified-channel-java](https://github.com/gambletan/unified-channel-java) | Maven / Gradle |

---

## 快速开始

```python
import asyncio
from unified_channel import ChannelManager, TelegramAdapter, CommandMiddleware

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="BOT_TOKEN"))

cmds = CommandMiddleware()
manager.add_middleware(cmds)

@cmds.command("status")
async def status(msg):
    return "All systems operational"  # 所有系统运行正常

@cmds.command("deploy")
async def deploy(msg):
    env = msg.content.args[0] if msg.content.args else "staging"
    # your_app.deploy(env)
    return f"Deploying to {env}..."  # 正在部署到 {env}...

asyncio.run(manager.run())
```

就这么简单。你的机器人已经上线，可以响应 `/status` 和 `/deploy staging`。

---

## 目录

- [安装](#安装)
- [核心概念](#核心概念)
- [频道适配器](#频道适配器)
  - [Telegram](#telegram)
  - [Discord](#discord)
  - [Slack](#slack)
  - [WhatsApp](#whatsapp)
  - [iMessage](#imessage)
  - [LINE](#line)
  - [Matrix](#matrix)
  - [Microsoft Teams](#microsoft-teams)
  - [飞书 / Lark](#飞书--lark)
- [中间件](#中间件)
  - [访问控制](#访问控制)
  - [命令路由](#命令路由)
  - [会话记忆](#会话记忆)
  - [流式推送与输入指示器](#流式推送与输入指示器)
  - [自定义中间件](#自定义中间件)
  - [中间件链顺序](#中间件链顺序)
- [富文本回复](#富文本回复)
- [发送消息](#发送消息)
- [多频道配置](#多频道配置)
- [消息类型](#消息类型)
- [编写自定义适配器](#编写自定义适配器)
- [ServiceBridge](#servicebridge)
- [YAML 配置](#yaml-配置)
- [实战示例](#实战示例)
- [API 参考](#api-参考)

---

## 安装

只安装你需要的适配器：

```bash
# 单个频道
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

# 无需额外依赖：iMessage、IRC
pip install unified-channel

# 多个频道
pip install unified-channel[telegram,discord,slack]

# 安装所有
pip install unified-channel[all]
```

需要 **Python 3.10+**。

### 国内镜像安装

在中国大陆，推荐使用清华大学 PyPI 镜像加速安装：

```bash
# 使用清华镜像源
pip install unified-channel[telegram,discord,slack] -i https://pypi.tuna.tsinghua.edu.cn/simple

# 永久配置镜像源
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

其他可用镜像：

| 镜像源 | 地址 |
|---|---|
| 清华大学 | `https://pypi.tuna.tsinghua.edu.cn/simple` |
| 阿里云 | `https://mirrors.aliyun.com/pypi/simple/` |
| 中国科技大学 | `https://pypi.mirrors.ustc.edu.cn/simple/` |
| 华为云 | `https://repo.huaweicloud.com/repository/pypi/simple/` |

---

## 核心概念

```
你的应用
  │
  ├─ ChannelManager              ← 统一调度
  │    ├─ Middleware Pipeline     ← 共享逻辑（认证、命令、限流、日志）
  │    │    ├─ AccessMiddleware
  │    │    ├─ CommandMiddleware
  │    │    └─ YourMiddleware
  │    │
  │    ├─ TelegramAdapter        ← 每个频道 1 个文件
  │    ├─ DiscordAdapter         ← 1 个文件
  │    ├─ SlackAdapter           ← 1 个文件
  │    ├─ WhatsAppAdapter        ← 1 个文件
  │    ├─ ... (19 个适配器)
  │    └─ IRCAdapter             ← 1 个文件
  │
  └─ UnifiedMessage              ← 统一消息类型，适用所有频道
```

**ChannelManager** 连接适配器和中间件。消息从任意适配器到达，流经中间件管道，回复通过同一适配器发回。

**UnifiedMessage** 是跨所有频道共享的统一消息类型 — 你的命令处理器永远不需要知道消息来自哪个平台。

**Middleware** 可组合。按任意顺序叠加访问控制、命令路由、限流、日志。

---

## 频道适配器

### Telegram

使用 [python-telegram-bot](https://python-telegram-bot.org/)。轮询模式，无需 Webhook 服务器。

```python
from unified_channel import TelegramAdapter

adapter = TelegramAdapter(
    token="123456:ABC-DEF...",
    parse_mode="Markdown",       # 默认值；也支持 "HTML"
)
```

**配置步骤：**
1. 在 Telegram 上向 [@BotFather](https://t.me/BotFather) 发送 `/newbot`
2. 复制获取的 token
3. 获取你的用户 ID：向 [@userinfobot](https://t.me/userinfobot) 发送消息

---

### Discord

使用 [discord.py](https://discordpy.readthedocs.io/)。通过 Gateway WebSocket 连接。

```python
from unified_channel import DiscordAdapter

adapter = DiscordAdapter(
    token="your-bot-token",
    allowed_channel_ids={123456789},  # 可选：限制特定频道
    allow_dm=True,                    # 接受私信（默认 True）
    command_prefix="/",               # 默认 "/"
)
```

**配置步骤：**
1. 在 [discord.com/developers](https://discord.com/developers/applications) 创建应用
2. Bot → 启用 **Message Content Intent**
3. 复制 Bot token
4. 邀请链接：`https://discord.com/oauth2/authorize?client_id=APP_ID&scope=bot&permissions=3072`

---

### Slack

使用 [slack-bolt](https://slack.dev/bolt-python/) Socket Mode（无需公网 URL）。

```python
from unified_channel import SlackAdapter

adapter = SlackAdapter(
    bot_token="xoxb-...",
    app_token="xapp-...",            # Socket Mode token
    allowed_channel_ids={"C01234"},   # 可选
    command_prefix="/",
)
```

**配置步骤：**
1. 在 [api.slack.com/apps](https://api.slack.com/apps) 创建应用
2. 启用 **Socket Mode** → 生成 App-Level Token (`xapp-...`)
3. **OAuth & Permissions** → 添加权限：`chat:write`, `channels:history`, `im:history`
4. **Event Subscriptions** → 订阅 `message.channels`, `message.im`
5. 安装到工作区 → 复制 Bot Token (`xoxb-...`)

---

### WhatsApp

使用 Meta 的 [WhatsApp Business Cloud API](https://developers.facebook.com/docs/whatsapp/cloud-api)。Webhook 模式 — 需要公网 URL。

```python
from unified_channel import WhatsAppAdapter

adapter = WhatsAppAdapter(
    access_token="EAABx...",          # 永久 token
    phone_number_id="1234567890",
    verify_token="my-verify-token",   # 自定义验证令牌
    app_secret="abc123",              # 可选，用于签名验证
    port=8443,
)
```

**配置步骤：**
1. 在 [developers.facebook.com](https://developers.facebook.com/) 创建应用
2. 添加 **WhatsApp** 产品
3. 从 WhatsApp 控制台获取永久 access token + phone number ID
4. 设置 Webhook URL 为 `https://your-server:8443/whatsapp/webhook`
5. 设置 verify token 与你的 `verify_token` 参数一致

---

### iMessage

**仅限 macOS。** 无需外部依赖。轮询 Messages 的 SQLite 数据库获取消息，通过 AppleScript 发送。

```python
from unified_channel import IMessageAdapter

adapter = IMessageAdapter(
    allowed_numbers={"+1234567890"},  # 可选：限制发送者
    poll_interval=3.0,                # 轮询间隔秒数（默认 3）
)
```

**要求：**
- macOS，且 Messages.app 已登录 iMessage
- 进程需要 **完全磁盘访问** 权限（系统设置 → 隐私与安全 → 完全磁盘访问权限）
- Messages.app 必须运行中

---

### LINE

使用官方 [LINE Bot SDK v3](https://github.com/line/line-bot-sdk-python)。Webhook 模式。

```python
from unified_channel import LineAdapter

adapter = LineAdapter(
    channel_secret="your-channel-secret",
    channel_access_token="your-access-token",
    port=8080,
    path="/line/webhook",
)
```

**配置步骤：**
1. 在 [LINE Developers Console](https://developers.line.biz/) 创建频道
2. 获取 Channel Secret + Channel Access Token
3. 设置 Webhook URL 为 `https://your-server:8080/line/webhook`

---

### Matrix

使用 [matrix-nio](https://github.com/poljar/matrix-nio)。支持端到端加密。

```python
from unified_channel import MatrixAdapter

adapter = MatrixAdapter(
    homeserver="https://matrix.org",
    user_id="@bot:matrix.org",
    password="your-password",
    # 或者: access_token="syt_...",
    allowed_room_ids={"!abc:matrix.org"},  # 可选
    auto_join=True,                         # 自动接受邀请（默认 True）
)
```

**配置步骤：**
1. 在你的 Matrix 服务器上注册一个机器人账号
2. 端到端加密支持：`pip install unified-channel[matrix]` 会自动安装 `matrix-nio[e2e]`

---

### Microsoft Teams

使用 [Bot Framework SDK](https://github.com/microsoft/botbuilder-python)。Webhook 模式。

```python
from unified_channel import MSTeamsAdapter

adapter = MSTeamsAdapter(
    app_id="your-app-id",
    app_password="your-app-password",
    port=3978,
    path="/api/messages",
)
```

**配置步骤：**
1. 在 [Bot Framework Portal](https://dev.botframework.com/bots/new) 注册机器人
2. 获取 Microsoft App ID + Password
3. 设置消息端点为 `https://your-server:3978/api/messages`
4. 将机器人添加到你的 Teams 工作区

---

### 飞书 / Lark

使用官方 [lark-oapi SDK](https://github.com/larksuite/oapi-sdk-python)。Webhook 模式。

```python
from unified_channel import FeishuAdapter

adapter = FeishuAdapter(
    app_id="cli_xxx",
    app_secret="your-app-secret",
    verification_token="your-verify-token",  # 来自事件订阅配置
    port=9000,
    path="/feishu/webhook",
)
```

**配置步骤：**
1. 在[飞书开放平台](https://open.feishu.cn/)创建应用
2. 获取 App ID + App Secret
3. 启用**事件订阅** → 设置 Webhook URL
4. 添加 `im:message:receive_v1` 事件

---

### Mattermost

使用 WebSocket 接收事件 + REST API 发送消息。

```python
from unified_channel import MattermostAdapter

adapter = MattermostAdapter(
    url="https://mattermost.example.com",
    token="your-bot-token",
    allowed_channel_ids={"channel-id"},  # 可选
)
```

---

### Google Chat

使用 Google 服务账号 + Webhook。

```python
from unified_channel import GoogleChatAdapter

adapter = GoogleChatAdapter(
    service_account_file="service-account.json",
    port=8090,
)
```

---

### Twitch

IRC over WebSocket。默认命令前缀为 `!`（Twitch 惯例）。

```python
from unified_channel import TwitchAdapter

adapter = TwitchAdapter(
    oauth_token="oauth:your-token",
    bot_username="mybotname",
    channels=["#yourchannel"],
    command_prefix="!",
)
```

**配置步骤：** 在 [twitchapps.com/tmi](https://twitchapps.com/tmi/) 生成 token。

---

### IRC

纯 asyncio 实现 — 无需外部依赖。

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

NIP-04 加密私信，通过中继 WebSocket 通信。

```python
from unified_channel import NostrAdapter

adapter = NostrAdapter(
    private_key_hex="your-hex-private-key",
    relay_urls=["wss://relay.damus.io", "wss://nos.lol"],
)
```

---

### BlueBubbles

通过 [BlueBubbles](https://bluebubbles.app/) macOS 服务端 REST API 使用 iMessage。

```python
from unified_channel import BlueBubblesAdapter

adapter = BlueBubblesAdapter(
    server_url="http://localhost:1234",
    password="your-server-password",
)
```

---

### Zalo

Zalo Official Account API（越南）。

```python
from unified_channel import ZaloAdapter

adapter = ZaloAdapter(
    access_token="your-oa-access-token",
    port=8060,
)
```

---

### Nextcloud Talk

REST 轮询 — 自托管。

```python
from unified_channel import NextcloudTalkAdapter

adapter = NextcloudTalkAdapter(
    server_url="https://nextcloud.example.com",
    username="botuser",
    password="app-password",
    room_tokens=["room-token"],  # 可选；为空时自动发现
)
```

---

### Synology Chat

收发 Webhook — 基于 NAS 的聊天。

```python
from unified_channel import SynologyChatAdapter

adapter = SynologyChatAdapter(
    incoming_webhook_url="https://your-nas/webapi/entry.cgi?...",
    outgoing_token="your-outgoing-token",
    port=8070,
)
```

---

## 中间件

### 访问控制

限制谁可以与你的机器人交互：

```python
from unified_channel import AccessMiddleware

# 只有这些用户 ID 可以发送命令
manager.add_middleware(AccessMiddleware(
    allowed_user_ids={"123456", "789012"}
))

# 不设白名单 = 允许所有人
manager.add_middleware(AccessMiddleware())
```

被拦截的消息会被静默丢弃（不会发送回复）。

### 命令路由

注册 `/command` 处理器：

```python
from unified_channel import CommandMiddleware

cmds = CommandMiddleware()
manager.add_middleware(cmds)

# 装饰器方式
@cmds.command("help")
async def help_cmd(msg):
    return "Available: /status, /deploy, /logs"  # 可用命令列表

# 编程方式注册
async def status_handler(msg):
    return "OK"
cmds.register("status", status_handler)

# 获取命令参数
@cmds.command("deploy")
async def deploy(msg):
    # /deploy staging → msg.content.args = ["staging"]
    env = msg.content.args[0] if msg.content.args else "production"
    return f"Deploying to {env}"  # 正在部署到 {env}

# 列出已注册命令
print(cmds.registered_commands)  # ["help", "status", "deploy"]
```

非命令消息会传递到下一个中间件或回退处理器。

### 自定义中间件

实现 `Middleware` 基类：

```python
from unified_channel import Middleware, UnifiedMessage

class LoggingMiddleware(Middleware):
    """日志中间件：记录所有收发消息。"""
    async def process(self, msg, next_handler):
        print(f"[{msg.channel}] {msg.sender.id}: {msg.content.text}")
        result = await next_handler(msg)
        print(f"[{msg.channel}] reply: {result}")
        return result

class RateLimitMiddleware(Middleware):
    """限流中间件：限制每分钟消息数。"""
    def __init__(self, max_per_minute=10):
        self._counts = {}
        self._max = max_per_minute

    async def process(self, msg, next_handler):
        uid = msg.sender.id
        # ... 检查速率限制 ...
        if self._is_limited(uid):
            return "Too many requests. Please wait."  # 请求过于频繁，请稍候
        return await next_handler(msg)

class AdminOnlyMiddleware(Middleware):
    """管理员中间件：管理员与普通用户的区别处理。"""
    def __init__(self, admin_ids):
        self._admins = admin_ids

    async def process(self, msg, next_handler):
        if msg.content.command in ("shutdown", "restart"):
            if msg.sender.id not in self._admins:
                return "Admin only."  # 仅管理员可用
        return await next_handler(msg)
```

### 中间件链顺序

中间件按**添加顺序**运行。先添加的先执行：

```python
manager.add_middleware(LoggingMiddleware())      # 第 1 步：记录所有消息
manager.add_middleware(AccessMiddleware({...}))   # 第 2 步：检查访问权限
manager.add_middleware(RateLimitMiddleware())      # 第 3 步：速率限制
manager.add_middleware(cmds)                       # 第 4 步：路由命令
```

每个中间件调用 `next_handler(msg)` 传递到下一个，或返回字符串/`None` 来短路。

### 会话记忆

自动维护按会话的对话历史，并注入到每条消息中。非常适合需要上下文的 LLM Agent：

```python
from unified_channel import ConversationMemory, InMemoryStore, SQLiteStore

# 内存存储（默认）— 快速，重启后丢失
manager.add_middleware(ConversationMemory(max_turns=50))

# SQLite — 重启后保留
manager.add_middleware(ConversationMemory(
    store=SQLiteStore("memory.db"),
    max_turns=100,
))

# 在处理器中访问历史记录
@manager.on_message
async def chat(msg):
    history = msg.metadata["history"]  # [{"role", "content", "timestamp", ...}] 历史记录列表
    # 将历史传递给 LLM
    response = await llm.chat(messages=history + [{"role": "user", "content": msg.content.text}])
    return response
```

**存储后端：**

| 后端 | 持久化 | 使用场景 |
|---------|-------------|----------|
| `InMemoryStore()` | 否 | 开发、测试、无状态机器人 |
| `SQLiteStore(path)` | 是 | 单服务器生产部署 |
| `RedisStore(url)` | 是 | 多服务器 / 分布式部署 |

实现 `MemoryStore` 接口可以添加自定义后端（DynamoDB、Postgres 等）。

### 流式推送与输入指示器

处理消息时显示输入指示器，LLM 回复按块逐步推送：

```python
from unified_channel import StreamingMiddleware, StreamingReply

# 添加到管道 — 自动发送输入指示器
manager.add_middleware(StreamingMiddleware(
    typing_interval=3.0,  # 输入指示器发送间隔（秒）
    chunk_delay=0.5,      # 流式块之间的延迟（秒）
))

# 普通处理器自动获得输入指示器
@cmds.command("slow")
async def slow_command(msg):
    result = await expensive_computation()
    return result  # 计算期间自动显示输入指示器

# 返回 StreamingReply 实现逐步推送
@manager.on_message
async def chat(msg):
    stream = llm.stream_chat(msg.content.text)
    return StreamingReply.from_llm(stream)
```

---

## 富文本回复

使用流畅 API 构建跨平台富文本消息。表格、按钮、图片和代码块在不支持的频道上自动降级为纯文本：

```python
from unified_channel import RichReply, Button

reply = (
    RichReply("Server Status")  # 服务器状态
    .add_table(
        headers=["Service", "Status", "Uptime"],  # 服务、状态、运行时间
        rows=[
            ["API", "OK", "99.9%"],
            ["DB", "OK", "99.7%"],
            ["Cache", "WARN", "98.2%"],
        ],
    )
    .add_divider()
    .add_code("$ systemctl status api\n  Active: running", language="bash")
    .add_buttons([[
        Button(label="Restart API", callback_data="restart_api"),  # 重启 API
        Button(label="View Logs", url="https://logs.example.com"),  # 查看日志
    ]])
)

# 按频道自动选择最佳格式
outbound = reply.to_outbound("telegram")  # Markdown + inline_keyboard
outbound = reply.to_outbound("discord")   # Embeds + components
outbound = reply.to_outbound("slack")     # Blocks
outbound = reply.to_outbound("irc")       # 纯文本回退
```

在任意处理器中使用：

```python
@cmds.command("status")
async def status(msg):
    reply = RichReply("All systems operational").add_table(  # 所有系统运行正常
        ["Metric", "Value"],  # 指标、值
        [["Latency", "12ms"], ["Queue", "0"]],  # 延迟、队列
    )
    return reply.to_outbound(msg.channel)
```

---

## 发送消息

### 自动回复

命令处理器返回字符串 → 自动回复到同一会话：

```python
@cmds.command("ping")
async def ping(msg):
    return "pong"  # 自动回复给发送者的会话
```

### 主动推送

从应用任何位置发送消息：

```python
# 发送到指定频道 + 会话
await manager.send("telegram", chat_id="123456", text="Job complete!")  # 任务完成！

# 带选项
await manager.send(
    "telegram",
    chat_id="123456",
    text="*Alert*: disk usage 95%",  # 警报：磁盘使用率 95%
    parse_mode="Markdown",
)

# 广播到多个频道
await manager.broadcast(
    "Deploy v2.1.0 complete",  # 部署 v2.1.0 完成
    chat_ids={
        "telegram": "123456",
        "discord": "987654321",
        "slack": "C01ABCDEF",
    }
)
```

### 返回 OutboundMessage 获得完全控制

```python
from unified_channel import OutboundMessage, Button

@cmds.command("confirm")
async def confirm(msg):
    return OutboundMessage(
        chat_id=msg.chat_id,
        text="Are you sure?",  # 你确定吗？
        buttons=[[
            Button(label="Yes", callback_data="confirm_yes"),  # 是
            Button(label="No", callback_data="confirm_no"),    # 否
        ]],
        parse_mode="Markdown",
    )
```

---

## 多频道配置

同时运行多个频道 — 共享命令和中间件：

```python
from unified_channel import (
    ChannelManager, TelegramAdapter, DiscordAdapter, SlackAdapter,
    AccessMiddleware, CommandMiddleware,
)

manager = ChannelManager()

# 添加所有频道
manager.add_channel(TelegramAdapter(token="tg-token"))
manager.add_channel(DiscordAdapter(token="dc-token"))
manager.add_channel(SlackAdapter(bot_token="xoxb-...", app_token="xapp-..."))

# 共享中间件 — 所有频道通用
manager.add_middleware(AccessMiddleware(allowed_user_ids={"tg_123", "dc_456", "U0SLACK"}))

cmds = CommandMiddleware()
manager.add_middleware(cmds)

@cmds.command("status")
async def status(msg):
    # msg.channel 告诉你消息来自哪里
    return f"OK (via {msg.channel})"

asyncio.run(manager.run())
```

所有频道共享同一套命令处理器和中间件管道。一个 `/status` 命令无论从 Telegram、Discord 还是 Slack 发送，行为完全一致。

---

## 消息类型

### UnifiedMessage（传入消息）

每条传入消息，无论来自哪个频道，都会变成 `UnifiedMessage`：

```python
@manager.on_message
async def handler(msg):
    msg.id           # "12345" — 平台消息 ID
    msg.channel      # "telegram", "discord", "slack", ...
    msg.sender.id    # 发送者的平台用户 ID
    msg.sender.username
    msg.sender.display_name
    msg.content.type # ContentType.TEXT, COMMAND, MEDIA, CALLBACK, REACTION
    msg.content.text # 原始文本
    msg.content.command  # "status"（对应 /status）
    msg.content.args     # ["arg1", "arg2"]（对应 /status arg1 arg2）
    msg.chat_id      # 会话/频道/房间 ID
    msg.thread_id    # 线程 ID（如适用）
    msg.reply_to_id  # 被回复消息的 ID
    msg.timestamp    # datetime
    msg.raw          # 原始平台对象（高级用法）
    msg.metadata     # 自定义数据字典
```

### ContentType 枚举

```python
from unified_channel import ContentType

ContentType.TEXT      # 普通文本消息
ContentType.COMMAND   # 带解析参数的 /command
ContentType.MEDIA     # 图片、视频、文件
ContentType.CALLBACK  # 内联按钮点击
ContentType.REACTION  # 表情回应
ContentType.EDIT      # 编辑后的消息
```

---

## 编写自定义适配器

通过实现 `ChannelAdapter` 添加新频道 — 5 个方法，1 个文件：

```python
from unified_channel import ChannelAdapter, UnifiedMessage, OutboundMessage, ChannelStatus

class MyAdapter(ChannelAdapter):
    channel_id = "mychannel"

    async def connect(self) -> None:
        """建立连接（WebSocket、轮询、Webhook 服务器等）。"""
        ...

    async def disconnect(self) -> None:
        """优雅关闭。"""
        ...

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        """以 UnifiedMessage 形式产出传入消息。"""
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
        """发送消息。如果有的话返回消息 ID。"""
        result = await self._api.send(msg.chat_id, msg.text)
        return result.id

    async def get_status(self) -> ChannelStatus:
        """返回连接健康状态。"""
        return ChannelStatus(connected=self._connected, channel="mychannel")
```

然后注册：

```python
manager.add_channel(MyAdapter(...))
```

---

## ServiceBridge

`ServiceBridge` 是将任意服务暴露为聊天控制界面的最快方式。无需手动配置 `CommandMiddleware`，只需调用 `expose()` 即可自动获得 `/help`、参数解析、错误处理和同步函数支持。

```python
import asyncio
from unified_channel import ChannelManager, TelegramAdapter, ServiceBridge

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token="BOT_TOKEN"))

bridge = ServiceBridge(manager)

# 将任意函数暴露为聊天命令
bridge.expose("deploy", lambda args: f"Deploying to {args[0] if args else 'staging'}...",
              description="Deploy the app", params=["env"])  # 部署应用

# 同步或异步函数都可以
def disk_usage(args):
    import shutil
    total, used, free = shutil.disk_usage("/")
    return f"Disk: {used // (1 << 30)}G / {total // (1 << 30)}G"  # 磁盘用量

bridge.expose("disk", disk_usage, description="Check disk usage")  # 检查磁盘用量

# 内置 /status 和 /logs 快捷方式
bridge.expose_status(lambda args: "All systems operational")  # 所有系统运行正常
bridge.expose_logs(lambda args: open("app.log").readlines()[-10:])

# 处理器可以接收完整的 UnifiedMessage
async def whoami(args, msg):
    return f"You are {msg.sender.username} on {msg.channel}"  # 你是 {用户名}，来自 {频道}

bridge.expose("whoami", whoami, description="Show caller info")  # 显示调用者信息

asyncio.run(bridge.run())
```

这样你就拥有了 `/help`、`/deploy`、`/disk`、`/status`、`/logs` 和 `/whoami` — 全部带有自动错误处理。如果命令抛出异常，用户会收到友好的错误提示而不是沉默。

### Flag 解析

像 `--force` 和 `--count 3` 这样的参数会被自动解析：

```python
async def restart(args, msg):
    flags = msg.metadata.get("_flags", {})
    force = flags.get("force") == "true"
    service = args[0] if args else "all"
    return f"Restarting {service} (force={force})"  # 重启 {服务}（强制={force}）

bridge.expose("restart", restart, description="Restart services", params=["service"])
# /restart nginx --force  →  "Restarting nginx (force=True)"
```

---

## YAML 配置

用配置文件代替 Python 代码加载频道和中间件：

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

环境变量通过 `${VAR}` 语法插值。适配器根据名称自动检测。返回一个配置好的 `ChannelManager`，可以直接使用。

---

## 实战示例

一个完整的任务队列远程管理机器人：

```python
import asyncio
import os
from unified_channel import (
    ChannelManager, TelegramAdapter,
    AccessMiddleware, CommandMiddleware, UnifiedMessage,
)

# 你的应用导入
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
        f"*System Status*\n"           # 系统状态
        f"Queued: {m['queued']} | Running: {m['running']}\n"    # 排队 | 运行中
        f"Completed: {m['completed']} | Failed: {m['failed']}"  # 已完成 | 失败
    )


@cmds.command("accounts")
async def accounts(msg: UnifiedMessage) -> str:
    accs = list_accounts()
    lines = [f"  {a.name}: {a.status}" for a in accs]
    return "*Accounts*\n" + "\n".join(lines)  # 账户列表


@cmds.command("run")
async def run_job(msg: UnifiedMessage) -> str:
    if len(msg.content.args) < 2:
        return "Usage: /run <account> <job_type>"  # 用法
    account, job_type = msg.content.args[0], msg.content.args[1]
    job_id = queue.enqueue(account, job_type)
    return f"Enqueued: `{account}.{job_type}` (ID: `{job_id[:8]}...`)"  # 已入队


@cmds.command("logs")
async def logs(msg: UnifiedMessage) -> str:
    n = int(msg.content.args[0]) if msg.content.args else 10
    lines = open(f"logs/app.log").readlines()[-n:]
    return f"```\n{''.join(lines)}```"


# 从你的应用推送通知
async def on_job_failed(job_name, error):
    await manager.send("telegram", chat_id=os.environ["ADMIN_ID"],
                       text=f"Job failed: {job_name}\n{error}")  # 任务失败


@manager.on_message
async def fallback(msg: UnifiedMessage) -> str:
    return "Unknown command. Send /start for help."  # 未知命令，发送 /start 获取帮助


if __name__ == "__main__":
    asyncio.run(manager.run())
```

---

## AI Agent 集成

将 Claude（或任何 LLM）连接到你的 Telegram 机器人 — 用户自然对话，Agent 可以读取/编辑你的项目文件：

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

# 安全：仅管理员 + 限流
manager.add_middleware(AccessMiddleware(allowed_user_ids={os.environ["ADMIN_ID"]}))
manager.add_middleware(RateLimitMiddleware(max_messages=30, window_seconds=60))
manager.add_middleware(ConversationMemory(max_turns=50))

cmds = CommandMiddleware()
manager.add_middleware(cmds)

# 每个会话的 LLM 对话历史
chat_histories: dict[str, list[dict]] = {}
active_tasks: dict[str, asyncio.subprocess.Process] = {}

ALLOWED_MODELS = {"claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-6"}
model = "claude-sonnet-4-20250514"
work_dir = os.environ.get("CLAUDE_WORK_DIR", os.getcwd())


async def call_claude_cli(text: str, history: list, chat_id: str) -> str:
    """调用 Claude Code CLI，带项目上下文。"""
    import shutil
    claude_bin = shutil.which("claude")
    if not claude_bin:
        return "Claude CLI not found."  # 未找到 Claude CLI

    # 构建带对话历史的 prompt
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
        cwd=work_dir,  # Claude 在你的项目目录中工作
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
        return "Stopped."  # 已停止
    return "No active task."  # 无活跃任务


@cmds.command("model")
async def model_cmd(msg: UnifiedMessage) -> str:
    global model
    if msg.content.args:
        if msg.content.args[0] not in ALLOWED_MODELS:
            return f"Allowed: {', '.join(ALLOWED_MODELS)}"  # 允许的模型
        model = msg.content.args[0]
        return f"Model: `{model}`"  # 当前模型
    return f"Current: `{model}`"  # 当前模型


@cmds.command("clear")
async def clear_cmd(msg: UnifiedMessage) -> str:
    chat_histories.pop(msg.chat_id, None)
    return "History cleared."  # 历史已清除


@manager.on_message
async def on_message(msg: UnifiedMessage) -> str:
    text = msg.content.text
    if not text or not text.strip():
        return "Send a message to chat with Claude."  # 发送消息与 Claude 对话

    chat_id = msg.chat_id or "default"
    history = chat_histories.setdefault(chat_id, [])
    history.append({"role": "user", "content": text})

    if len(history) > 40:
        chat_histories[chat_id] = history[-40:]
        history = chat_histories[chat_id]

    reply = await call_claude_cli(text, history, chat_id)
    history.append({"role": "assistant", "content": reply})
    return reply


# 可选：定时报告 + Web 仪表板
scheduler = Scheduler(manager)
dashboard = Dashboard(manager, port=8080)


async def main():
    await dashboard.start()
    scheduler.every(3600, "telegram", os.environ["ADMIN_ID"],
                    lambda: "Hourly: all systems operational")  # 每小时报告：所有系统运行正常
    await manager.run()

asyncio.run(main())
```

**功能说明：**
- 通过 Telegram 与 Claude 自然对话 — Claude 可以读取你的项目文件
- `/stop` 终止长时间运行的 Claude 任务
- `/model claude-opus-4-6` 切换模型（白名单限制）
- `/clear` 重置对话历史
- 内置限流 + 访问控制
- `CLAUDE_WORK_DIR` 设置 Claude 的工作目录
- 每小时状态报告 + `localhost:8080` Web 仪表板

---

## API 参考

### ChannelManager

| 方法 | 说明 |
|--------|-------------|
| `add_channel(adapter)` | 注册频道适配器 |
| `add_middleware(mw)` | 添加中间件到管道 |
| `on_message(handler)` | 设置回退处理器（装饰器） |
| `await send(channel, chat_id, text, ...)` | 发送到指定频道 + 会话 |
| `await broadcast(text, chat_ids)` | 广播到多个频道 |
| `await get_status()` | 获取所有频道状态 |
| `await run()` | 启动所有频道（阻塞） |
| `await shutdown()` | 停止所有频道 |

### CommandMiddleware

| 方法 | 说明 |
|--------|-------------|
| `@command(name)` | 装饰器注册命令处理器 |
| `register(name, handler)` | 编程方式注册处理器 |
| `registered_commands` | 已注册命令名称列表 |

### AccessMiddleware

| 参数 | 说明 |
|-----------|-------------|
| `allowed_user_ids` | `set[str]` 允许的发送者 ID。`None` = 允许所有 |

### ConversationMemory

| 参数 | 说明 |
|-----------|-------------|
| `store` | `MemoryStore` 后端（`InMemoryStore`、`SQLiteStore`、`RedisStore`）。默认：`InMemoryStore()` |
| `max_turns` | 每个会话保留的最大历史条数。默认：`50` |

### RichReply

| 方法 | 说明 |
|--------|-------------|
| `add_text(text)` | 添加文本段落 |
| `add_table(headers, rows)` | 添加 ASCII/富文本表格 |
| `add_buttons(buttons)` | 添加按钮网格（`list[list[Button]]`） |
| `add_image(url, alt)` | 添加图片 |
| `add_code(code, language)` | 添加代码块 |
| `add_divider()` | 添加分隔线 |
| `to_plain_text()` | 渲染为纯文本（通用回退） |
| `to_telegram()` | 渲染为 Telegram Markdown + inline_keyboard |
| `to_discord()` | 渲染为 Discord embeds + components |
| `to_slack()` | 渲染为 Slack blocks |
| `to_outbound(channel)` | 自动选择频道最佳格式 |

### StreamingMiddleware

| 参数 | 说明 |
|-----------|-------------|
| `typing_interval` | 输入指示器发送间隔（秒）。默认：`3.0` |
| `chunk_delay` | 流式块之间的延迟（秒）。默认：`0.5` |

### StreamingReply

| 方法 | 说明 |
|--------|-------------|
| `StreamingReply(chunks)` | 包装 `AsyncIterator[str]` |
| `StreamingReply.from_llm(stream)` | 包装 LLM 流式响应 |

### ServiceBridge

| 方法 | 说明 |
|--------|-------------|
| `ServiceBridge(manager, prefix="/")` | 创建包装 `ChannelManager` 的 Bridge |
| `expose(name, handler, description, params)` | 将函数暴露为聊天命令 |
| `expose_status(handler)` | 注册 `/status` 命令 |
| `expose_logs(handler)` | 注册 `/logs` 命令 |
| `await run()` | 启动 Bridge（委托给 `manager.run()`） |

### load_config

| 函数 | 说明 |
|----------|-------------|
| `load_config(path)` | 加载 YAML 配置文件，返回配置好的 `ChannelManager` |

### 适配器列表

| 适配器 | 安装选项 | 模式 | 需要公网 URL |
|---------|--------------|------|-----------------|
| `TelegramAdapter` | `telegram` | 轮询 | 否 |
| `DiscordAdapter` | `discord` | WebSocket | 否 |
| `SlackAdapter` | `slack` | Socket Mode | 否 |
| `WhatsAppAdapter` | `whatsapp` | Webhook | **是** |
| `IMessageAdapter` | *（无）* | 数据库轮询 | 否（仅 macOS） |
| `LineAdapter` | `line` | Webhook | **是** |
| `MatrixAdapter` | `matrix` | 同步 | 否 |
| `MSTeamsAdapter` | `msteams` | Webhook | **是** |
| `FeishuAdapter` | `feishu` | Webhook | **是** |
| `MattermostAdapter` | `mattermost` | WebSocket | 否 |
| `GoogleChatAdapter` | `googlechat` | Webhook | **是** |
| `NextcloudTalkAdapter` | `nextcloud` | 轮询 | 否 |
| `SynologyChatAdapter` | `synology` | Webhook | **是** |
| `ZaloAdapter` | `zalo` | Webhook | **是** |
| `NostrAdapter` | `nostr` | WebSocket（中继） | 否 |
| `BlueBubblesAdapter` | `bluebubbles` | 轮询 | 否 |
| `TwitchAdapter` | `twitch` | IRC/WebSocket | 否 |
| `IRCAdapter` | *（无）* | TCP socket | 否 |

---

## 测试

127 个测试覆盖各个层级。运行方式：

```bash
pip install -e ".[dev]"
pytest -v
```

### 测试结构

| 文件 | 测试数 | 覆盖范围 |
|------|-------|----------------|
| `test_types.py` | 14 | 所有数据类型 — `ContentType`、`Identity`、`MessageContent`、`UnifiedMessage`、`OutboundMessage`、`Button`、`ChannelStatus`。默认值、完整构造、边界情况。 |
| `test_adapter.py` | 5 | `ChannelAdapter` 基类 — 连接/断开生命周期、`receive()` 异步迭代器、`send()` 返回值、`run_forever()` 取消行为、抽象实例化保护。 |
| `test_middleware.py` | 7 | `AccessMiddleware` — 允许、拦截、无白名单透传。`CommandMiddleware` — 路由、透传、参数解析、`registered_commands` 属性。 |
| `test_manager.py` | 4 | 核心 `ChannelManager` 管道 — 命令端到端、访问控制拦截、回退处理器、`get_status()`。 |
| `test_manager_advanced.py` | 14 | 多频道路由、`OutboundMessage` 返回、`send()` 直接推送、未知频道错误、`broadcast()`、中间件链顺序验证、短路、无回复/空回复情况、认证+命令组合、流畅 API 链式调用、无频道保护。 |
| `test_adapters_unit.py` | 32 | 模拟 SDK 的适配器单元测试：**IRC**（PRIVMSG 解析、命令、自消息忽略、DM 路由）、**iMessage**（仅 macOS）、**WhatsApp**（文本/命令/图片/回应/回复上下文）、**Mattermost**（文本/命令/自消息忽略/线程）、**Twitch**（文本/命令/自消息忽略/IRC tags）、**Zalo**（文本/命令）、**BlueBubbles/Synology/Nextcloud**（channel_id、状态）。全部 18 个适配器的延迟导入验证。 |
| `test_bridge.py` | 12 | `ServiceBridge` — 暴露命令、同步/异步处理器、参数/flag 解析、`/help` 生成、`/status` + `/logs` 快捷方式、错误处理、处理器签名检测。 |
| `test_config.py` | 8 | YAML 配置加载 — 环境变量插值（基本、嵌入、缺失、非字符串）、嵌套字典插值、模拟适配器完整配置解析、空文件错误、缺少 PyYAML 错误。 |
| `test_memory.py` | 12 | `InMemoryStore` CRUD（空、追加、裁剪、清除、隔离）。`ConversationMemory` 中间件（历史注入、用户+回复保存、无回复、max_turns 裁剪、独立会话）。`SQLiteStore`（CRUD、跨重启持久化）。 |
| `test_rich.py` | 12 | 流畅 API 链式调用、纯文本渲染（基本、表格、按钮、代码）、Telegram 输出（Markdown + inline_keyboard）、Discord embeds、Slack blocks、`to_outbound` 频道选择（telegram、discord、未知）、空回复。 |
| `test_streaming.py` | 7 | `StreamingReply` 块收集和 `from_llm`。`StreamingMiddleware` 输入任务生命周期（创建、取消、异常安全）、流式回复组装、无适配器回退、适配器输入指示器。 |

### 运行特定测试

```bash
# 仅适配器测试
pytest tests/test_adapters_unit.py -v

# 仅管理器管道
pytest tests/test_manager.py tests/test_manager_advanced.py -v

# 单个测试
pytest tests/test_adapters_unit.py::TestTwitchParsing::test_process_command -v
```

---

## 许可证

MIT
