# AI Customer Service System — API Reference

Telegram Group + WebChat 客服系统，基于 unified-channel 构建。

## Architecture

```
Browser ──WebSocket──→ WebChatAdapter (:8081/ws)
                              ↓
Mobile ──HTTP──→ WKIMCompatAdapter (:8080)     ChannelManager
                              ↓                     ↓
                         route by channel      on_message handler
                              ↓                     ↓
                     ┌── webchat/wkim ──→ forward_to_telegram()
                     │                         ↓
                     │              AI FAQ match? → reply directly
                     │                         ↓ (no match)
                     │              Create Telegram topic in support group
                     │              Agent sees message + user info
                     │
                     └── telegram ──→ forward_to_user()
                                         ↓
                              Agent reply → auto-translate → send to customer
                              /close → CSAT rating → close topic
```

---

## 1. WebChat (Customer-Facing WebSocket)

### Connect

```
ws://HOST:8081/ws
ws://HOST:8081/ws?user_id=C10086&name=张三&phone=138xxxx
ws://HOST:8081/ws?session_id=abc123def456
```

| Query Param | Required | Description |
|-------------|----------|-------------|
| `user_id` | No | Platform user ID (authenticated mode) |
| `name` | No | Display name |
| `phone` | No | Phone number |
| `session_id` | No | Resume previous anonymous session (from localStorage) |

On connect, server sends:

```json
{
  "type": "system",
  "text": "connected",
  "session_id": "abc123def456",
  "user_type": "anonymous"
}
```

### Chat page

```
GET http://HOST:8081/chat
GET http://HOST:8081/chat?user_id=C10086&name=张三
```

### Wire Protocol (JSON over WebSocket)

#### Client → Server

**Text message:**
```json
{ "type": "text", "text": "How do I reset my password?" }
```

**Media (base64):**
```json
{
  "type": "media",
  "media_type": "image",
  "data": "data:image/png;base64,iVBOR...",
  "text": "screenshot"
}
```

**Upgrade to authenticated (post-connect):**
```json
{
  "type": "auth",
  "user_id": "C10086",
  "name": "张三",
  "phone": "138xxxx",
  "extra": { "vip_level": 3 }
}
```

**Rating callback:**
```json
{ "type": "callback", "callback_data": "rate:session123:5" }
```

#### Server → Client

**Text reply:**
```json
{ "type": "text", "text": "...", "id": "a1b2c3d4", "timestamp": "2026-03-09T14:30:00" }
```

**Media reply:**
```json
{ "type": "media", "media_type": "image", "url": "https://...", "text": "caption" }
```

**History (on reconnect):**
```json
{
  "type": "history",
  "messages": [
    { "sender": "user", "text": "hello", "timestamp": "..." },
    { "sender": "agent", "text": "hi!", "timestamp": "..." }
  ]
}
```

**Rating buttons:**
```json
{
  "type": "text",
  "text": "请为本次服务评分：",
  "buttons": [[
    { "label": "⭐", "callback_data": "rate:sess:1" },
    { "label": "⭐⭐⭐⭐⭐", "callback_data": "rate:sess:5" }
  ]]
}
```

**System events:**
```json
{ "type": "system", "text": "connected", "session_id": "...", "user_type": "anonymous" }
{ "type": "system", "text": "authenticated", "user_type": "authenticated" }
{ "type": "typing" }
```

### Health Check

```
GET /health → { "status": "ok", "sessions": 3 }
```

---

## 2. Agent Interface (Telegram Group)

Agents interact via a Telegram supergroup with forum topics. Each customer session = one topic.

### Agent Commands

| Command | Description |
|---------|-------------|
| `/erp [ID]` | Query ERP user info (mock) |
| `/order [phone/ID]` | Query orders (mock) |
| `/tpl [name]` | Send quick reply template (auto-translated) |
| `/ticket title` | Create a ticket |
| `/close` | Close session + send CSAT rating |
| `/history [N]` | View last N messages |
| `/lang` | Check user language + translation status |
| `/report [date]` | Daily report (sessions, messages, avg response time) |
| `/hotwords [days]` | Hot keyword analysis |
| `/help` | Show all commands |

### Topic Info (auto-created on first message)

```
👤 登录用户
• 会话ID: abc123
• 来源: webchat
• 客户ID: C10086
• 姓名: 张三
• 手机: 138xxxx
• 分配客服: agent-1
• 时间: 2026-03-09 14:30:00

📋 /erp C10086 | /order C10086
直接回复即可。输入 /help 查看所有命令。
```

---

## 3. Features

### AI Auto-Reply
- FAQ keyword matching (fast path)
- LLM-based reply via ModelRouter (if `CS_AI_ENABLED=true`)
- Customer can type "转人工" / "agent" to skip AI

### Auto-Translation
- Detects user language (heuristic + LLM fallback)
- Translates user→agent (to Chinese) and agent→user (to user's language)
- Uses ModelRouter (`translate` / `detect_lang` tasks)

### Session Persistence
- SQLite-backed (`cs_data.db`): sessions, messages, ratings, tickets
- Survives restart — topic mappings restored from DB
- Anonymous users: session_id stored in browser localStorage for reconnect

### Reply Timeout
- Configurable via `CS_REPLY_TIMEOUT` (default 180s)
- Alerts agents in topic if no reply within timeout

### CSAT Rating
- Sent on `/close` — customer rates 1-5 stars
- Stored in DB, included in `/report`

### Agent Assignment
- Round-robin to least-loaded agent (`CS_AGENTS`)
- Access control via `CS_ALLOWED_AGENTS` (Telegram user IDs)

### Sensitive Word Filter
- Configurable word list in code
- Flags matched messages to agents, still forwards

---

## 4. Sample Code

### 4.1 Minimal Browser Client

```javascript
const ws = new WebSocket('ws://localhost:8081/ws');
let sessionId = null;

ws.onmessage = (e) => {
  const data = JSON.parse(e.data);
  if (data.type === 'system') {
    sessionId = data.session_id;
    localStorage.setItem('cs_session_id', sessionId);
  } else if (data.type === 'text') {
    console.log('Agent:', data.text);
  } else if (data.type === 'history') {
    data.messages.forEach(m => console.log(`[${m.sender}] ${m.text}`));
  }
};

// Send message
ws.send(JSON.stringify({ type: 'text', text: 'Hello' }));

// Send image
function sendImage(file) {
  const reader = new FileReader();
  reader.onload = () => ws.send(JSON.stringify({
    type: 'media', media_type: 'image', data: reader.result, text: '',
  }));
  reader.readAsDataURL(file);
}
```

### 4.2 Embed in Your App

```html
<!-- iframe -->
<iframe src="http://localhost:8081/chat?user_id=C10086&name=张三"
        style="width:420px; height:680px; border:none; border-radius:16px;"></iframe>

<!-- Or via postMessage (SPA) -->
<script>
document.getElementById('chatFrame').contentWindow.postMessage({
  type: 'chat_user', user_id: 'C10086', name: '张三'
}, '*');
</script>
```

### 4.3 Reconnect with Session Persistence

```javascript
function buildWsUrl() {
  const base = `ws://${location.host}/ws`;
  const saved = localStorage.getItem('cs_session_id');
  return saved ? `${base}?session_id=${saved}` : base;
}
```

---

## 5. Configuration

All via environment variables (in `~/.env`):

```bash
# Required
CS_TELEGRAM_TOKEN=your-bot-token
CS_SUPPORT_GROUP_ID=-100xxxxxxxxxx

# Ports
WEBCHAT_PORT=8081          # default 8081
WKIM_PORT=8080             # default 8080

# AI auto-reply
CS_AI_ENABLED=false        # set true to enable
CS_ROUTER_AI_REPLY=deepseek

# Translation
CS_ROUTER_TRANSLATE=minimax
CS_ROUTER_DETECT_LANG=minimax

# LLM backends (configure whichever you use)
MINIMAX_API_KEY=sk-xxx
MINIMAX_BASE_URL=https://api.minimaxi.com/v1
MINIMAX_MODEL=MiniMax-Text-01
DEEPSEEK_API_KEY=sk-xxx
OPENAI_API_KEY=sk-xxx

# Agent management
CS_AGENTS=agent1,agent2           # comma-separated names
CS_ALLOWED_AGENTS=123,456         # Telegram user IDs (empty = open mode)

# Timeouts
CS_REPLY_TIMEOUT=180              # seconds before timeout alert
CS_HEALTH_INTERVAL=30             # health check interval
CS_DB_PATH=cs_data.db             # SQLite path
```

---

## 6. Quick Start

```bash
cd unified-channel

# Configure ~/.env with CS_TELEGRAM_TOKEN + CS_SUPPORT_GROUP_ID

# Run
.venv/bin/python examples/ai-customer-service/main.py

# Open: http://localhost:8081/chat
# Agent: Telegram support group
```
