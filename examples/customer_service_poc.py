"""
Customer Service IM — POC (Full-Featured)

支持两种客户端接入:
1. WebChat (新): 匿名/登录用户通过网页 WebSocket 聊天
2. WuKongIM 兼容 (旧): 现有 Android/iOS App 不改代码直接接入

全部功能:
- SQLite 持久化 (session/消息/评分/工单)
- 断线重连恢复 + 登录用户 Topic 复用
- 用户上下线通知
- 客服输入状态推送 + 超时未回复提醒
- 历史消息加载
- 自动语言检测 + 双向翻译
- /erp, /order, /ticket, /tpl, /close, /history, /report, /hotwords 命令
- 客服自动分配 (最少负载)
- 满意度评价
- AI 自动回复 (FAQ)
- 敏感词过滤
- 语音转文字 (OpenAI Whisper)
- 日报 + 热词分析

启动:
    export TELEGRAM_TOKEN="your-bot-token"
    export SUPPORT_GROUP_ID="-100xxxxxxxxxx"
    export OPENAI_API_KEY="sk-..."          # 翻译 + 语音转文字
    python examples/customer_service_poc.py
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env", override=True)

from aiohttp import web

from cs_store import CSStore
from model_router import ModelRouter
from unified_channel import ChannelManager
from unified_channel.adapters.telegram import TelegramAdapter
from unified_channel.adapters.webchat import WebChatAdapter
from unified_channel.adapters.wkim_compat import WKIMCompatAdapter
from unified_channel.health import HealthMonitor
from unified_channel.keyed_queue import KeyedAsyncQueue
from unified_channel.types import (
    Button,
    ContentType,
    OutboundMessage,
    UnifiedMessage,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
logger = logging.getLogger("customer_service")

# --- Config ---
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
SUPPORT_GROUP_ID = os.environ["SUPPORT_GROUP_ID"]
WEBCHAT_PORT = int(os.environ.get("WEBCHAT_PORT", "8081"))
WKIM_PORT = int(os.environ.get("WKIM_PORT", "8080"))
DB_PATH = os.environ.get("CS_DB_PATH", "cs_data.db")
AI_ENABLED = os.environ.get("CS_AI_ENABLED", "false").lower() == "true"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
MINIMAX_API_KEY = os.environ.get("MINIMAX_API_KEY", "")
REPLY_TIMEOUT_SECONDS = int(os.environ.get("CS_REPLY_TIMEOUT", "180"))  # 3 min

# --- Allowed agent user IDs (Telegram user IDs who can be in the support group) ---
# Bot's own messages are always allowed. Set via CS_ALLOWED_AGENTS env var (comma-separated Telegram user IDs)
# If empty, all group members are treated as agents (open mode).
ALLOWED_AGENTS: set[str] = set(
    a.strip() for a in os.environ.get("CS_ALLOWED_AGENTS", "").split(",") if a.strip()
)

# --- Model Router (task-based LLM routing) ---
router = ModelRouter.from_env()

# --- Persistent store ---
store = CSStore(DB_PATH)

# --- In-memory caches ---
session_to_topic: dict[str, int] = {}
topic_to_session: dict[int, str] = {}
session_channel: dict[str, str] = {}

# Track pending replies for timeout alerts
pending_replies: dict[str, asyncio.Task] = {}  # session_id → timeout task

# --- Keyed queue for per-customer message serialization ---
_msg_queue = KeyedAsyncQueue()

# --- Agent list ---
AGENTS: list[str] = os.environ.get("CS_AGENTS", "").split(",") if os.environ.get("CS_AGENTS") else []

# --- FAQ ---
FAQ: dict[str, str] = {
    "工作时间": "我们的客服工作时间是 周一至周五 9:00-18:00，周末 10:00-16:00。",
    "退货": "退货政策：自收货起7天内可无理由退货，请保持商品完好。需要我帮您办理退货吗？",
    "发货": "一般下单后1-3个工作日发货，您可以在订单详情查看物流信息。",
    "支付": "我们支持微信支付、支付宝、银行卡等多种支付方式。",
    "working hours": "Our service hours are Mon-Fri 9:00-18:00, Weekends 10:00-16:00.",
    "return": "Return policy: 7-day no-reason return from receipt. Want me to help process a return?",
    "shipping": "Orders ship within 1-3 business days. Check your order details for tracking.",
}

# --- Quick reply templates ---
TEMPLATES: dict[str, str] = {
    "欢迎": "您好！很高兴为您服务，请问有什么可以帮您？",
    "稍等": "好的，请您稍等，我帮您查一下。",
    "发货": "您的订单已发货，物流单号为 xxxxxx，请注意查收。",
    "退款": "退款申请已提交，预计1-3个工作日到账，请耐心等待。",
    "感谢": "感谢您的耐心等待，还有其他需要帮助的吗？",
    "结束": "感谢您的咨询，祝您生活愉快！如有需要随时联系我们。",
}

# --- Sensitive words ---
SENSITIVE_WORDS: list[str] = [
    # Add your sensitive words here
]


# =============================================================================
# Language Detection + Translation (OpenAI)
# =============================================================================

async def detect_language(text: str) -> str:
    """Detect language of text. Returns ISO 639-1 code."""
    if not text.strip():
        return "zh"

    # Simple heuristic for unique-script languages (avoid API call)
    chinese_ratio = len(re.findall(r'[\u4e00-\u9fff]', text)) / max(len(text), 1)
    if chinese_ratio > 0.3:
        return "zh"

    if re.search(r'[\u3040-\u309f\u30a0-\u30ff]', text):
        return "ja"
    if re.search(r'[\uac00-\ud7af]', text):
        return "ko"
    if re.search(r'[\u0e00-\u0e7f]', text):
        return "th"
    if re.search(r'[\u0600-\u06ff]', text):
        return "ar"
    if re.search(r'[\u0400-\u04ff]', text):
        return "ru"

    # Latin script — use LLM for accurate detection (fr/es/de/pt/etc.)
    if router.get_backend("detect_lang") and re.search(r'[a-zA-Z]{3,}', text):
        try:
            code = await router.chat(
                "detect_lang",
                [
                    {"role": "system", "content": "Detect the language of the text. Reply with ONLY the ISO 639-1 code (e.g. en, fr, de, es, pt, vi, id). Nothing else."},
                    {"role": "user", "content": text},
                ],
                temperature=0,
                max_tokens=5,
                timeout=5,
            )
            code = code.strip().lower()[:2]
            if re.match(r'^[a-z]{2}$', code):
                return code
        except Exception as e:
            logger.warning("language detection API failed: %s", e)

    # Fallback: Latin script = English
    if re.search(r'[a-zA-Z]{3,}', text):
        return "en"

    return "zh"


async def translate_text(text: str, target_lang: str, source_lang: str = "") -> str:
    """Translate text via ModelRouter. Returns translated text."""
    if not router.get_backend("translate") or not text.strip():
        return text

    if source_lang == target_lang:
        return text

    lang_names = {
        "zh": "Chinese", "en": "English", "ja": "Japanese", "ko": "Korean",
        "th": "Thai", "ar": "Arabic", "ru": "Russian", "es": "Spanish",
        "fr": "French", "de": "German", "pt": "Portuguese", "vi": "Vietnamese",
        "id": "Indonesian", "ms": "Malay", "tl": "Filipino",
    }
    target_name = lang_names.get(target_lang, target_lang)

    try:
        return await router.chat(
            "translate",
            [
                {"role": "system", "content": f"Translate the following text to {target_name}. Only output the translation, nothing else."},
                {"role": "user", "content": text},
            ],
            temperature=0.1,
            max_tokens=1000,
            timeout=10,
        )
    except Exception as e:
        logger.warning("translation failed: %s", e)
        return text


# =============================================================================
# Sensitive Word Filter
# =============================================================================

def check_sensitive(text: str) -> list[str]:
    """Check text for sensitive words. Returns list of matched words."""
    if not SENSITIVE_WORDS:
        return []
    matched = [w for w in SENSITIVE_WORDS if w in text]
    return matched


# =============================================================================
# Topic Management
# =============================================================================

async def get_or_create_topic(
    manager: ChannelManager, session_id: str, user_info: dict, channel: str
) -> int:
    if session_id in session_to_topic:
        return session_to_topic[session_id]

    db_session = store.get_session(session_id)
    if db_session and db_session.get("topic_id"):
        topic_id = db_session["topic_id"]
        session_to_topic[session_id] = topic_id
        topic_to_session[topic_id] = session_id
        return topic_id

    user_id = user_info.get("user_id")
    if user_id:
        existing = store.get_session_by_user_id(user_id)
        if existing and existing.get("topic_id"):
            topic_id = existing["topic_id"]
            session_to_topic[session_id] = topic_id
            topic_to_session[topic_id] = session_id
            store.set_topic_id(session_id, topic_id)
            return topic_id

    tg = manager._channels["telegram"]
    assert isinstance(tg, TelegramAdapter) and tg._app

    user_type = user_info.get("user_type", "anonymous")
    is_auth = user_type == "authenticated"
    name = user_info.get("name")

    topic_name = f"👤 {name or user_id}" if is_auth else f"💬 访客_{session_id[:6]}"

    topic = await tg._app.bot.create_forum_topic(
        chat_id=int(SUPPORT_GROUP_ID),
        name=topic_name,
    )
    topic_id = topic.message_thread_id

    session_to_topic[session_id] = topic_id
    topic_to_session[topic_id] = session_id
    session_channel[session_id] = channel

    store.create_session(
        session_id, topic_id=topic_id, channel=channel,
        user_type=user_type, user_id=user_id,
        user_name=name, user_phone=user_info.get("phone"),
    )

    assigned = auto_assign_agent(session_id)

    lines = [f"{'👤 登录用户' if is_auth else '💬 匿名访客'}"]
    lines.append(f"• 会话ID: `{session_id}`")
    lines.append(f"• 来源: {channel}")
    if is_auth:
        lines.append(f"• 客户ID: `{user_id}`")
        if name:
            lines.append(f"• 姓名: {name}")
        phone = user_info.get("phone")
        if phone:
            lines.append(f"• 手机: {phone}")
        lines.append(f"\n📋 `/erp {user_id}` | `/order {user_id}`")
    if assigned:
        lines.append(f"• 分配客服: {assigned}")
    lines.append(f"• 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"\n直接回复即可。输入 /help 查看所有命令。")

    await tg._app.bot.send_message(
        chat_id=int(SUPPORT_GROUP_ID),
        message_thread_id=topic_id,
        text="\n".join(lines),
        parse_mode="Markdown",
    )

    logger.info("created topic %d for session %s (type=%s)", topic_id, session_id, user_type)
    return topic_id


# =============================================================================
# Agent Assignment
# =============================================================================

def auto_assign_agent(session_id: str) -> str | None:
    if not AGENTS:
        return None
    load = store.get_agent_load()
    agent = min(AGENTS, key=lambda a: load.get(a, 0))
    store.set_assigned_agent(session_id, agent)
    return agent


# =============================================================================
# AI Auto-Reply
# =============================================================================

async def try_ai_reply(text: str) -> str | None:
    """Try AI auto-reply. Uses FAQ keyword match first, then LLM if available."""
    if not AI_ENABLED:
        return None

    # FAQ keyword match (fast path)
    text_lower = text.strip().lower()
    for keyword, answer in FAQ.items():
        if keyword.lower() in text_lower:
            return f"🤖 {answer}\n\n_如需人工客服，请回复「转人工」/ type \"agent\" for human support_"

    # LLM-based reply if ai_reply backend is configured
    ai_backend = router.get_backend("ai_reply")
    if ai_backend:
        try:
            faq_context = "\n".join(f"Q: {k} -> A: {v}" for k, v in FAQ.items())
            reply = await router.chat(
                "ai_reply",
                [
                    {"role": "system", "content": (
                        "You are a customer service AI assistant. Answer the user's question based on the FAQ below. "
                        "If the question is not covered by the FAQ, reply with exactly 'NO_MATCH'. "
                        "Keep answers concise and helpful. Reply in the same language as the user.\n\n"
                        f"FAQ:\n{faq_context}"
                    )},
                    {"role": "user", "content": text},
                ],
                temperature=0.3,
                max_tokens=300,
                timeout=8,
            )
            if reply and reply.strip() != "NO_MATCH":
                return f"🤖 {reply}\n\n_如需人工客服，请回复「转人工」/ type \"agent\" for human support_"
        except Exception as e:
            logger.warning("AI reply failed: %s", e)

    return None


# =============================================================================
# Reply Timeout Monitor
# =============================================================================

async def _timeout_alert(manager: ChannelManager, session_id: str, topic_id: int) -> None:
    """Wait for timeout, then alert agents."""
    await asyncio.sleep(REPLY_TIMEOUT_SECONDS)

    # Check if still pending
    if session_id not in pending_replies:
        return

    tg = manager._channels["telegram"]
    assert isinstance(tg, TelegramAdapter) and tg._app

    minutes = REPLY_TIMEOUT_SECONDS // 60
    await tg._app.bot.send_message(
        chat_id=int(SUPPORT_GROUP_ID),
        message_thread_id=topic_id,
        text=f"⏰ 用户已等待 {minutes} 分钟未收到回复！请尽快处理。",
    )
    pending_replies.pop(session_id, None)


def start_reply_timer(manager: ChannelManager, session_id: str, topic_id: int) -> None:
    # Cancel existing timer
    old = pending_replies.pop(session_id, None)
    if old:
        old.cancel()
    pending_replies[session_id] = asyncio.create_task(
        _timeout_alert(manager, session_id, topic_id)
    )


def cancel_reply_timer(session_id: str) -> None:
    task = pending_replies.pop(session_id, None)
    if task:
        task.cancel()


# =============================================================================
# Forward: User → Telegram (with language detection + sensitive filter)
# =============================================================================

async def forward_to_telegram(manager: ChannelManager, msg: UnifiedMessage) -> None:
    session_id = msg.chat_id
    if not session_id:
        return

    user_info = msg.metadata.get("user_info", {})
    topic_id = await get_or_create_topic(manager, session_id, user_info, msg.channel)
    text = msg.content.text or ""

    # Detect and store user language (on first text message)
    if msg.content.type == ContentType.TEXT and text:
        lang = await detect_language(text)
        current_lang = store.get_user_lang(session_id)
        if current_lang == "zh" and lang != "zh":
            store.set_user_lang(session_id, lang)
            logger.info("session %s language detected: %s", session_id, lang)

    # Sensitive word check
    matched = check_sensitive(text)
    if matched:
        store.log_sensitive(session_id, text, matched)
        # Notify agent, but still forward
        tg = manager._channels["telegram"]
        assert isinstance(tg, TelegramAdapter) and tg._app
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID),
            message_thread_id=topic_id,
            text=f"⚠️ 敏感词检测: {', '.join(matched)}",
        )

    # Persist message
    store.add_message(
        session_id, "user", text,
        media_url=msg.content.media_url, media_type=msg.content.media_type,
    )

    # AI auto-reply
    if msg.content.type == ContentType.TEXT and text:
        if text.strip() in ("转人工", "agent", "human"):
            cancel_reply_timer(session_id)
            tg = manager._channels["telegram"]
            assert isinstance(tg, TelegramAdapter) and tg._app
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID),
                message_thread_id=topic_id,
                text=f"👤 用户请求转人工\n\n> {text}",
            )
            start_reply_timer(manager, session_id, topic_id)
            return

        ai_reply = await try_ai_reply(text)
        if ai_reply:
            store.add_message(session_id, "agent", ai_reply)
            user_ch = _find_user_channel(manager, session_id)
            if user_ch:
                await user_ch.send(OutboundMessage(chat_id=session_id, text=ai_reply))
            tg = manager._channels["telegram"]
            assert isinstance(tg, TelegramAdapter) and tg._app
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID),
                message_thread_id=topic_id,
                text=f"👤 {text}\n\n🤖 _{ai_reply}_",
                parse_mode="Markdown",
            )
            return

    # Forward to Telegram
    tg = manager._channels["telegram"]
    assert isinstance(tg, TelegramAdapter) and tg._app

    # Translate user message for agent if not Chinese
    user_lang = store.get_user_lang(session_id)
    display_text = text

    if user_lang != "zh" and text and router.get_backend("translate"):
        translated = await translate_text(text, "zh", user_lang)
        if translated != text:
            display_text = f"{text}\n\n🌐 _{translated}_"

    if msg.content.type == ContentType.MEDIA and msg.content.media_url:
        media_type = msg.content.media_type or "image"
        data_url = msg.content.media_url
        if "," in data_url:
            header, b64data = data_url.split(",", 1)
            raw = base64.b64decode(b64data)
            buf = io.BytesIO(raw)
            if media_type == "video":
                buf.name = "video.mp4"
                await tg._app.bot.send_video(
                    chat_id=int(SUPPORT_GROUP_ID),
                    message_thread_id=topic_id,
                    video=buf,
                    caption=display_text or None,
                )
            else:
                buf.name = "image.jpg"
                await tg._app.bot.send_photo(
                    chat_id=int(SUPPORT_GROUP_ID),
                    message_thread_id=topic_id,
                    photo=buf,
                    caption=display_text or None,
                )
        else:
            if media_type == "video":
                await tg._app.bot.send_video(
                    chat_id=int(SUPPORT_GROUP_ID),
                    message_thread_id=topic_id,
                    video=data_url,
                    caption=display_text or None,
                )
            else:
                await tg._app.bot.send_photo(
                    chat_id=int(SUPPORT_GROUP_ID),
                    message_thread_id=topic_id,
                    photo=data_url,
                    caption=display_text or None,
                )
    else:
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID),
            message_thread_id=topic_id,
            text=display_text or "(empty)",
            parse_mode="Markdown",
        )

    # Start reply timeout timer
    start_reply_timer(manager, session_id, topic_id)


# =============================================================================
# Forward: Telegram → User (with auto-translation)
# =============================================================================

async def forward_to_user(manager: ChannelManager, msg: UnifiedMessage) -> None:
    if not msg.thread_id:
        return

    topic_id = int(msg.thread_id)
    session_id = topic_to_session.get(topic_id)

    if not session_id:
        db_session = store.get_session_by_topic(topic_id)
        if db_session:
            session_id = db_session["session_id"]
            session_to_topic[session_id] = topic_id
            topic_to_session[topic_id] = session_id

    if not session_id:
        return

    # Handle commands
    if msg.content.type == ContentType.COMMAND:
        await handle_agent_command(manager, msg, session_id, topic_id)
        return

    # Cancel reply timer (agent responded)
    cancel_reply_timer(session_id)
    store.set_first_reply(session_id)

    agent_text = msg.content.text or ""

    # Auto-translate agent reply to user's language
    user_lang = store.get_user_lang(session_id)
    translated_text = agent_text

    if user_lang != "zh" and agent_text and router.get_backend("translate"):
        translated_text = await translate_text(agent_text, user_lang, "zh")
        if translated_text != agent_text:
            # Show original + translation to agent
            tg = manager._channels["telegram"]
            assert isinstance(tg, TelegramAdapter) and tg._app
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID),
                message_thread_id=topic_id,
                text=f"🌐 已翻译为 [{user_lang}]: _{translated_text}_",
                parse_mode="Markdown",
            )

    # Persist
    store.add_message(session_id, "agent", agent_text)

    user_ch = _find_user_channel(manager, session_id)
    if not user_ch:
        tg = manager._channels["telegram"]
        assert isinstance(tg, TelegramAdapter) and tg._app
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID),
            message_thread_id=topic_id,
            text="⚠️ 用户当前离线，消息已保存。",
        )
        return

    out = OutboundMessage(chat_id=session_id, text=translated_text)

    if msg.content.type == ContentType.MEDIA and msg.raw:
        tg = manager._channels["telegram"]
        assert isinstance(tg, TelegramAdapter) and tg._app
        update = msg.raw
        if update.message and update.message.photo:
            photo = update.message.photo[-1]
            file = await tg._app.bot.get_file(photo.file_id)
            out.media_url = file.file_path
            out.media_type = "image"
        elif update.message and update.message.video:
            video = update.message.video
            file = await tg._app.bot.get_file(video.file_id)
            out.media_url = file.file_path
            out.media_type = "video"
        elif update.message and update.message.document:
            doc = update.message.document
            file = await tg._app.bot.get_file(doc.file_id)
            out.media_url = file.file_path
            out.media_type = "document"

    await user_ch.send(out)
    logger.info("forwarded reply to %s (lang=%s)", session_id, user_lang)


# =============================================================================
# Agent Commands
# =============================================================================

async def handle_agent_command(
    manager: ChannelManager, msg: UnifiedMessage, session_id: str, topic_id: int
) -> None:
    tg = manager._channels["telegram"]
    assert isinstance(tg, TelegramAdapter) and tg._app
    cmd = msg.content.command
    args = msg.content.args

    if cmd == "erp":
        user_id = args[0] if args else None
        if not user_id:
            db_session = store.get_session(session_id)
            user_id = db_session.get("user_id") if db_session else None

        if user_id:
            erp_info = (
                f"📋 ERP 用户信息\n"
                f"• 客户ID: `{user_id}`\n"
                f"• 注册时间: 2024-01-15\n"
                f"• 订单数: 12\n"
                f"• 累计消费: ¥3,580\n"
                f"• 会员等级: 金牌\n"
                f"• 最近订单: #20240301001 (已签收)\n\n"
                f"_模拟数据，接入 ERP API 后显示真实信息_"
            )
        else:
            erp_info = "⚠️ 该用户未登录，无法查询。"

        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text=erp_info, parse_mode="Markdown",
        )

    elif cmd == "order":
        query = args[0] if args else None
        if not query:
            db_session = store.get_session(session_id)
            query = db_session.get("user_phone") or db_session.get("user_id") if db_session else None

        if query:
            order_info = (
                f"📦 订单查询: `{query}`\n\n"
                f"1. #20240301001 — ¥299 已签收 (3/5)\n"
                f"2. #20240225003 — ¥158 已签收 (2/28)\n"
                f"3. #20240220007 — ¥89 退款完成\n\n"
                f"_模拟数据_"
            )
        else:
            order_info = "⚠️ 请提供手机号或客户ID: `/order 13800138000`"

        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text=order_info, parse_mode="Markdown",
        )

    elif cmd == "tpl":
        if not args:
            # List all templates
            lines = ["📝 快捷回复模板:\n"]
            for name in TEMPLATES:
                lines.append(f"• `/tpl {name}`")
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                text="\n".join(lines), parse_mode="Markdown",
            )
        else:
            tpl_name = args[0]
            tpl_text = TEMPLATES.get(tpl_name)
            if tpl_text:
                # Auto-translate template if needed
                user_lang = store.get_user_lang(session_id)
                send_text = tpl_text
                if user_lang != "zh" and router.get_backend("translate"):
                    send_text = await translate_text(tpl_text, user_lang, "zh")

                store.add_message(session_id, "agent", tpl_text)
                cancel_reply_timer(session_id)
                store.set_first_reply(session_id)

                user_ch = _find_user_channel(manager, session_id)
                if user_ch:
                    await user_ch.send(OutboundMessage(chat_id=session_id, text=send_text))
                    await tg._app.bot.send_message(
                        chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                        text=f"✅ 已发送模板「{tpl_name}」" + (f"\n🌐 {send_text}" if send_text != tpl_text else ""),
                    )
                else:
                    await tg._app.bot.send_message(
                        chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                        text="⚠️ 用户离线，模板消息已保存。",
                    )
            else:
                await tg._app.bot.send_message(
                    chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                    text=f"⚠️ 模板「{tpl_name}」不存在。输入 `/tpl` 查看所有模板。",
                    parse_mode="Markdown",
                )

    elif cmd == "ticket":
        title = " ".join(args) if args else "客户问题"
        ticket_id = store.create_ticket(session_id, title, msg.sender.display_name or "")
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text=f"🎫 工单已创建\n• ID: #{ticket_id}\n• 标题: {title}\n• 状态: open",
        )

    elif cmd == "close":
        store.close_session(session_id)
        cancel_reply_timer(session_id)

        user_ch = _find_user_channel(manager, session_id)
        if user_ch:
            # Translate rating prompt if needed
            user_lang = store.get_user_lang(session_id)
            rating_text = "感谢您的咨询！请为本次服务评分："
            if user_lang != "zh" and router.get_backend("translate"):
                rating_text = await translate_text(rating_text, user_lang, "zh")

            await user_ch.send(OutboundMessage(
                chat_id=session_id, text=rating_text,
                buttons=[
                    [
                        Button(label="⭐", callback_data=f"rate:{session_id}:1"),
                        Button(label="⭐⭐", callback_data=f"rate:{session_id}:2"),
                        Button(label="⭐⭐⭐", callback_data=f"rate:{session_id}:3"),
                        Button(label="⭐⭐⭐⭐", callback_data=f"rate:{session_id}:4"),
                        Button(label="⭐⭐⭐⭐⭐", callback_data=f"rate:{session_id}:5"),
                    ],
                ],
            ))

        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text="✅ 会话已关闭，已发送评价请求。",
        )
        try:
            await tg._app.bot.close_forum_topic(
                chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            )
        except Exception:
            pass

    elif cmd == "history":
        limit = int(args[0]) if args else 20
        messages = store.get_messages(session_id, limit=limit)
        if messages:
            lines = [f"📜 最近 {len(messages)} 条消息:"]
            for m in messages:
                role = "👤" if m["sender"] == "user" else "💬"
                text = m["content"][:80]
                lines.append(f"{role} {m['timestamp']}: {text}")
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                text="\n".join(lines),
            )
        else:
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                text="暂无历史消息。",
            )

    elif cmd == "report":
        date = args[0] if args else None
        report = store.daily_report(date)
        avg_reply = f"{report['avg_first_reply_seconds']}s" if report['avg_first_reply_seconds'] else "N/A"
        lines = [
            f"📊 日报 {report['date']}\n",
            f"• 总会话: {report['total_sessions']}",
            f"• 已关闭: {report['closed_sessions']}",
            f"• 总消息: {report['total_messages']}",
            f"• 平均评分: {report['avg_rating'] or 'N/A'}",
            f"• 平均首次响应: {avg_reply}",
        ]
        if report['agents']:
            lines.append("\n👥 客服工作量:")
            for a in report['agents']:
                lines.append(f"  • {a['assigned_agent']}: {a['sessions']}会话 / {a['replies']}回复")

        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text="\n".join(lines),
        )

    elif cmd == "hotwords":
        days = int(args[0]) if args else 7
        keywords = store.hot_keywords(days=days)
        if keywords:
            lines = [f"🔥 近 {days} 天热词 Top {len(keywords)}:\n"]
            for i, (word, count) in enumerate(keywords, 1):
                lines.append(f"{i}. {word} ({count}次)")
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                text="\n".join(lines),
            )
        else:
            await tg._app.bot.send_message(
                chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                text="暂无数据。",
            )

    elif cmd == "lang":
        user_lang = store.get_user_lang(session_id)
        translate_backend = router.get_backend("translate")
        if translate_backend:
            translate_status = f"已启用 ({translate_backend.name}/{translate_backend.model})"
        else:
            translate_status = "未配置 (设置 MINIMAX_API_KEY 或 OPENAI_API_KEY)"
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text=f"🌐 用户语言: {user_lang}\n翻译: {translate_status}",
        )

    elif cmd == "help":
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text=(
                "📖 客服命令:\n\n"
                "**查询**\n"
                "• `/erp [ID]` — ERP 用户信息\n"
                "• `/order [手机/ID]` — 订单查询\n"
                "• `/history [N]` — 聊天记录\n"
                "• `/lang` — 用户语言\n\n"
                "**操作**\n"
                "• `/tpl [名称]` — 快捷回复模板\n"
                "• `/ticket 标题` — 创建工单\n"
                "• `/close` — 关闭会话+评价\n\n"
                "**报表**\n"
                "• `/report [日期]` — 日报统计\n"
                "• `/hotwords [天数]` — 热词分析\n\n"
                "💡 翻译自动进行，无需手动操作"
            ),
            parse_mode="Markdown",
        )


# =============================================================================
# Callback (ratings)
# =============================================================================

async def handle_callback(manager: ChannelManager, msg: UnifiedMessage) -> None:
    data = msg.content.callback_data or ""
    if data.startswith("rate:"):
        parts = data.split(":")
        if len(parts) == 3:
            session_id = parts[1]
            score = int(parts[2])
            store.add_rating(session_id, score)

            user_ch = _find_user_channel(manager, session_id)
            if user_ch:
                user_lang = store.get_user_lang(session_id)
                thanks = "感谢您的评价！祝您生活愉快！"
                if user_lang != "zh" and router.get_backend("translate"):
                    thanks = await translate_text(thanks, user_lang, "zh")
                await user_ch.send(OutboundMessage(
                    chat_id=session_id, text=f"{'⭐' * score} {thanks}",
                ))

            if session_id in session_to_topic:
                topic_id = session_to_topic[session_id]
                tg = manager._channels["telegram"]
                assert isinstance(tg, TelegramAdapter) and tg._app
                await tg._app.bot.send_message(
                    chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
                    text=f"⭐ 用户评价: {score}/5 {'⭐' * score}",
                )


# =============================================================================
# Online/Offline + History
# =============================================================================

async def notify_user_online(manager: ChannelManager, session_id: str) -> None:
    if session_id not in session_to_topic:
        return
    topic_id = session_to_topic[session_id]
    tg = manager._channels["telegram"]
    assert isinstance(tg, TelegramAdapter) and tg._app
    await tg._app.bot.send_message(
        chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
        text="🟢 用户已上线",
    )


async def notify_user_offline(manager: ChannelManager, session_id: str) -> None:
    if session_id not in session_to_topic:
        return
    topic_id = session_to_topic[session_id]
    tg = manager._channels["telegram"]
    assert isinstance(tg, TelegramAdapter) and tg._app
    try:
        await tg._app.bot.send_message(
            chat_id=int(SUPPORT_GROUP_ID), message_thread_id=topic_id,
            text="🔴 用户已离线",
        )
    except Exception:
        pass


async def send_history(manager: ChannelManager, session_id: str) -> None:
    messages = store.get_messages(session_id, limit=20)
    if not messages:
        return
    user_ch = _find_user_channel(manager, session_id)
    if not user_ch:
        return
    if hasattr(user_ch, '_sessions'):
        ws = user_ch._sessions.get(session_id)
        if ws and not ws.closed:
            await ws.send_json({
                "type": "history",
                "messages": [
                    {
                        "sender": m["sender"],
                        "text": m["content"],
                        "media_url": m.get("media_url"),
                        "media_type": m.get("media_type"),
                        "timestamp": m["timestamp"],
                    }
                    for m in messages
                ],
            })


# =============================================================================
# Helpers
# =============================================================================

def _find_user_channel(manager: ChannelManager, session_id: str):
    for ch_name in ("webchat", "wkim"):
        ch = manager._channels.get(ch_name)
        if not ch:
            continue
        sessions = getattr(ch, '_connections', None) or getattr(ch, '_sessions', None)
        if sessions and session_id in sessions:
            return ch
    return None


# =============================================================================
# Serve frontend
# =============================================================================

CHAT_HTML = Path(__file__).parent / "customer_service_chat.html"


async def serve_chat_page(request: web.Request) -> web.Response:
    html = CHAT_HTML.read_text()
    return web.Response(text=html, content_type="text/html")


# =============================================================================
# Main
# =============================================================================

async def main() -> None:
    global session_to_topic, topic_to_session
    s2t, t2s = store.load_all_mappings()
    session_to_topic.update(s2t)
    topic_to_session.update(t2s)
    logger.info("loaded %d session-topic mappings from DB", len(s2t))

    manager = ChannelManager()

    webchat = WebChatAdapter(port=WEBCHAT_PORT)
    wkim = WKIMCompatAdapter(port=WKIM_PORT)
    telegram = TelegramAdapter(token=TELEGRAM_TOKEN)

    manager.add_channel(webchat)
    manager.add_channel(wkim)
    manager.add_channel(telegram)

    # --- Group access control: auto-kick unauthorized members ---
    if ALLOWED_AGENTS:
        from telegram.ext import ChatMemberHandler

        async def _on_chat_member(update, context):
            """Kick users who join the support group but aren't on the allowed list."""
            if not update.chat_member or str(update.chat_member.chat.id) != SUPPORT_GROUP_ID:
                return
            new = update.chat_member.new_chat_member
            if not new or new.status in ("left", "kicked"):
                return
            user_id = str(new.user.id)
            bot_id = str((await telegram._app.bot.get_me()).id)
            if user_id == bot_id:
                return
            if user_id not in ALLOWED_AGENTS:
                try:
                    await telegram._app.bot.ban_chat_member(
                        chat_id=int(SUPPORT_GROUP_ID), user_id=int(user_id),
                    )
                    await telegram._app.bot.unban_chat_member(
                        chat_id=int(SUPPORT_GROUP_ID), user_id=int(user_id),
                    )
                    logger.warning("kicked unauthorized user %s (%s) from support group",
                                   user_id, new.user.full_name)
                except Exception as e:
                    logger.error("failed to kick user %s: %s", user_id, e)

        telegram._app.add_handler(ChatMemberHandler(_on_chat_member, ChatMemberHandler.CHAT_MEMBER))
        logger.info("group access control enabled: %d allowed agents", len(ALLOWED_AGENTS))

    @manager.on_message
    async def route(msg: UnifiedMessage) -> None:
        if msg.content.type == ContentType.CALLBACK:
            await handle_callback(manager, msg)
            return

        if msg.channel in ("webchat", "wkim"):
            # Serialize per-customer: use chat_id (session_id) as key
            key = msg.chat_id or "unknown"
            await _msg_queue.run(key, forward_to_telegram(manager, msg))
        elif msg.channel == "telegram":
            if msg.chat_id == SUPPORT_GROUP_ID:
                # Check agent authorization
                if ALLOWED_AGENTS and msg.sender.id not in ALLOWED_AGENTS:
                    logger.warning("ignored message from unauthorized user %s in support group", msg.sender.id)
                    return
                # Serialize per-session: use thread_id → session_id as key
                key = topic_to_session.get(int(msg.thread_id)) if msg.thread_id else None
                if key:
                    await _msg_queue.run(key, forward_to_user(manager, msg))
                else:
                    await forward_to_user(manager, msg)

    # Online/offline + history hooks
    first_message_sent: set[str] = set()
    orig_queue_put = webchat._queue.put

    async def enhanced_put(item: UnifiedMessage):
        await orig_queue_put(item)
        sid = item.chat_id
        if sid and sid not in first_message_sent:
            first_message_sent.add(sid)
            asyncio.create_task(notify_user_online(manager, sid))
            asyncio.create_task(send_history(manager, sid))

    webchat._queue.put = enhanced_put  # type: ignore

    webchat.add_route("GET", "/chat", serve_chat_page)
    await webchat.connect()

    await wkim.connect()
    await telegram.connect()

    # --- Health monitor: auto-reconnect stale channels ---
    health_interval = int(os.environ.get("CS_HEALTH_INTERVAL", "30"))
    health_monitor = HealthMonitor(interval=health_interval)
    await health_monitor.start(manager)

    logger.info("=" * 60)
    logger.info("Customer Service POC started! (full-featured)")
    logger.info("  Web chat:    http://localhost:%d/chat", WEBCHAT_PORT)
    logger.info("  WuKongIM:    http://localhost:%d", WKIM_PORT)
    logger.info("  Telegram:    group %s", SUPPORT_GROUP_ID)
    logger.info("  DB:          %s", DB_PATH)
    logger.info("  AI FAQ:      %s", "on" if AI_ENABLED else "off")
    logger.info("  Timeout:     %ds", REPLY_TIMEOUT_SECONDS)
    logger.info("  Health:      every %ds", health_interval)
    logger.info("  Agents:      %s", AGENTS or "(auto-assign off)")
    logger.info("  Access:      %s", f"{len(ALLOWED_AGENTS)} allowed agents" if ALLOWED_AGENTS else "open (anyone in group can reply)")
    logger.info("  Restored:    %d sessions", len(s2t))
    logger.info("  Model Router:")
    for line in router.summary():
        logger.info("    %s", line)
    logger.info("=" * 60)

    try:
        await asyncio.gather(
            manager._consume(webchat),
            manager._consume(wkim),
            manager._consume(telegram),
        )
    finally:
        await health_monitor.stop()


if __name__ == "__main__":
    asyncio.run(main())
