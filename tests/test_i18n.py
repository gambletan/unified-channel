"""Tests for I18n middleware."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from unified_channel.i18n import I18nMiddleware
from unified_channel.types import ContentType, Identity, MessageContent, UnifiedMessage


TRANSLATIONS = {
    "en": {"greeting": "Hello", "rate_limited": "Too fast!", "help": "Need help?"},
    "zh": {"greeting": "你好", "rate_limited": "太快了！", "help": "需要帮助？"},
    "ja": {"greeting": "こんにちは", "rate_limited": "速すぎます！"},
}


def _msg(
    sender_id: str = "user1",
    metadata: dict | None = None,
    sender: Identity | None = None,
) -> UnifiedMessage:
    return UnifiedMessage(
        id="1",
        channel="test",
        sender=sender or Identity(id=sender_id),
        content=MessageContent(type=ContentType.TEXT, text="hello"),
        chat_id="chat1",
        metadata=metadata if metadata is not None else {},
    )


@pytest.mark.asyncio
async def test_default_locale_when_no_detection():
    mw = I18nMiddleware(TRANSLATIONS, default_locale="en")

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg()
    await mw.process(msg, handler)

    assert msg.metadata["locale"] == "en"
    t = msg.metadata["t"]
    assert t("greeting") == "Hello"


@pytest.mark.asyncio
async def test_detects_locale_from_metadata():
    mw = I18nMiddleware(TRANSLATIONS)

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg(metadata={"locale": "zh"})
    await mw.process(msg, handler)

    assert msg.metadata["locale"] == "zh"
    t = msg.metadata["t"]
    assert t("greeting") == "你好"
    assert t("rate_limited") == "太快了！"


@pytest.mark.asyncio
async def test_detects_locale_from_sender():
    """Sender identity with a locale attribute is respected."""
    mw = I18nMiddleware(TRANSLATIONS)

    @dataclass
    class LocaleIdentity(Identity):
        locale: str | None = None

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    sender = LocaleIdentity(id="user1", locale="ja")
    msg = _msg(sender=sender)
    await mw.process(msg, handler)

    assert msg.metadata["locale"] == "ja"
    t = msg.metadata["t"]
    assert t("greeting") == "こんにちは"


@pytest.mark.asyncio
async def test_falls_back_to_default_for_missing_keys():
    mw = I18nMiddleware(TRANSLATIONS)

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg(metadata={"locale": "ja"})
    await mw.process(msg, handler)

    t = msg.metadata["t"]
    # "help" not in ja, should fall back to en
    assert t("help") == "Need help?"


@pytest.mark.asyncio
async def test_returns_key_when_no_translation():
    mw = I18nMiddleware(TRANSLATIONS)

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg()
    await mw.process(msg, handler)

    t = msg.metadata["t"]
    assert t("nonexistent_key") == "nonexistent_key"


@pytest.mark.asyncio
async def test_returns_explicit_fallback():
    mw = I18nMiddleware(TRANSLATIONS)

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg()
    await mw.process(msg, handler)

    t = msg.metadata["t"]
    assert t("missing", "default text") == "default text"


@pytest.mark.asyncio
async def test_custom_detect_fn():
    mw = I18nMiddleware(TRANSLATIONS, detect_fn=lambda _msg: "zh")

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg()
    await mw.process(msg, handler)

    assert msg.metadata["locale"] == "zh"
    t = msg.metadata["t"]
    assert t("greeting") == "你好"


@pytest.mark.asyncio
async def test_falls_back_when_detect_fn_returns_unknown_locale():
    mw = I18nMiddleware(TRANSLATIONS, default_locale="en", detect_fn=lambda _msg: "fr")

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    msg = _msg()
    await mw.process(msg, handler)

    assert msg.metadata["locale"] == "en"
    t = msg.metadata["t"]
    assert t("greeting") == "Hello"


@pytest.mark.asyncio
async def test_calls_next_handler():
    mw = I18nMiddleware(TRANSLATIONS)
    called = False

    async def handler(msg: UnifiedMessage) -> str:
        nonlocal called
        called = True
        return "result"

    msg = _msg()
    result = await mw.process(msg, handler)

    assert called
    assert result == "result"
