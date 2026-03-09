"""Tests for RateLimitMiddleware."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from unified_channel.ratelimit import RateLimitMiddleware
from unified_channel.types import ContentType, Identity, MessageContent, UnifiedMessage


def _msg(sender_id: str = "user1", chat_id: str = "chat1") -> UnifiedMessage:
    return UnifiedMessage(
        id="1",
        channel="test",
        sender=Identity(id=sender_id),
        content=MessageContent(type=ContentType.TEXT, text="hello"),
        chat_id=chat_id,
    )


async def _next(msg: UnifiedMessage) -> str:
    return "ok"


@pytest.mark.asyncio
async def test_allows_under_limit():
    mw = RateLimitMiddleware(max_messages=3, window_seconds=10)
    result = await mw.process(_msg(), _next)
    assert result == "ok"


@pytest.mark.asyncio
async def test_blocks_when_limit_reached():
    mw = RateLimitMiddleware(max_messages=2, window_seconds=10)
    await mw.process(_msg(), _next)
    await mw.process(_msg(), _next)
    result = await mw.process(_msg(), _next)
    assert result is None


@pytest.mark.asyncio
async def test_window_reset():
    """After the window expires, messages should be allowed again."""
    mw = RateLimitMiddleware(max_messages=1, window_seconds=0.5)
    await mw.process(_msg(), _next)
    assert await mw.process(_msg(), _next) is None

    # Simulate time passing by manipulating internal timestamps
    # Shift all timestamps back past the window
    for ts_list in mw._windows.values():
        for i in range(len(ts_list)):
            ts_list[i] -= 1.0

    result = await mw.process(_msg(), _next)
    assert result == "ok"


@pytest.mark.asyncio
async def test_multiple_users_independent():
    mw = RateLimitMiddleware(max_messages=1, window_seconds=10)
    r1 = await mw.process(_msg(sender_id="alice"), _next)
    r2 = await mw.process(_msg(sender_id="bob"), _next)
    assert r1 == "ok"
    assert r2 == "ok"

    # Both now at limit
    assert await mw.process(_msg(sender_id="alice"), _next) is None
    assert await mw.process(_msg(sender_id="bob"), _next) is None


@pytest.mark.asyncio
async def test_custom_key_fn():
    """Key by chat_id instead of sender."""
    mw = RateLimitMiddleware(
        max_messages=1,
        window_seconds=10,
        key_fn=lambda msg: msg.chat_id or "unknown",
    )
    await mw.process(_msg(sender_id="alice", chat_id="room1"), _next)
    # Same room, different user — blocked
    result = await mw.process(_msg(sender_id="bob", chat_id="room1"), _next)
    assert result is None

    # Different room — allowed
    r2 = await mw.process(_msg(sender_id="alice", chat_id="room2"), _next)
    assert r2 == "ok"


@pytest.mark.asyncio
async def test_custom_reply_text():
    mw = RateLimitMiddleware(max_messages=1, window_seconds=10, reply_text="Slow down!")
    await mw.process(_msg(), _next)
    result = await mw.process(_msg(), _next)
    assert result == "Slow down!"


@pytest.mark.asyncio
async def test_burst_at_exact_limit():
    mw = RateLimitMiddleware(max_messages=5, window_seconds=10)
    for _ in range(5):
        assert await mw.process(_msg(), _next) == "ok"
    # 6th blocked
    assert await mw.process(_msg(), _next) is None


@pytest.mark.asyncio
async def test_cleanup_removes_expired():
    mw = RateLimitMiddleware(max_messages=1, window_seconds=0.5)
    await mw.process(_msg(sender_id="alice"), _next)
    await mw.process(_msg(sender_id="bob"), _next)

    # Shift timestamps back
    for ts_list in mw._windows.values():
        for i in range(len(ts_list)):
            ts_list[i] -= 1.0

    mw.cleanup()

    # Both users should be able to send again
    assert await mw.process(_msg(sender_id="alice"), _next) == "ok"
    assert await mw.process(_msg(sender_id="bob"), _next) == "ok"


@pytest.mark.asyncio
async def test_sliding_window_partial_expiry():
    """First message expires while second is still valid."""
    mw = RateLimitMiddleware(max_messages=2, window_seconds=1.0)

    await mw.process(_msg(), _next)

    # Shift first timestamp back by 0.7s (will expire at t+0.3)
    mw._windows["user1"][0] -= 0.7

    await mw.process(_msg(), _next)
    # At limit
    assert await mw.process(_msg(), _next) is None

    # Expire the first message
    mw._windows["user1"][0] -= 0.4

    result = await mw.process(_msg(), _next)
    assert result == "ok"
