"""Tests for the Scheduler module."""

from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_channel.scheduler import (
    CronSchedule,
    Scheduler,
    cron_matches,
    parse_cron,
    _task_counter,
)


@pytest.fixture
def mock_manager():
    """Create a mock ChannelManager with an async send method."""
    manager = MagicMock()
    manager.send = AsyncMock(return_value=None)
    return manager


@pytest.fixture
def scheduler(mock_manager):
    return Scheduler(mock_manager)


# -- parse_cron tests --


def test_parse_cron_standard():
    parsed = parse_cron("0 9 * * *")
    assert parsed.minute == [0]
    assert parsed.hour == [9]
    assert len(parsed.dom) == 31
    assert len(parsed.month) == 12
    assert len(parsed.dow) == 7


def test_parse_cron_comma_separated():
    parsed = parse_cron("0,30 9,17 * * 1,5")
    assert parsed.minute == [0, 30]
    assert parsed.hour == [9, 17]
    assert parsed.dow == [1, 5]


def test_parse_cron_invalid_fields():
    with pytest.raises(ValueError, match="expected 5 fields"):
        parse_cron("0 9 *")


def test_parse_cron_out_of_range():
    with pytest.raises(ValueError, match="expected 0-59"):
        parse_cron("60 9 * * *")


# -- cron_matches tests --


def test_cron_matches_true():
    parsed = parse_cron("30 14 * * *")
    # Wednesday 2026-03-04 14:30 — dow cron=3 (Wednesday), Python weekday=2
    dt = datetime(2026, 3, 4, 14, 30, 0)
    assert cron_matches(parsed, dt)


def test_cron_matches_false():
    parsed = parse_cron("30 14 * * *")
    dt = datetime(2026, 3, 4, 14, 31, 0)
    assert not cron_matches(parsed, dt)


# -- Scheduler.every tests --


@pytest.mark.asyncio
async def test_every_sends_messages(mock_manager, scheduler):
    scheduler.every(0.05, "telegram", "chat1", "hello")

    # Let it run for ~3 intervals
    await asyncio.sleep(0.18)
    scheduler.stop()

    assert mock_manager.send.call_count >= 3
    mock_manager.send.assert_any_call("telegram", "chat1", "hello")


# -- Scheduler.once tests --


@pytest.mark.asyncio
async def test_once_sends_single_message(mock_manager, scheduler):
    scheduler.once(0.05, "discord", "chat2", "one-shot")

    await asyncio.sleep(0.1)
    scheduler.stop()

    assert mock_manager.send.call_count == 1
    mock_manager.send.assert_called_with("discord", "chat2", "one-shot")


# -- Scheduler.cancel tests --


@pytest.mark.asyncio
async def test_cancel_stops_task(mock_manager, scheduler):
    task_id = scheduler.every(0.05, "slack", "chat3", "ping")

    await asyncio.sleep(0.12)
    count_before = mock_manager.send.call_count
    scheduler.cancel(task_id)

    await asyncio.sleep(0.1)
    assert mock_manager.send.call_count == count_before


def test_cancel_returns_false_for_unknown(scheduler):
    assert scheduler.cancel("nonexistent") is False


# -- Scheduler.list tests --


@pytest.mark.asyncio
async def test_list_returns_active_only(mock_manager, scheduler):
    id1 = scheduler.every(1.0, "telegram", "c1", "a")
    id2 = scheduler.once(5.0, "discord", "c2", "b")
    scheduler.cancel(id1)

    active = scheduler.list()
    assert len(active) == 1
    assert active[0]["id"] == id2
    assert active[0]["type"] == "once"
    assert active[0]["active"] is True

    scheduler.stop()


# -- Scheduler.stop tests --


@pytest.mark.asyncio
async def test_stop_cancels_all(mock_manager, scheduler):
    scheduler.every(0.05, "telegram", "c1", "a")
    scheduler.every(0.05, "discord", "c2", "b")

    scheduler.stop()
    await asyncio.sleep(0.1)

    assert mock_manager.send.call_count == 0
    assert scheduler.list() == []


# -- async callback tests --


@pytest.mark.asyncio
async def test_async_function_callback(mock_manager, scheduler):
    async def dynamic():
        return "dynamic text"

    scheduler.every(0.05, "telegram", "chat1", dynamic)

    await asyncio.sleep(0.08)
    scheduler.stop()

    assert mock_manager.send.call_count >= 1
    mock_manager.send.assert_any_call("telegram", "chat1", "dynamic text")


@pytest.mark.asyncio
async def test_sync_function_callback(mock_manager, scheduler):
    counter = {"n": 0}

    def gen():
        counter["n"] += 1
        return f"count: {counter['n']}"

    scheduler.every(0.05, "telegram", "chat1", gen)

    await asyncio.sleep(0.08)
    scheduler.stop()

    assert mock_manager.send.call_count >= 1
    # First call should have count: 1
    mock_manager.send.assert_any_call("telegram", "chat1", "count: 1")
