"""Tests for ChannelManager pipeline."""

from __future__ import annotations

import asyncio

import pytest

from unified_channel.adapter import ChannelAdapter
from unified_channel.manager import ChannelManager
from unified_channel.middleware import AccessMiddleware, CommandMiddleware
from unified_channel.types import (
    ChannelStatus,
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)


class MockAdapter(ChannelAdapter):
    """In-memory adapter for testing."""

    channel_id = "mock"

    def __init__(self) -> None:
        self._connected = False
        self._inbound: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self.sent: list[OutboundMessage] = []

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def receive(self):
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._inbound.get(), timeout=0.1)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        self.sent.append(msg)
        return str(len(self.sent))

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel="mock")

    async def inject(self, text: str, *, command: str | None = None) -> None:
        content_type = ContentType.COMMAND if command else ContentType.TEXT
        msg = UnifiedMessage(
            id="test-1",
            channel="mock",
            sender=Identity(id="user1", username="tester"),
            content=MessageContent(
                type=content_type, text=text, command=command
            ),
            chat_id="chat1",
        )
        await self._inbound.put(msg)


@pytest.mark.asyncio
async def test_full_pipeline():
    adapter = MockAdapter()
    manager = ChannelManager()
    manager.add_channel(adapter)

    cmds = CommandMiddleware()
    manager.add_middleware(cmds)

    @cmds.command("ping")
    async def ping(msg: UnifiedMessage) -> str:
        return "pong"

    # Start manager in background
    task = asyncio.create_task(manager.run())

    # Wait for connection
    await asyncio.sleep(0.05)

    # Send a command
    await adapter.inject("/ping", command="ping")
    await asyncio.sleep(0.2)

    # Check reply was sent
    assert len(adapter.sent) == 1
    assert adapter.sent[0].text == "pong"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_access_control_blocks():
    adapter = MockAdapter()
    manager = ChannelManager()
    manager.add_channel(adapter)
    manager.add_middleware(AccessMiddleware(allowed_user_ids={"admin_only"}))

    @manager.on_message
    async def fallback(msg: UnifiedMessage) -> str:
        return "should not reach"

    task = asyncio.create_task(manager.run())
    await asyncio.sleep(0.05)

    await adapter.inject("hello")
    await asyncio.sleep(0.2)

    # Message from user1 should be blocked
    assert len(adapter.sent) == 0

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_fallback_handler():
    adapter = MockAdapter()
    manager = ChannelManager()
    manager.add_channel(adapter)

    @manager.on_message
    async def echo(msg: UnifiedMessage) -> str:
        return f"echo: {msg.content.text}"

    task = asyncio.create_task(manager.run())
    await asyncio.sleep(0.05)

    await adapter.inject("hello world")
    await asyncio.sleep(0.2)

    assert len(adapter.sent) == 1
    assert adapter.sent[0].text == "echo: hello world"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_get_status():
    adapter = MockAdapter()
    manager = ChannelManager()
    manager.add_channel(adapter)

    await adapter.connect()
    statuses = await manager.get_status()
    assert statuses["mock"].connected is True
    await adapter.disconnect()
