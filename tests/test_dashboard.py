"""Tests for the Dashboard web UI."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import datetime

import pytest
import pytest_asyncio
import aiohttp

from unified_channel.dashboard import Dashboard
from unified_channel.manager import ChannelManager
from unified_channel.adapter import ChannelAdapter
from unified_channel.types import (
    ChannelStatus,
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)


class MockAdapter(ChannelAdapter):
    """Mock adapter for testing."""

    def __init__(self, channel_id: str = "telegram") -> None:
        self.channel_id = channel_id
        self._connected = True
        self.sent: list[OutboundMessage] = []
        self._msg_count = 0

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def receive(self):
        while False:
            yield  # type: ignore

    async def send(self, msg: OutboundMessage) -> str | None:
        self.sent.append(msg)
        self._msg_count += 1
        return f"sent-{self._msg_count}"

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(connected=self._connected, channel=self.channel_id)


def make_msg(channel: str = "telegram", text: str = "hello") -> UnifiedMessage:
    return UnifiedMessage(
        id=f"msg-{id(text)}",
        channel=channel,
        sender=Identity(id="user1", username="testuser"),
        content=MessageContent(type=ContentType.TEXT, text=text),
        timestamp=datetime(2025, 1, 1, 12, 0, 0),
        chat_id="c1",
    )


@pytest_asyncio.fixture
async def setup():
    """Set up manager + dashboard, yield (dashboard, port, adapter, manager), then tear down."""
    manager = ChannelManager()
    adapter = MockAdapter("telegram")
    manager.add_channel(adapter)

    dashboard = Dashboard(manager, port=0)
    await dashboard.start()

    # Get the actual port
    assert dashboard._site is not None
    sockets = dashboard._site._server.sockets  # type: ignore[union-attr]
    port = sockets[0].getsockname()[1]

    yield dashboard, port, adapter, manager

    await dashboard.stop()


@pytest_asyncio.fixture
async def auth_setup():
    manager = ChannelManager()
    manager.add_channel(MockAdapter("test"))

    dashboard = Dashboard(manager, port=0, auth=("admin", "secret"))
    await dashboard.start()

    sockets = dashboard._site._server.sockets  # type: ignore[union-attr]
    port = sockets[0].getsockname()[1]

    yield dashboard, port

    await dashboard.stop()


@pytest.mark.asyncio
async def test_index_returns_html(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{port}/") as resp:
            assert resp.status == 200
            assert "text/html" in resp.content_type
            body = await resp.text()
            assert "Unified Channel Dashboard" in body


@pytest.mark.asyncio
async def test_api_status(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{port}/api/status") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert "telegram" in data
            assert data["telegram"]["connected"] is True


@pytest.mark.asyncio
async def test_api_messages_empty(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{port}/api/messages") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data == []


@pytest.mark.asyncio
async def test_api_messages_after_capture(setup):
    dashboard, port, adapter, manager = setup
    msg = make_msg("telegram", "hello world")
    await manager._run_pipeline(msg)

    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{port}/api/messages") as resp:
            assert resp.status == 200
            data = await resp.json()
            assert len(data) == 1
            assert data[0]["text"] == "hello world"
            assert data[0]["channel"] == "telegram"


@pytest.mark.asyncio
async def test_api_send(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://127.0.0.1:{port}/api/send",
            json={"channel": "telegram", "chatId": "c1", "text": "outgoing"},
        ) as resp:
            assert resp.status == 200
            data = await resp.json()
            assert data["ok"] is True
            assert data["messageId"] == "sent-1"
    assert len(adapter.sent) == 1
    assert adapter.sent[0].text == "outgoing"


@pytest.mark.asyncio
async def test_api_send_missing_fields(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://127.0.0.1:{port}/api/send",
            json={"channel": "telegram"},
        ) as resp:
            assert resp.status == 400
            data = await resp.json()
            assert "Missing required fields" in data["error"]


@pytest.mark.asyncio
async def test_api_send_invalid_json(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://127.0.0.1:{port}/api/send",
            data=b"not json",
            headers={"Content-Type": "application/json"},
        ) as resp:
            assert resp.status == 400


@pytest.mark.asyncio
async def test_api_send_unregistered_channel(setup):
    dashboard, port, adapter, manager = setup
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://127.0.0.1:{port}/api/send",
            json={"channel": "nonexistent", "chatId": "c1", "text": "hi"},
        ) as resp:
            assert resp.status == 400
            data = await resp.json()
            assert "not registered" in data["error"]


@pytest.mark.asyncio
async def test_auth_required(auth_setup):
    dashboard, port = auth_setup
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{port}/") as resp:
            assert resp.status == 401


@pytest.mark.asyncio
async def test_auth_wrong_creds(auth_setup):
    dashboard, port = auth_setup
    creds = base64.b64encode(b"wrong:creds").decode()
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"http://127.0.0.1:{port}/",
            headers={"Authorization": f"Basic {creds}"},
        ) as resp:
            assert resp.status == 401


@pytest.mark.asyncio
async def test_auth_correct_creds(auth_setup):
    dashboard, port = auth_setup
    creds = base64.b64encode(b"admin:secret").decode()
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"http://127.0.0.1:{port}/api/status",
            headers={"Authorization": f"Basic {creds}"},
        ) as resp:
            assert resp.status == 200
