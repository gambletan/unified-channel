"""Tests for middleware pipeline."""

from __future__ import annotations

import pytest

from unified_channel.middleware import AccessMiddleware, CommandMiddleware
from unified_channel.types import (
    ContentType,
    Identity,
    MessageContent,
    UnifiedMessage,
)


def _msg(
    text: str = "hello",
    sender_id: str = "user1",
    command: str | None = None,
    args: list[str] | None = None,
) -> UnifiedMessage:
    content_type = ContentType.COMMAND if command else ContentType.TEXT
    return UnifiedMessage(
        id="1",
        channel="test",
        sender=Identity(id=sender_id),
        content=MessageContent(
            type=content_type,
            text=text,
            command=command,
            args=args or [],
        ),
        chat_id="chat1",
    )


@pytest.mark.asyncio
async def test_access_middleware_allows():
    mw = AccessMiddleware(allowed_user_ids={"user1"})

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    result = await mw.process(_msg(sender_id="user1"), handler)
    assert result == "ok"


@pytest.mark.asyncio
async def test_access_middleware_blocks():
    mw = AccessMiddleware(allowed_user_ids={"user1"})

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    result = await mw.process(_msg(sender_id="user999"), handler)
    assert result is None


@pytest.mark.asyncio
async def test_access_middleware_no_allowlist():
    mw = AccessMiddleware()

    async def handler(msg: UnifiedMessage) -> str:
        return "ok"

    result = await mw.process(_msg(sender_id="anyone"), handler)
    assert result == "ok"


@pytest.mark.asyncio
async def test_command_middleware_routes():
    cmds = CommandMiddleware()

    @cmds.command("status")
    async def status(msg: UnifiedMessage) -> str:
        return "running"

    async def fallback(msg: UnifiedMessage) -> str:
        return "fallback"

    result = await cmds.process(_msg(command="status"), fallback)
    assert result == "running"


@pytest.mark.asyncio
async def test_command_middleware_passthrough():
    cmds = CommandMiddleware()

    @cmds.command("status")
    async def status(msg: UnifiedMessage) -> str:
        return "running"

    async def fallback(msg: UnifiedMessage) -> str:
        return "fallback"

    result = await cmds.process(_msg(text="hello"), fallback)
    assert result == "fallback"


@pytest.mark.asyncio
async def test_command_with_args():
    cmds = CommandMiddleware()

    @cmds.command("run")
    async def run(msg: UnifiedMessage) -> str:
        return f"running {' '.join(msg.content.args)}"

    async def fallback(msg: UnifiedMessage) -> str:
        return "nope"

    result = await cmds.process(
        _msg(command="run", args=["job1", "job2"]), fallback
    )
    assert result == "running job1 job2"


def test_registered_commands():
    cmds = CommandMiddleware()
    cmds.register("a", lambda m: "a")  # type: ignore[arg-type, return-value]
    cmds.register("b", lambda m: "b")  # type: ignore[arg-type, return-value]
    assert sorted(cmds.registered_commands) == ["a", "b"]
