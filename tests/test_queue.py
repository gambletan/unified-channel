"""Tests for MessageQueue middleware."""

import asyncio

import pytest

from unified_channel.queue import InMemoryQueue, QueueMiddleware, QueueProcessor
from unified_channel.types import ContentType, Identity, MessageContent, UnifiedMessage


def make_msg(msg_id: str, text: str) -> UnifiedMessage:
    return UnifiedMessage(
        id=msg_id,
        channel="test",
        sender=Identity(id="user1"),
        content=MessageContent(type=ContentType.TEXT, text=text),
        chat_id="chat1",
    )


@pytest.mark.asyncio
async def test_enqueue_and_size():
    queue = InMemoryQueue(concurrency=2, max_size=5)
    assert queue.enqueue(make_msg("1", "a"))
    assert queue.enqueue(make_msg("2", "b"))
    assert queue.size() == 2


@pytest.mark.asyncio
async def test_max_size_overflow():
    queue = InMemoryQueue(concurrency=1, max_size=3)
    for i in range(3):
        assert queue.enqueue(make_msg(str(i), f"msg{i}"))
    assert queue.size() == 3
    # 4th should be rejected
    assert not queue.enqueue(make_msg("3", "overflow"))
    assert queue.size() == 3


@pytest.mark.asyncio
async def test_process_messages():
    queue = InMemoryQueue(concurrency=2, max_size=10)
    processed: list[str] = []

    async def handler(msg: UnifiedMessage):
        processed.append(msg.content.text)
        return msg.content.text

    queue.enqueue(make_msg("1", "hello"))
    queue.enqueue(make_msg("2", "world"))
    queue.on_process(handler)
    queue.start()

    await queue.drain()
    await queue.stop()
    assert processed == ["hello", "world"]
    assert queue.size() == 0


@pytest.mark.asyncio
async def test_concurrency_limit():
    queue = InMemoryQueue(concurrency=2, max_size=10)
    concurrent = 0
    max_concurrent = 0
    events: list[asyncio.Event] = []

    async def handler(msg: UnifiedMessage):
        nonlocal concurrent, max_concurrent
        concurrent += 1
        max_concurrent = max(max_concurrent, concurrent)
        event = asyncio.Event()
        events.append(event)
        await event.wait()
        concurrent -= 1
        return None

    for i in range(4):
        queue.enqueue(make_msg(str(i), f"msg{i}"))

    queue.on_process(handler)
    queue.start()

    # Let workers pick up items
    await asyncio.sleep(0.15)
    assert max_concurrent == 2
    assert concurrent == 2

    # Release first batch
    for e in events[:2]:
        e.set()
    await asyncio.sleep(0.15)

    # Release second batch
    for e in events[2:]:
        e.set()

    await queue.drain()
    await queue.stop()
    assert concurrent == 0


@pytest.mark.asyncio
async def test_drain_empty_queue():
    queue = InMemoryQueue(concurrency=2)

    async def noop(msg: UnifiedMessage):
        return None

    queue.on_process(noop)
    queue.start()
    # Should not hang
    await asyncio.wait_for(queue.drain(), timeout=1.0)
    await queue.stop()


@pytest.mark.asyncio
async def test_stop_prevents_processing():
    queue = InMemoryQueue(concurrency=1, max_size=10)
    processed: list[str] = []

    async def handler(msg: UnifiedMessage):
        processed.append(msg.content.text)
        return None

    queue.on_process(handler)
    queue.enqueue(make_msg("1", "before"))
    queue.start()
    await queue.drain()
    assert processed == ["before"]

    await queue.stop()
    queue.enqueue(make_msg("2", "after-stop"))
    # Message is queued but no workers running
    assert queue.size() == 1
    assert processed == ["before"]


@pytest.mark.asyncio
async def test_error_handling():
    queue = InMemoryQueue(concurrency=2, max_size=10)
    call_count = 0

    async def handler(msg: UnifiedMessage):
        nonlocal call_count
        call_count += 1
        if msg.content.text == "fail":
            raise RuntimeError("boom")
        return msg.content.text

    queue.enqueue(make_msg("1", "fail"))
    queue.enqueue(make_msg("2", "ok"))
    queue.on_process(handler)
    queue.start()

    await queue.drain()
    await queue.stop()
    # Both processed despite error in first
    assert call_count == 2


@pytest.mark.asyncio
async def test_queue_middleware():
    queue = InMemoryQueue(concurrency=1, max_size=10)
    mw = QueueMiddleware(queue)

    next_called = False

    async def next_handler(msg):
        nonlocal next_called
        next_called = True
        return "should not reach"

    msg = make_msg("1", "hello")
    result = await mw.process(msg, next_handler)

    assert result is None
    assert queue.size() == 1
    assert not next_called


@pytest.mark.asyncio
async def test_queue_middleware_full():
    queue = InMemoryQueue(concurrency=1, max_size=1)
    mw = QueueMiddleware(queue)

    queue.enqueue(make_msg("1", "fill"))
    result = await mw.process(make_msg("2", "overflow"), lambda m: asyncio.sleep(0))

    assert result is None
    assert queue.size() == 1


@pytest.mark.asyncio
async def test_queue_processor():
    queue = InMemoryQueue(concurrency=2, max_size=10)
    sent_replies: list[tuple[str, str]] = []

    async def send_reply(chat_id, result):
        sent_replies.append((chat_id, result))

    processor = QueueProcessor(queue, send_reply)

    queue.enqueue(make_msg("1", "hello"))
    queue.enqueue(make_msg("2", "world"))

    async def reply_handler(msg: UnifiedMessage):
        return f"reply: {msg.content.text}"

    processor.start(handler=reply_handler)

    await queue.drain()
    await processor.stop()

    assert len(sent_replies) == 2
    assert sent_replies[0] == ("chat1", "reply: hello")
    assert sent_replies[1] == ("chat1", "reply: world")
