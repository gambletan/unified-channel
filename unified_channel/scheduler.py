"""Scheduler — schedule periodic messages or tasks across channels."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Union

from .manager import ChannelManager

logger = logging.getLogger(__name__)

# Callback can be a plain string or an async/sync callable returning a string.
TaskCallback = Union[str, Callable[[], Any]]

_task_counter = 0


def _next_id() -> str:
    global _task_counter
    _task_counter += 1
    return f"task_{_task_counter}"


@dataclass
class CronSchedule:
    """Parsed cron expression fields."""

    minute: list[int]
    hour: list[int]
    dom: list[int]
    month: list[int]
    dow: list[int]


def parse_cron(expr: str) -> CronSchedule:
    """
    Parse a simple cron expression: "min hour dom month dow".

    Supports exact values, ``*`` (any), and comma-separated lists.
    """
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(
            f'Invalid cron expression "{expr}": expected 5 fields (min hour dom month dow)'
        )

    def _parse_field(raw: str, lo: int, hi: int) -> list[int]:
        if raw == "*":
            return list(range(lo, hi + 1))
        values: list[int] = []
        for token in raw.split(","):
            n = int(token)
            if n < lo or n > hi:
                raise ValueError(
                    f'Invalid cron field value "{token}" (expected {lo}-{hi})'
                )
            values.append(n)
        return values

    return CronSchedule(
        minute=_parse_field(parts[0], 0, 59),
        hour=_parse_field(parts[1], 0, 23),
        dom=_parse_field(parts[2], 1, 31),
        month=_parse_field(parts[3], 1, 12),
        dow=_parse_field(parts[4], 0, 6),
    )


def cron_matches(parsed: CronSchedule, dt: datetime) -> bool:
    """Check whether *dt* matches the parsed cron schedule."""
    return (
        dt.minute in parsed.minute
        and dt.hour in parsed.hour
        and dt.day in parsed.dom
        and dt.month in parsed.month
        and dt.weekday() in _convert_dow(parsed.dow)
    )


def _convert_dow(cron_dow: list[int]) -> list[int]:
    """Convert cron dow (0=Sunday) to Python weekday (0=Monday)."""
    mapping = {0: 6, 1: 0, 2: 1, 3: 2, 4: 3, 5: 4, 6: 5}
    return [mapping[d] for d in cron_dow]


@dataclass
class ScheduledTask:
    id: str
    type: str  # "every" | "cron" | "once"
    channel_id: str
    chat_id: str
    schedule: Union[float, str]
    active: bool = True
    callback: TaskCallback = ""
    _handle: asyncio.Task[Any] | None = field(default=None, repr=False)


class Scheduler:
    """Schedule periodic messages or tasks through a ChannelManager."""

    def __init__(self, manager: ChannelManager) -> None:
        self._manager = manager
        self._tasks: dict[str, ScheduledTask] = {}

    def every(
        self,
        interval_sec: float,
        channel_id: str,
        chat_id: str,
        callback: TaskCallback,
    ) -> str:
        """Schedule a repeating task at a fixed interval (in seconds)."""
        task_id = _next_id()
        task = ScheduledTask(
            id=task_id,
            type="every",
            channel_id=channel_id,
            chat_id=chat_id,
            schedule=interval_sec,
            callback=callback,
        )
        task._handle = asyncio.ensure_future(self._run_every(task, interval_sec))
        self._tasks[task_id] = task
        return task_id

    def cron(
        self,
        cron_expr: str,
        channel_id: str,
        chat_id: str,
        callback: TaskCallback,
    ) -> str:
        """Schedule a task using a cron expression (checked every 60s)."""
        parsed = parse_cron(cron_expr)
        task_id = _next_id()
        task = ScheduledTask(
            id=task_id,
            type="cron",
            channel_id=channel_id,
            chat_id=chat_id,
            schedule=cron_expr,
            callback=callback,
        )
        task._handle = asyncio.ensure_future(self._run_cron(task, parsed))
        self._tasks[task_id] = task
        return task_id

    def once(
        self,
        delay_sec: float,
        channel_id: str,
        chat_id: str,
        callback: TaskCallback,
    ) -> str:
        """Schedule a one-shot delayed task."""
        task_id = _next_id()
        task = ScheduledTask(
            id=task_id,
            type="once",
            channel_id=channel_id,
            chat_id=chat_id,
            schedule=delay_sec,
            callback=callback,
        )
        task._handle = asyncio.ensure_future(self._run_once(task, delay_sec))
        self._tasks[task_id] = task
        return task_id

    def cancel(self, task_id: str) -> bool:
        """Cancel a scheduled task. Returns True if found and cancelled."""
        task = self._tasks.pop(task_id, None)
        if task is None:
            return False
        task.active = False
        if task._handle and not task._handle.done():
            task._handle.cancel()
        return True

    def list(self) -> list[dict[str, Any]]:
        """List all active scheduled tasks."""
        return [
            {
                "id": t.id,
                "type": t.type,
                "channel_id": t.channel_id,
                "chat_id": t.chat_id,
                "schedule": t.schedule,
                "active": t.active,
            }
            for t in self._tasks.values()
            if t.active
        ]

    def stop(self) -> None:
        """Stop all scheduled tasks."""
        for task in self._tasks.values():
            task.active = False
            if task._handle and not task._handle.done():
                task._handle.cancel()
        self._tasks.clear()

    # -- internal runners --

    async def _resolve_text(self, callback: TaskCallback) -> str:
        if isinstance(callback, str):
            return callback
        result = callback()
        if asyncio.iscoroutine(result):
            result = await result
        return str(result)

    async def _execute(self, task: ScheduledTask) -> None:
        if not task.active:
            return
        try:
            text = await self._resolve_text(task.callback)
            await self._manager.send(task.channel_id, task.chat_id, text)
        except Exception:
            logger.exception("Scheduler task %s failed", task.id)

    async def _run_every(self, task: ScheduledTask, interval: float) -> None:
        try:
            while task.active:
                await asyncio.sleep(interval)
                if task.active:
                    await self._execute(task)
        except asyncio.CancelledError:
            pass

    async def _run_cron(self, task: ScheduledTask, parsed: CronSchedule) -> None:
        try:
            while task.active:
                await asyncio.sleep(60)
                if task.active and cron_matches(parsed, datetime.now()):
                    await self._execute(task)
        except asyncio.CancelledError:
            pass

    async def _run_once(self, task: ScheduledTask, delay: float) -> None:
        try:
            await asyncio.sleep(delay)
            if task.active:
                await self._execute(task)
                task.active = False
        except asyncio.CancelledError:
            pass
