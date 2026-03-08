"""
Example: Remote management of X project via Telegram.

This is a standalone example showing the unified-channel pattern.
For the real integration, use: python -m src.telegram_bot

Usage:
    TELEGRAM_TOKEN=xxx ADMIN_USER_ID=123 python examples/x_project_telegram.py
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unified_channel import (
    AccessMiddleware,
    ChannelManager,
    CommandMiddleware,
    TelegramAdapter,
    UnifiedMessage,
)

TOKEN = os.environ["TELEGRAM_TOKEN"]
ADMIN_ID = os.environ["ADMIN_USER_ID"]

manager = ChannelManager()
manager.add_channel(TelegramAdapter(token=TOKEN))
manager.add_middleware(AccessMiddleware(allowed_user_ids={ADMIN_ID}))

cmds = CommandMiddleware()
manager.add_middleware(cmds)


@cmds.command("start")
async def start(msg: UnifiedMessage) -> str:
    commands = cmds.registered_commands
    lines = [f"/{c}" for c in sorted(commands)]
    return "Available commands:\n" + "\n".join(lines)


@cmds.command("status")
async def status(msg: UnifiedMessage) -> str:
    # In real integration, this calls aggregate_metrics(queue, data_dir)
    return (
        "*System Status*\n"
        "Jobs running: 3\n"
        "Jobs queued: 12\n"
        "Failed (24h): 0"
    )


@cmds.command("accounts")
async def accounts(msg: UnifiedMessage) -> str:
    # In real integration, this lists accounts/ directories + daily plans
    return (
        "*Accounts*\n"
        "  gambletan: 3/5 posts executed\n"
        "  alvinsclub: 2/4 posts executed"
    )


@cmds.command("jobs")
async def jobs(msg: UnifiedMessage) -> str:
    # In real integration, this queries JobQueue.get_distinct_job_types()
    return (
        "*Running*\n"
        "  gambletan.execute - started 2m ago\n"
        "*Queued*\n"
        "  alvinsclub.fetch"
    )


@cmds.command("run")
async def run_job(msg: UnifiedMessage) -> str:
    if not msg.content.args or len(msg.content.args) < 2:
        return "Usage: /run <account> <job\\_type> [--dry-run]"
    account_id = msg.content.args[0]
    job_type = msg.content.args[1]
    # In real integration: queue.enqueue(account_id, job_type)
    return f"Enqueued: `{account_id}.{job_type}`"


@cmds.command("metrics")
async def metrics(msg: UnifiedMessage) -> str:
    # In real integration, this calls compute_account_metrics(db_path)
    account = msg.content.args[0] if msg.content.args else "gambletan"
    return (
        f"*Metrics: {account}*\n"
        "Total posts: 142\n"
        "Posts (7d): 18\n"
        "Trend: Improving\n"
        "Best structure: spicy\\_take"
    )


@cmds.command("plan")
async def plan_cmd(msg: UnifiedMessage) -> str:
    account = msg.content.args[0] if msg.content.args else "gambletan"
    return (
        f"*Daily Plan: {account}*\n"
        "  1. [done] 09:30 - breaking\\_news\n"
        "  2. [done] 12:00 - spicy\\_take\n"
        "  3. [pending] 15:30 - builder\\_lesson"
    )


@cmds.command("workers")
async def workers_cmd(msg: UnifiedMessage) -> str:
    # In real integration: queue.get_worker_heartbeats()
    return (
        "*Workers*\n"
        "  worker-1 pid=12345 job=idle seen=5s ago"
    )


@cmds.command("logs")
async def logs(msg: UnifiedMessage) -> str:
    account = msg.content.args[0] if msg.content.args else "gambletan"
    n = 5
    if len(msg.content.args or []) > 1:
        try:
            n = int(msg.content.args[1])
        except ValueError:
            pass
    return f"(last {n} log entries for {account} would appear here)"


@cmds.command("recover")
async def recover(msg: UnifiedMessage) -> str:
    # In real integration: queue.recover_stale(timeout_minutes)
    return "Recovered 0 stale jobs (>60min threshold)"


@manager.on_message
async def on_message(msg: UnifiedMessage) -> str:
    return "Unknown command. Send /start for available commands."


if __name__ == "__main__":
    asyncio.run(manager.run())
