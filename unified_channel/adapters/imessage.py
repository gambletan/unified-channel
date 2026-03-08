"""iMessage adapter — macOS-only, uses AppleScript + Messages.app SQLite DB.

No external dependencies beyond macOS system libraries.
Polls the Messages database for new messages and sends via AppleScript.

Requirements:
  - macOS only
  - Full Disk Access for the process (to read ~/Library/Messages/chat.db)
  - Messages.app must be running and signed in
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from ..adapter import ChannelAdapter
from ..types import (
    ChannelStatus,
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)

logger = logging.getLogger(__name__)

# macOS Messages database (requires Full Disk Access)
CHAT_DB = Path.home() / "Library" / "Messages" / "chat.db"

# Apple's Core Data epoch: 2001-01-01 00:00:00 UTC
APPLE_EPOCH = 978307200


class IMessageAdapter(ChannelAdapter):
    """
    iMessage adapter for macOS.

    Reads messages by polling the Messages SQLite database.
    Sends messages via AppleScript / Messages.app.
    """

    channel_id = "imessage"

    def __init__(
        self,
        *,
        allowed_numbers: set[str] | None = None,
        poll_interval: float = 3.0,
        command_prefix: str = "/",
    ) -> None:
        self._allowed_numbers = allowed_numbers
        self._poll_interval = poll_interval
        self._prefix = command_prefix
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._last_rowid = 0  # track last processed message ROWID
        self._poll_task: asyncio.Task | None = None

    async def connect(self) -> None:
        if not CHAT_DB.exists():
            raise RuntimeError(
                f"Messages database not found: {CHAT_DB}\n"
                "This adapter requires macOS with Messages.app."
            )

        # Get the latest ROWID to avoid processing old messages
        try:
            conn = sqlite3.connect(f"file:{CHAT_DB}?mode=ro", uri=True)
            row = conn.execute("SELECT MAX(ROWID) FROM message").fetchone()
            self._last_rowid = row[0] or 0
            conn.close()
        except sqlite3.OperationalError as e:
            raise RuntimeError(
                f"Cannot read Messages database: {e}\n"
                "Grant Full Disk Access to this process in System Settings > Privacy."
            ) from e

        self._connected = True
        self._poll_task = asyncio.create_task(self._poll_loop())
        logger.info("imessage connected: polling from ROWID %d", self._last_rowid)

    async def disconnect(self) -> None:
        self._connected = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        logger.info("imessage disconnected")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def send(self, msg: OutboundMessage) -> str | None:
        # Determine if it's a phone number or email
        chat_id = msg.chat_id
        if "@" in chat_id:
            service = "iMessage"
        else:
            service = "iMessage"

        # Escape text for AppleScript
        text = msg.text.replace("\\", "\\\\").replace('"', '\\"')

        script = f'''
        tell application "Messages"
            set targetService to 1st account whose service type = iMessage
            set targetBuddy to participant "{chat_id}" of targetService
            send "{text}" to targetBuddy
        end tell
        '''

        try:
            proc = await asyncio.create_subprocess_exec(
                "osascript", "-e", script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                logger.error("imessage send failed: %s", stderr.decode().strip())
                return None
            self._last_activity = datetime.now()
            return None  # AppleScript doesn't return message ID
        except Exception as e:
            logger.error("imessage send error: %s", e)
            return None

    async def get_status(self) -> ChannelStatus:
        return ChannelStatus(
            connected=self._connected,
            channel="imessage",
            last_activity=self._last_activity,
        )

    async def _poll_loop(self) -> None:
        """Poll the Messages database for new messages."""
        while self._connected:
            try:
                await self._check_new_messages()
            except Exception as e:
                logger.error("imessage poll error: %s", e)
            await asyncio.sleep(self._poll_interval)

    async def _check_new_messages(self) -> None:
        """Read new messages from the SQLite database."""
        conn = sqlite3.connect(f"file:{CHAT_DB}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT
                    m.ROWID,
                    m.guid,
                    m.text,
                    m.date,
                    m.is_from_me,
                    m.cache_has_attachments,
                    h.id as handle_id,
                    h.uncanonicalized_id as handle_raw
                FROM message m
                LEFT JOIN handle h ON m.handle_id = h.ROWID
                WHERE m.ROWID > ?
                  AND m.is_from_me = 0
                  AND m.text IS NOT NULL
                  AND m.text != ''
                ORDER BY m.ROWID ASC
                LIMIT 50
                """,
                (self._last_rowid,),
            ).fetchall()

            for row in rows:
                self._last_rowid = row["ROWID"]
                handle = row["handle_id"] or ""

                # Filter by allowed numbers
                if self._allowed_numbers and handle not in self._allowed_numbers:
                    continue

                text = row["text"] or ""
                self._last_activity = datetime.now()

                # Parse command
                if text.startswith(self._prefix):
                    parts = text[len(self._prefix):].split()
                    cmd = parts[0] if parts else ""
                    args = parts[1:]
                    mc = MessageContent(type=ContentType.COMMAND, text=text, command=cmd, args=args)
                elif row["cache_has_attachments"]:
                    mc = MessageContent(type=ContentType.MEDIA, text=text, media_type="attachment")
                else:
                    mc = MessageContent(type=ContentType.TEXT, text=text)

                # Convert Apple timestamp to datetime
                apple_ts = row["date"]
                if apple_ts:
                    # date field is nanoseconds since 2001-01-01 in newer macOS
                    if apple_ts > 1e15:
                        ts = datetime.fromtimestamp(apple_ts / 1e9 + APPLE_EPOCH, tz=timezone.utc)
                    else:
                        ts = datetime.fromtimestamp(apple_ts + APPLE_EPOCH, tz=timezone.utc)
                else:
                    ts = datetime.now(tz=timezone.utc)

                msg = UnifiedMessage(
                    id=row["guid"],
                    channel="imessage",
                    sender=Identity(id=handle, display_name=row["handle_raw"]),
                    content=mc,
                    timestamp=ts,
                    chat_id=handle,
                    raw=dict(row),
                )
                await self._queue.put(msg)
        finally:
            conn.close()
