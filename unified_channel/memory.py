"""ConversationMemory middleware — maintains per-chat conversation history."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime
from typing import Any

from .middleware import Handler, Middleware
from .types import UnifiedMessage

logger = logging.getLogger(__name__)


class MemoryStore(ABC):
    """Pluggable storage backend for conversation history."""

    @abstractmethod
    async def get(self, key: str) -> list[dict[str, Any]]:
        """Return full history for the given key."""

    @abstractmethod
    async def append(self, key: str, entry: dict[str, Any]) -> None:
        """Append a single entry to the history."""

    @abstractmethod
    async def trim(self, key: str, max_entries: int) -> None:
        """Keep only the last *max_entries* items."""

    @abstractmethod
    async def clear(self, key: str) -> None:
        """Delete all history for the given key."""


class InMemoryStore(MemoryStore):
    """Default in-memory store (dict-based). Data is lost on restart."""

    def __init__(self) -> None:
        self._data: dict[str, list[dict[str, Any]]] = defaultdict(list)

    async def get(self, key: str) -> list[dict[str, Any]]:
        return list(self._data[key])

    async def append(self, key: str, entry: dict[str, Any]) -> None:
        self._data[key].append(entry)

    async def trim(self, key: str, max_entries: int) -> None:
        history = self._data[key]
        if len(history) > max_entries:
            self._data[key] = history[-max_entries:]

    async def clear(self, key: str) -> None:
        self._data.pop(key, None)


class SQLiteStore(MemoryStore):
    """SQLite-backed persistent store."""

    def __init__(self, db_path: str = "unified_channel_memory.db") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS memory ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  key TEXT NOT NULL,"
            "  entry TEXT NOT NULL"
            ")"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_key ON memory(key)"
        )
        self._conn.commit()

    async def get(self, key: str) -> list[dict[str, Any]]:
        cursor = self._conn.execute(
            "SELECT entry FROM memory WHERE key = ? ORDER BY id", (key,)
        )
        return [json.loads(row[0]) for row in cursor.fetchall()]

    async def append(self, key: str, entry: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO memory (key, entry) VALUES (?, ?)",
            (key, json.dumps(entry)),
        )
        self._conn.commit()

    async def trim(self, key: str, max_entries: int) -> None:
        # Keep the last max_entries rows for this key
        cursor = self._conn.execute(
            "SELECT id FROM memory WHERE key = ? ORDER BY id DESC LIMIT -1 OFFSET ?",
            (key, max_entries),
        )
        ids_to_delete = [row[0] for row in cursor.fetchall()]
        if ids_to_delete:
            placeholders = ",".join("?" for _ in ids_to_delete)
            self._conn.execute(
                f"DELETE FROM memory WHERE id IN ({placeholders})",
                ids_to_delete,
            )
            self._conn.commit()

    async def clear(self, key: str) -> None:
        self._conn.execute("DELETE FROM memory WHERE key = ?", (key,))
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()


class RedisStore(MemoryStore):
    """Redis-backed store (requires redis[hiredis])."""

    def __init__(
        self, url: str = "redis://localhost:6379", prefix: str = "uc:"
    ) -> None:
        try:
            import redis.asyncio as aioredis
        except ImportError as exc:
            raise ImportError(
                "RedisStore requires the 'redis' package: pip install redis[hiredis]"
            ) from exc
        self._redis = aioredis.from_url(url, decode_responses=True)
        self._prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> list[dict[str, Any]]:
        raw_list = await self._redis.lrange(self._key(key), 0, -1)
        return [json.loads(item) for item in raw_list]

    async def append(self, key: str, entry: dict[str, Any]) -> None:
        await self._redis.rpush(self._key(key), json.dumps(entry))

    async def trim(self, key: str, max_entries: int) -> None:
        # Keep the last max_entries items
        await self._redis.ltrim(self._key(key), -max_entries, -1)

    async def clear(self, key: str) -> None:
        await self._redis.delete(self._key(key))


class ConversationMemory(Middleware):
    """Maintains per-chat conversation history, injected into msg.metadata["history"]."""

    def __init__(
        self,
        store: MemoryStore | None = None,
        max_turns: int = 50,
    ) -> None:
        self.store = store or InMemoryStore()
        self.max_turns = max_turns

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> Any:
        chat_key = f"{msg.channel}:{msg.chat_id}"
        history = await self.store.get(chat_key)
        msg.metadata = msg.metadata or {}
        msg.metadata["history"] = history

        result = await next_handler(msg)

        # Save user message
        await self.store.append(
            chat_key,
            {
                "role": "user",
                "content": msg.content.text,
                "sender": msg.sender.id,
                "timestamp": msg.timestamp.isoformat(),
            },
        )

        # Save bot reply
        if result:
            if isinstance(result, str):
                reply_text = result
            elif hasattr(result, "text"):
                reply_text = result.text
            else:
                reply_text = str(result)
            await self.store.append(
                chat_key,
                {
                    "role": "assistant",
                    "content": reply_text,
                    "timestamp": datetime.now().isoformat(),
                },
            )

        # Trim in background — don't block the response
        asyncio.create_task(self._safe_trim(chat_key))
        return result

    async def _safe_trim(self, chat_key: str) -> None:
        """Trim history in background, swallowing errors."""
        try:
            await self.store.trim(chat_key, self.max_turns)
        except Exception as e:
            logger.warning("Memory trim failed for %s: %s", chat_key, e)
