"""
Customer Service persistent store — SQLite-backed.

Handles:
- Session ↔ Topic mapping (survives restart)
- Message history (per session)
- User info persistence
- Agent assignment tracking
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any


class CSStore:
    """SQLite-backed persistent store for customer service sessions."""

    def __init__(self, db_path: str = "cs_data.db") -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                topic_id INTEGER,
                channel TEXT DEFAULT 'webchat',
                user_type TEXT DEFAULT 'anonymous',
                user_id TEXT,
                user_name TEXT,
                user_phone TEXT,
                user_extra TEXT DEFAULT '{}',
                user_lang TEXT DEFAULT 'zh',
                assigned_agent TEXT,
                status TEXT DEFAULT 'active',
                first_reply_at TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now')),
                closed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_topic ON sessions(topic_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                content TEXT NOT NULL,
                media_url TEXT,
                media_type TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);

            CREATE TABLE IF NOT EXISTS ratings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                score INTEGER NOT NULL,
                comment TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                created_by TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS sensitive_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                original_text TEXT NOT NULL,
                matched_words TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            );
        """)
        self._conn.commit()

    # --- Session management ---

    def get_session(self, session_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_session_by_topic(self, topic_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE topic_id = ?", (topic_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_session_by_user_id(self, user_id: str) -> dict | None:
        """Find existing active session for a logged-in user."""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None

    def create_session(
        self,
        session_id: str,
        *,
        topic_id: int | None = None,
        channel: str = "webchat",
        user_type: str = "anonymous",
        user_id: str | None = None,
        user_name: str | None = None,
        user_phone: str | None = None,
        user_extra: dict | None = None,
    ) -> dict:
        self._conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, topic_id, channel, user_type, user_id, user_name, user_phone, user_extra, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                session_id,
                topic_id,
                channel,
                user_type,
                user_id,
                user_name,
                user_phone,
                json.dumps(user_extra or {}),
            ),
        )
        self._conn.commit()
        return self.get_session(session_id)  # type: ignore

    def set_topic_id(self, session_id: str, topic_id: int) -> None:
        self._conn.execute(
            "UPDATE sessions SET topic_id = ?, updated_at = datetime('now') WHERE session_id = ?",
            (topic_id, session_id),
        )
        self._conn.commit()

    def set_assigned_agent(self, session_id: str, agent: str) -> None:
        self._conn.execute(
            "UPDATE sessions SET assigned_agent = ?, updated_at = datetime('now') WHERE session_id = ?",
            (agent, session_id),
        )
        self._conn.commit()

    def set_user_lang(self, session_id: str, lang: str) -> None:
        self._conn.execute(
            "UPDATE sessions SET user_lang = ?, updated_at = datetime('now') WHERE session_id = ?",
            (lang, session_id),
        )
        self._conn.commit()

    def get_user_lang(self, session_id: str) -> str:
        row = self._conn.execute(
            "SELECT user_lang FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return row["user_lang"] if row and row["user_lang"] else "zh"

    def set_first_reply(self, session_id: str) -> None:
        self._conn.execute(
            "UPDATE sessions SET first_reply_at = datetime('now') WHERE session_id = ? AND first_reply_at IS NULL",
            (session_id,),
        )
        self._conn.commit()

    def close_session(self, session_id: str) -> None:
        self._conn.execute(
            "UPDATE sessions SET status = 'closed', closed_at = datetime('now') WHERE session_id = ?",
            (session_id,),
        )
        self._conn.commit()

    def get_active_sessions(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM sessions WHERE status = 'active' ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Topic mapping (bulk load for startup) ---

    def load_all_mappings(self) -> tuple[dict[str, int], dict[int, str]]:
        """Load all session↔topic mappings. Returns (session_to_topic, topic_to_session)."""
        rows = self._conn.execute(
            "SELECT session_id, topic_id FROM sessions WHERE topic_id IS NOT NULL AND status = 'active'"
        ).fetchall()
        s2t = {r["session_id"]: r["topic_id"] for r in rows}
        t2s = {r["topic_id"]: r["session_id"] for r in rows}
        return s2t, t2s

    # --- Message history ---

    def add_message(
        self,
        session_id: str,
        sender: str,
        content: str,
        media_url: str | None = None,
        media_type: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            """INSERT INTO messages (session_id, sender, content, media_url, media_type)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, sender, content, media_url, media_type),
        )
        self._conn.commit()
        # Touch session updated_at
        self._conn.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE session_id = ?",
            (session_id,),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore

    def get_messages(
        self, session_id: str, limit: int = 50, before_id: int | None = None
    ) -> list[dict]:
        if before_id:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE session_id = ? AND id < ? ORDER BY id DESC LIMIT ?",
                (session_id, before_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [dict(r) for r in reversed(rows)]

    # --- Ratings ---

    def add_rating(self, session_id: str, score: int, comment: str = "") -> None:
        self._conn.execute(
            "INSERT INTO ratings (session_id, score, comment) VALUES (?, ?, ?)",
            (session_id, score, comment),
        )
        self._conn.commit()

    def get_rating(self, session_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM ratings WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return dict(row) if row else None

    # --- Agent stats ---

    def get_agent_load(self) -> dict[str, int]:
        """Get active session count per agent."""
        rows = self._conn.execute(
            "SELECT assigned_agent, COUNT(*) as cnt FROM sessions WHERE status = 'active' AND assigned_agent IS NOT NULL GROUP BY assigned_agent"
        ).fetchall()
        return {r["assigned_agent"]: r["cnt"] for r in rows}

    # --- Tickets ---

    def create_ticket(self, session_id: str, title: str, created_by: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO tickets (session_id, title, created_by) VALUES (?, ?, ?)",
            (session_id, title, created_by),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore

    def get_tickets(self, session_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM tickets WHERE session_id = ? ORDER BY created_at DESC", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Sensitive word log ---

    def log_sensitive(self, session_id: str, text: str, matched: list[str]) -> None:
        self._conn.execute(
            "INSERT INTO sensitive_log (session_id, original_text, matched_words) VALUES (?, ?, ?)",
            (session_id, text, ",".join(matched)),
        )
        self._conn.commit()

    # --- Reports ---

    def daily_report(self, date: str | None = None) -> dict:
        """Generate daily stats. date format: YYYY-MM-DD, defaults to today."""
        if not date:
            date = datetime.now().strftime("%Y-%m-%d")

        total = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE created_at LIKE ?", (f"{date}%",)
        ).fetchone()["cnt"]

        closed = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM sessions WHERE closed_at LIKE ?", (f"{date}%",)
        ).fetchone()["cnt"]

        avg_rating = self._conn.execute(
            "SELECT AVG(score) as avg FROM ratings WHERE created_at LIKE ?", (f"{date}%",)
        ).fetchone()["avg"]

        msg_count = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM messages WHERE timestamp LIKE ?", (f"{date}%",)
        ).fetchone()["cnt"]

        # Avg first reply time (seconds)
        reply_times = self._conn.execute(
            """SELECT AVG(
                (julianday(first_reply_at) - julianday(created_at)) * 86400
            ) as avg_seconds
            FROM sessions
            WHERE first_reply_at IS NOT NULL AND created_at LIKE ?""",
            (f"{date}%",),
        ).fetchone()["avg_seconds"]

        # Per-agent stats
        agent_rows = self._conn.execute(
            """SELECT assigned_agent, COUNT(*) as sessions,
               (SELECT COUNT(*) FROM messages m
                WHERE m.session_id IN (SELECT session_id FROM sessions s2 WHERE s2.assigned_agent = s.assigned_agent AND s2.created_at LIKE ?)
                AND m.sender = 'agent') as replies
            FROM sessions s
            WHERE created_at LIKE ? AND assigned_agent IS NOT NULL
            GROUP BY assigned_agent""",
            (f"{date}%", f"{date}%"),
        ).fetchall()

        return {
            "date": date,
            "total_sessions": total,
            "closed_sessions": closed,
            "total_messages": msg_count,
            "avg_rating": round(avg_rating, 1) if avg_rating else None,
            "avg_first_reply_seconds": round(reply_times) if reply_times else None,
            "agents": [dict(r) for r in agent_rows],
        }

    def hot_keywords(self, days: int = 7, top_n: int = 20) -> list[tuple[str, int]]:
        """Extract most common words from user messages in recent N days."""
        rows = self._conn.execute(
            """SELECT content FROM messages
               WHERE sender = 'user'
               AND timestamp >= datetime('now', ?)""",
            (f"-{days} days",),
        ).fetchall()

        # Simple word frequency (split by common delimiters)
        from collections import Counter
        counter: Counter[str] = Counter()
        stop_words = {"的", "了", "是", "在", "我", "你", "有", "不", "这", "就", "都", "也",
                      "要", "会", "可以", "吗", "呢", "啊", "嗯", "好", "a", "the", "is", "i",
                      "to", "and", "it", "of", "in", "that", "for", "on", "my", "me", "do"}
        for row in rows:
            text = row["content"].strip()
            if len(text) < 2:
                continue
            # For Chinese: use character bigrams; for others: split by spaces
            words = text.lower().split()
            if len(words) <= 1 and len(text) > 1:
                # Likely Chinese — use bigrams
                words = [text[i:i+2] for i in range(len(text)-1)]
            counter.update(w for w in words if w not in stop_words and len(w) > 1)

        return counter.most_common(top_n)

    def close(self) -> None:
        self._conn.close()
