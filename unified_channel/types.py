"""Unified message types — the core abstraction that all channels share."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ContentType(Enum):
    TEXT = "text"
    COMMAND = "command"
    MEDIA = "media"
    REACTION = "reaction"
    EDIT = "edit"
    CALLBACK = "callback"


@dataclass
class Identity:
    id: str
    username: str | None = None
    display_name: str | None = None


@dataclass
class MessageContent:
    type: ContentType
    text: str = ""
    command: str | None = None  # parsed command name (without /)
    args: list[str] = field(default_factory=list)
    media_url: str | None = None
    media_type: str | None = None
    callback_data: str | None = None


@dataclass
class UnifiedMessage:
    """Single message type that flows through the entire pipeline."""

    id: str
    channel: str  # "telegram", "discord", "slack", ...
    sender: Identity
    content: MessageContent
    timestamp: datetime = field(default_factory=datetime.now)
    thread_id: str | None = None
    reply_to_id: str | None = None
    chat_id: str | None = None
    raw: Any = None  # original platform-specific object
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class OutboundMessage:
    """Message to send back via a channel."""

    chat_id: str
    text: str = ""
    reply_to_id: str | None = None
    media_url: str | None = None
    media_type: str | None = None
    parse_mode: str | None = None  # "markdown", "html", None
    buttons: list[list[Button]] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Button:
    label: str
    callback_data: str | None = None
    url: str | None = None


@dataclass
class ChannelStatus:
    connected: bool
    channel: str
    account_id: str | None = None
    error: str | None = None
    last_activity: datetime | None = None
