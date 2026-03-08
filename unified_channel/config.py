"""YAML config loader — create a ChannelManager from a config file."""

from __future__ import annotations

import importlib
import os
import re
from typing import Any

from .manager import ChannelManager
from .middleware import AccessMiddleware, CommandMiddleware

# Adapter class name lookup: short name -> (module_path, class_name)
_ADAPTER_MAP: dict[str, tuple[str, str]] = {
    "telegram": (".adapters.telegram", "TelegramAdapter"),
    "discord": (".adapters.discord", "DiscordAdapter"),
    "slack": (".adapters.slack", "SlackAdapter"),
    "whatsapp": (".adapters.whatsapp", "WhatsAppAdapter"),
    "imessage": (".adapters.imessage", "IMessageAdapter"),
    "line": (".adapters.line", "LineAdapter"),
    "matrix": (".adapters.matrix", "MatrixAdapter"),
    "msteams": (".adapters.msteams", "MSTeamsAdapter"),
    "feishu": (".adapters.feishu", "FeishuAdapter"),
    "mattermost": (".adapters.mattermost", "MattermostAdapter"),
    "googlechat": (".adapters.googlechat", "GoogleChatAdapter"),
    "nextcloud": (".adapters.nextcloud_talk", "NextcloudTalkAdapter"),
    "synology": (".adapters.synology_chat", "SynologyChatAdapter"),
    "zalo": (".adapters.zalo", "ZaloAdapter"),
    "nostr": (".adapters.nostr", "NostrAdapter"),
    "bluebubbles": (".adapters.bluebubbles", "BlueBubblesAdapter"),
    "twitch": (".adapters.twitch", "TwitchAdapter"),
    "irc": (".adapters.irc", "IRCAdapter"),
}

_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _interpolate_env(value: Any) -> Any:
    """Replace ${VAR} references with environment variable values."""
    if not isinstance(value, str):
        return value

    def _replace(match: re.Match[str]) -> str:
        var = match.group(1)
        env_val = os.environ.get(var)
        if env_val is None:
            raise ValueError(f"environment variable not set: {var}")
        return env_val

    return _ENV_PATTERN.sub(_replace, value)


def _interpolate_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively interpolate environment variables in a dict."""
    result: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _interpolate_dict(v)
        elif isinstance(v, list):
            result[k] = [_interpolate_env(item) for item in v]
        else:
            result[k] = _interpolate_env(v)
    return result


def _make_adapter(name: str, config: dict[str, Any]) -> Any:
    """Instantiate an adapter by short name with the given config dict."""
    if name not in _ADAPTER_MAP:
        raise ValueError(f"unknown adapter: {name!r} (available: {', '.join(sorted(_ADAPTER_MAP))})")
    module_path, class_name = _ADAPTER_MAP[name]
    mod = importlib.import_module(module_path, "unified_channel")
    cls = getattr(mod, class_name)
    return cls(**config)


def load_config(path: str = "unified-channel.yaml") -> ChannelManager:
    """Load channels and middleware from a YAML config file.

    The config file supports ``${VAR}`` syntax for environment variable
    interpolation. Returns a fully configured :class:`ChannelManager`.

    Requires PyYAML (``pip install pyyaml``).
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("PyYAML is required for config loading: pip install pyyaml") from exc

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    if not raw:
        raise ValueError(f"empty or invalid config file: {path}")

    manager = ChannelManager()

    # --- channels ---
    channels_cfg = raw.get("channels", {})
    for name, adapter_cfg in channels_cfg.items():
        resolved = _interpolate_dict(adapter_cfg or {})
        adapter = _make_adapter(name, resolved)
        manager.add_channel(adapter)

    # --- middleware ---
    mw_cfg = raw.get("middleware", {})

    if "access" in mw_cfg:
        access_cfg = mw_cfg["access"]
        allowed = access_cfg.get("allowed_users")
        if allowed:
            allowed = [_interpolate_env(u) for u in allowed]
            manager.add_middleware(AccessMiddleware(allowed_user_ids=set(allowed)))

    # --- settings ---
    settings = raw.get("settings", {})
    prefix = settings.get("command_prefix", "/")
    # Store prefix in manager metadata for ServiceBridge to pick up
    if not hasattr(manager, "metadata"):
        manager.metadata = {}  # type: ignore[attr-defined]
    manager.metadata["command_prefix"] = prefix  # type: ignore[attr-defined]

    return manager
