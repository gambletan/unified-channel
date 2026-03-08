from .types import UnifiedMessage, MessageContent, Identity, ChannelStatus, ContentType
from .adapter import ChannelAdapter
from .middleware import Middleware, CommandMiddleware, AccessMiddleware
from .manager import ChannelManager

_LAZY_ADAPTERS = {
    "TelegramAdapter": ".adapters.telegram",
    "DiscordAdapter": ".adapters.discord",
    "SlackAdapter": ".adapters.slack",
    "LineAdapter": ".adapters.line",
    "MatrixAdapter": ".adapters.matrix",
    "MSTeamsAdapter": ".adapters.msteams",
    "FeishuAdapter": ".adapters.feishu",
    "WhatsAppAdapter": ".adapters.whatsapp",
    "IMessageAdapter": ".adapters.imessage",
    "MattermostAdapter": ".adapters.mattermost",
    "GoogleChatAdapter": ".adapters.googlechat",
    "NextcloudTalkAdapter": ".adapters.nextcloud_talk",
    "SynologyChatAdapter": ".adapters.synology_chat",
    "ZaloAdapter": ".adapters.zalo",
    "NostrAdapter": ".adapters.nostr",
    "BlueBubblesAdapter": ".adapters.bluebubbles",
    "TwitchAdapter": ".adapters.twitch",
    "IRCAdapter": ".adapters.irc",
}

def __getattr__(name):
    if name in _LAZY_ADAPTERS:
        import importlib
        module = importlib.import_module(_LAZY_ADAPTERS[name], __package__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "UnifiedMessage", "MessageContent", "Identity", "ChannelStatus", "ContentType",
    "ChannelAdapter", "Middleware", "CommandMiddleware", "AccessMiddleware",
    "ChannelManager",
    *_LAZY_ADAPTERS.keys(),
]
