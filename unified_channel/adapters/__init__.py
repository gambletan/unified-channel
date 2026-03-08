_ADAPTERS = {
    "TelegramAdapter": ".telegram",
    "DiscordAdapter": ".discord",
    "SlackAdapter": ".slack",
    "LineAdapter": ".line",
    "MatrixAdapter": ".matrix",
    "MSTeamsAdapter": ".msteams",
    "FeishuAdapter": ".feishu",
    "WhatsAppAdapter": ".whatsapp",
    "IMessageAdapter": ".imessage",
    "MattermostAdapter": ".mattermost",
    "GoogleChatAdapter": ".googlechat",
    "NextcloudTalkAdapter": ".nextcloud_talk",
    "SynologyChatAdapter": ".synology_chat",
    "ZaloAdapter": ".zalo",
    "NostrAdapter": ".nostr",
    "BlueBubblesAdapter": ".bluebubbles",
    "TwitchAdapter": ".twitch",
    "IRCAdapter": ".irc",
}

def __getattr__(name):
    if name in _ADAPTERS:
        import importlib
        module = importlib.import_module(_ADAPTERS[name], __package__)
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = list(_ADAPTERS.keys())
