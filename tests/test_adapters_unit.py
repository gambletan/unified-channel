"""Unit tests for individual adapters — mocked external dependencies."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from types import ModuleType
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_channel.types import (
    ChannelStatus,
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)


# ── iMessage adapter tests (no external deps, macOS only) ─────────────────

@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
class TestIMessageAdapter:
    def test_channel_id(self):
        from unified_channel.adapters.imessage import IMessageAdapter
        adapter = IMessageAdapter()
        assert adapter.channel_id == "imessage"

    @pytest.mark.asyncio
    async def test_get_status_disconnected(self):
        from unified_channel.adapters.imessage import IMessageAdapter
        adapter = IMessageAdapter()
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "imessage"


# ── IRC adapter tests (no external deps) ──────────────────────────────────

class TestIRCAdapter:
    def test_channel_id(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", nickname="testbot")
        assert adapter.channel_id == "irc"

    @pytest.mark.asyncio
    async def test_get_status_disconnected(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com")
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "irc"
        assert "irc.test.com" in status.account_id

    @pytest.mark.asyncio
    async def test_process_privmsg(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", command_prefix="!")
        adapter._connected = True

        await adapter._process_line(":bob!bob@host PRIVMSG #test :hello world")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.TEXT
        assert msg.content.text == "hello world"
        assert msg.sender.id == "bob"
        assert msg.chat_id == "#test"

    @pytest.mark.asyncio
    async def test_process_command(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", command_prefix="!")
        adapter._connected = True

        await adapter._process_line(":alice!a@h PRIVMSG #chan :!status arg1")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "status"
        assert msg.content.args == ["arg1"]

    @pytest.mark.asyncio
    async def test_ignores_own_messages(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", nickname="mybot")
        adapter._connected = True

        await adapter._process_line(":mybot!m@h PRIVMSG #test :self message")
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_dm_chat_id(self):
        """DM target is bot's nick — chat_id should be sender."""
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", nickname="mybot")
        adapter._connected = True

        await adapter._process_line(":alice!a@h PRIVMSG mybot :hello dm")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.chat_id == "alice"  # reply to sender, not to ourselves


# ── Telegram adapter tests (mode config) ──────────────────────────────────

class TestTelegramAdapter:
    @pytest.fixture
    def _mock_telegram(self):
        """Mock telegram modules so we can import the adapter without a real install path."""
        mock_update = MagicMock()
        mock_ext = MagicMock()
        with patch.dict(sys.modules, {
            "telegram": MagicMock(Update=mock_update),
            "telegram.ext": mock_ext,
        }):
            yield

    def test_defaults_to_polling(self):
        from unified_channel.adapters.telegram import TelegramAdapter
        adapter = TelegramAdapter(token="123:ABC")
        assert adapter.mode == "polling"
        assert adapter.channel_id == "telegram"

    def test_webhook_mode(self):
        from unified_channel.adapters.telegram import TelegramAdapter
        adapter = TelegramAdapter(
            token="123:ABC",
            mode="webhook",
            webhook_url="https://example.com",
            port=9000,
            url_path="/hook",
        )
        assert adapter.mode == "webhook"
        assert adapter._webhook_url == "https://example.com"
        assert adapter._port == 9000
        assert adapter._url_path == "/hook"

    def test_webhook_defaults(self):
        from unified_channel.adapters.telegram import TelegramAdapter
        adapter = TelegramAdapter(token="123:ABC", mode="webhook", webhook_url="https://example.com")
        assert adapter._port == 8443
        assert adapter._url_path == "/telegram-webhook"
        assert adapter._listen == "0.0.0.0"

    @pytest.mark.asyncio
    async def test_get_status_disconnected(self):
        from unified_channel.adapters.telegram import TelegramAdapter
        adapter = TelegramAdapter(token="123:ABC")
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "telegram"

    def test_backward_compatible_parse_mode(self):
        from unified_channel.adapters.telegram import TelegramAdapter
        adapter = TelegramAdapter(token="123:ABC", parse_mode="HTML")
        assert adapter._parse_mode == "HTML"
        assert adapter.mode == "polling"


# ── Adapter lazy import tests ─────────────────────────────────────────────

class TestLazyImports:
    """Verify that adapters are importable via lazy __getattr__."""

    def test_irc_import(self):
        from unified_channel import IRCAdapter
        assert IRCAdapter.channel_id == "irc"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_imessage_import(self):
        from unified_channel import IMessageAdapter
        assert IMessageAdapter.channel_id == "imessage"

    def test_unknown_import_raises(self):
        with pytest.raises(ImportError):
            from unified_channel import NonExistentAdapter  # noqa: F401

    def test_all_adapter_names_in_all(self):
        import unified_channel
        expected = [
            "TelegramAdapter", "DiscordAdapter", "SlackAdapter",
            "LineAdapter", "MatrixAdapter", "MSTeamsAdapter",
            "FeishuAdapter", "WhatsAppAdapter", "IMessageAdapter",
            "MattermostAdapter", "GoogleChatAdapter", "NextcloudTalkAdapter",
            "SynologyChatAdapter", "ZaloAdapter", "NostrAdapter",
            "BlueBubblesAdapter", "TwitchAdapter", "IRCAdapter",
        ]
        for name in expected:
            assert name in unified_channel.__all__


# ── WhatsApp message parsing (no SDK needed) ──────────────────────────────

class TestWhatsAppParsing:
    """Test WhatsApp webhook message parsing without running server."""

    @pytest.fixture
    def adapter(self):
        # Mock httpx so import works
        mock_httpx = MagicMock()
        with patch.dict(sys.modules, {"httpx": mock_httpx, "aiohttp": MagicMock(), "aiohttp.web": MagicMock()}):
            from unified_channel.adapters.whatsapp import WhatsAppAdapter
            return WhatsAppAdapter(
                access_token="test",
                phone_number_id="123",
                verify_token="verify",
            )

    @pytest.mark.asyncio
    async def test_process_text_message(self, adapter):
        wa_msg = {
            "id": "wamid.123",
            "from": "+1234567890",
            "type": "text",
            "timestamp": "1700000000",
            "text": {"body": "hello"},
        }
        await adapter._process_message(wa_msg, {"+1234567890": "John"})
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.TEXT
        assert msg.content.text == "hello"
        assert msg.sender.id == "+1234567890"
        assert msg.sender.display_name == "John"

    @pytest.mark.asyncio
    async def test_process_command(self, adapter):
        wa_msg = {
            "id": "wamid.456",
            "from": "+1234567890",
            "type": "text",
            "timestamp": "1700000000",
            "text": {"body": "/status"},
        }
        await adapter._process_message(wa_msg, {})
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "status"

    @pytest.mark.asyncio
    async def test_process_image(self, adapter):
        wa_msg = {
            "id": "wamid.789",
            "from": "+1234567890",
            "type": "image",
            "timestamp": "1700000000",
            "image": {"id": "media123", "caption": "look at this"},
        }
        await adapter._process_message(wa_msg, {})
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "image"
        assert msg.content.text == "look at this"

    @pytest.mark.asyncio
    async def test_process_reaction(self, adapter):
        wa_msg = {
            "id": "wamid.r1",
            "from": "+1234567890",
            "type": "reaction",
            "timestamp": "1700000000",
            "reaction": {"emoji": "👍"},
        }
        await adapter._process_message(wa_msg, {})
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.REACTION
        assert msg.content.text == "👍"

    @pytest.mark.asyncio
    async def test_process_reply_context(self, adapter):
        wa_msg = {
            "id": "wamid.reply1",
            "from": "+1234567890",
            "type": "text",
            "timestamp": "1700000000",
            "text": {"body": "reply text"},
            "context": {"id": "wamid.original"},
        }
        await adapter._process_message(wa_msg, {})
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.reply_to_id == "wamid.original"


# ── Mattermost post parsing ──────────────────────────────────────────────

class TestMattermostParsing:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock(), "websockets": MagicMock()}):
            from unified_channel.adapters.mattermost import MattermostAdapter
            a = MattermostAdapter(url="https://mm.test", token="tok")
            a._bot_user_id = "bot123"
            a._connected = True
            return a

    @pytest.mark.asyncio
    async def test_process_text(self, adapter):
        event = {
            "event": "posted",
            "data": {
                "post": json.dumps({
                    "id": "post1", "user_id": "user1",
                    "channel_id": "ch1", "message": "hello",
                }),
            },
        }
        await adapter._process_post(event)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.text == "hello"
        assert msg.sender.id == "user1"

    @pytest.mark.asyncio
    async def test_process_command(self, adapter):
        event = {
            "event": "posted",
            "data": {
                "post": json.dumps({
                    "id": "post2", "user_id": "user1",
                    "channel_id": "ch1", "message": "/deploy staging",
                }),
            },
        }
        await adapter._process_post(event)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "deploy"
        assert msg.content.args == ["staging"]

    @pytest.mark.asyncio
    async def test_ignores_own_posts(self, adapter):
        event = {
            "event": "posted",
            "data": {
                "post": json.dumps({
                    "id": "post3", "user_id": "bot123",
                    "channel_id": "ch1", "message": "echo",
                }),
            },
        }
        await adapter._process_post(event)
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_thread_id(self, adapter):
        event = {
            "event": "posted",
            "data": {
                "post": json.dumps({
                    "id": "post4", "user_id": "user1",
                    "channel_id": "ch1", "message": "threaded",
                    "root_id": "root1",
                }),
            },
        }
        await adapter._process_post(event)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.thread_id == "root1"


# ── Zalo message parsing ─────────────────────────────────────────────────

class TestZaloParsing:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock(), "aiohttp": MagicMock(), "aiohttp.web": MagicMock()}):
            from unified_channel.adapters.zalo import ZaloAdapter
            return ZaloAdapter(access_token="tok")

    @pytest.mark.asyncio
    async def test_process_text(self, adapter):
        body = {
            "sender": {"id": "zalo_user1"},
            "message": {"msg_id": "m1", "text": "xin chao"},
        }
        await adapter._process_text(body)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.text == "xin chao"
        assert msg.sender.id == "zalo_user1"

    @pytest.mark.asyncio
    async def test_process_command(self, adapter):
        body = {
            "sender": {"id": "u1"},
            "message": {"msg_id": "m2", "text": "/status"},
        }
        await adapter._process_text(body)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "status"


# ── BlueBubbles message parsing ──────────────────────────────────────────

class TestBlueBubblesParsing:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock()}):
            from unified_channel.adapters.bluebubbles import BlueBubblesAdapter
            a = BlueBubblesAdapter(server_url="http://localhost:1234", password="pw")
            a._connected = True
            a._http = MagicMock()
            return a

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "bluebubbles"

    @pytest.mark.asyncio
    async def test_status(self, adapter):
        status = await adapter.get_status()
        assert status.connected is True
        assert status.channel == "bluebubbles"


# ── Twitch message parsing ───────────────────────────────────────────────

class TestTwitchParsing:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"websockets": MagicMock()}):
            from unified_channel.adapters.twitch import TwitchAdapter
            a = TwitchAdapter(
                oauth_token="oauth:test", bot_username="testbot",
                channels=["#testchan"], command_prefix="!",
            )
            a._connected = True
            return a

    @pytest.mark.asyncio
    async def test_process_text(self, adapter):
        line = ":alice!alice@alice.tmi.twitch.tv PRIVMSG #testchan :hello chat"
        await adapter._process_line(line)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.text == "hello chat"
        assert msg.sender.username == "alice"
        assert msg.chat_id == "testchan"

    @pytest.mark.asyncio
    async def test_process_command(self, adapter):
        line = ":bob!bob@bob.tmi.twitch.tv PRIVMSG #testchan :!roll 6"
        await adapter._process_line(line)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "roll"
        assert msg.content.args == ["6"]

    @pytest.mark.asyncio
    async def test_ignores_self(self, adapter):
        line = ":testbot!testbot@testbot.tmi.twitch.tv PRIVMSG #testchan :echo"
        await adapter._process_line(line)
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_tags_parsing(self, adapter):
        line = "@user-id=12345;display-name=Alice :alice!alice@alice.tmi.twitch.tv PRIVMSG #testchan :hi"
        await adapter._process_line(line)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.sender.id == "12345"
        assert msg.sender.display_name == "Alice"


# ── Synology Chat parsing ────────────────────────────────────────────────

class TestSynologyChatParsing:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock(), "aiohttp": MagicMock(), "aiohttp.web": MagicMock()}):
            from unified_channel.adapters.synology_chat import SynologyChatAdapter
            return SynologyChatAdapter(incoming_webhook_url="https://nas/hook")

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "synology-chat"

    @pytest.mark.asyncio
    async def test_status(self, adapter):
        status = await adapter.get_status()
        assert status.connected is False


# ── Nextcloud Talk ────────────────────────────────────────────────────────

class TestNextcloudTalkAdapter:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock()}):
            from unified_channel.adapters.nextcloud_talk import NextcloudTalkAdapter
            return NextcloudTalkAdapter(
                server_url="https://nc.test",
                username="bot", password="pass",
            )

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "nextcloud-talk"

    @pytest.mark.asyncio
    async def test_status(self, adapter):
        status = await adapter.get_status()
        assert status.connected is False
        assert status.account_id == "bot"


# ── IRC adapter edge cases ─────────────────────────────────────────────────

class TestIRCAdapterEdgeCases:
    def test_custom_channel_list(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", nickname="bot", channels=["#a", "#b"])
        assert adapter.channel_id == "irc"

    def test_default_nickname(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com")
        assert adapter._nickname is not None

    @pytest.mark.asyncio
    async def test_process_empty_message(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", nickname="bot")
        adapter._connected = True
        # Non-PRIVMSG lines should be silently ignored
        await adapter._process_line(":server 001 bot :Welcome")
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_command_with_multiple_args(self):
        from unified_channel.adapters.irc import IRCAdapter
        adapter = IRCAdapter(server="irc.test.com", command_prefix="!")
        adapter._connected = True

        await adapter._process_line(":alice!a@h PRIVMSG #chan :!deploy prod --force --verbose")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "deploy"
        assert "prod" in msg.content.args


# ── WhatsApp adapter edge cases ─────────────────────────────────────────────

class TestWhatsAppEdgeCases:
    @pytest.fixture
    def adapter(self):
        mock_httpx = MagicMock()
        with patch.dict(sys.modules, {"httpx": mock_httpx, "aiohttp": MagicMock(), "aiohttp.web": MagicMock()}):
            from unified_channel.adapters.whatsapp import WhatsAppAdapter
            return WhatsAppAdapter(
                access_token="test",
                phone_number_id="123",
                verify_token="verify",
            )

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "whatsapp"

    @pytest.mark.asyncio
    async def test_status_disconnected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "whatsapp"

    @pytest.mark.asyncio
    async def test_process_command_with_args(self, adapter):
        wa_msg = {
            "id": "wamid.cmd",
            "from": "+1234567890",
            "type": "text",
            "timestamp": "1700000000",
            "text": {"body": "/deploy staging --force"},
        }
        await adapter._process_message(wa_msg, {})
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "deploy"
        assert "staging" in msg.content.args


# ── Mattermost adapter edge cases ──────────────────────────────────────────

class TestMattermostEdgeCases:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock(), "websockets": MagicMock()}):
            from unified_channel.adapters.mattermost import MattermostAdapter
            a = MattermostAdapter(url="https://mm.test", token="tok")
            a._bot_user_id = "bot123"
            a._connected = True
            return a

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "mattermost"

    @pytest.mark.asyncio
    async def test_status_connected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is True
        assert status.channel == "mattermost"

    @pytest.mark.asyncio
    async def test_empty_post_data_produces_empty_message(self, adapter):
        """Event with no post data still produces a message (adapter doesn't filter events)."""
        event = {"event": "posted", "data": {}}
        await adapter._process_post(event)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.channel == "mattermost"
        assert msg.content.text == ""


# ── Twitch adapter edge cases ──────────────────────────────────────────────

class TestTwitchEdgeCases:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"websockets": MagicMock()}):
            from unified_channel.adapters.twitch import TwitchAdapter
            a = TwitchAdapter(
                oauth_token="oauth:test", bot_username="testbot",
                channels=["#testchan"], command_prefix="!",
            )
            a._connected = True
            return a

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "twitch"

    @pytest.mark.asyncio
    async def test_status_connected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is True
        assert status.channel == "twitch"

    @pytest.mark.asyncio
    async def test_process_multiword_message(self, adapter):
        line = ":user1!user1@user1.tmi.twitch.tv PRIVMSG #testchan :this is a long message with many words"
        await adapter._process_line(line)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.text == "this is a long message with many words"
        assert msg.content.type == ContentType.TEXT

    @pytest.mark.asyncio
    async def test_non_privmsg_ignored(self, adapter):
        line = ":tmi.twitch.tv 001 testbot :Welcome, GLHF!"
        await adapter._process_line(line)
        assert adapter._queue.empty()


# ── Zalo adapter edge cases ────────────────────────────────────────────────

class TestZaloEdgeCases:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock(), "aiohttp": MagicMock(), "aiohttp.web": MagicMock()}):
            from unified_channel.adapters.zalo import ZaloAdapter
            return ZaloAdapter(access_token="tok")

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "zalo"

    @pytest.mark.asyncio
    async def test_status_disconnected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "zalo"


# ── BlueBubbles adapter edge cases ─────────────────────────────────────────

class TestBlueBubblesEdgeCases:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock()}):
            from unified_channel.adapters.bluebubbles import BlueBubblesAdapter
            return BlueBubblesAdapter(server_url="http://localhost:1234", password="pw")

    def test_channel_id_default(self, adapter):
        assert adapter.channel_id == "bluebubbles"

    @pytest.mark.asyncio
    async def test_status_disconnected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "bluebubbles"


# ── Synology Chat edge cases ──────────────────────────────────────────────

class TestSynologyChatEdgeCases:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock(), "aiohttp": MagicMock(), "aiohttp.web": MagicMock()}):
            from unified_channel.adapters.synology_chat import SynologyChatAdapter
            return SynologyChatAdapter(incoming_webhook_url="https://nas/hook")

    @pytest.mark.asyncio
    async def test_status_has_correct_channel(self, adapter):
        status = await adapter.get_status()
        assert status.channel == "synology-chat"
        assert status.connected is False


# ── Nextcloud Talk edge cases ──────────────────────────────────────────────

class TestNextcloudTalkEdgeCases:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": MagicMock()}):
            from unified_channel.adapters.nextcloud_talk import NextcloudTalkAdapter
            return NextcloudTalkAdapter(
                server_url="https://nc.test",
                username="admin", password="secret",
            )

    def test_custom_username_in_status(self, adapter):
        # account_id should reflect the username
        assert adapter._username == "admin"

    @pytest.mark.asyncio
    async def test_status_account_id(self, adapter):
        status = await adapter.get_status()
        assert status.account_id == "admin"


# ── iMessage adapter edge cases ───────────────────────────────────────────

@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
class TestIMessageEdgeCases:
    def test_default_construction(self):
        from unified_channel.adapters.imessage import IMessageAdapter
        adapter = IMessageAdapter()
        assert adapter.channel_id == "imessage"

    @pytest.mark.asyncio
    async def test_status_channel_field(self):
        from unified_channel.adapters.imessage import IMessageAdapter
        adapter = IMessageAdapter()
        status = await adapter.get_status()
        assert status.channel == "imessage"


# ── WeChat (企业微信) adapter tests ──────────────────────────────────────

class TestWeChatAdapter:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {
            "aiohttp": MagicMock(), "aiohttp.web": MagicMock(),
            "requests": MagicMock(),
            "Crypto": MagicMock(), "Crypto.Cipher": MagicMock(), "Crypto.Cipher.AES": MagicMock(),
        }):
            from unified_channel.adapters.wechat import WeChatAdapter
            return WeChatAdapter(
                corp_id="ww1234567890",
                corp_secret="secret123",
                agent_id="1000001",
                token="callback_token",
                encoding_aes_key="a" * 43,
            )

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "wechat"

    @pytest.mark.asyncio
    async def test_get_status_disconnected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is False
        assert status.channel == "wechat"
        assert "ww1234567890" in status.account_id
        assert "1000001" in status.account_id

    @pytest.mark.asyncio
    async def test_process_text_message(self, adapter):
        xml = """<xml>
            <MsgType>text</MsgType>
            <FromUserName>user001</FromUserName>
            <ToUserName>bot001</ToUserName>
            <MsgId>msg123</MsgId>
            <CreateTime>1700000000</CreateTime>
            <AgentID>1000001</AgentID>
            <Content>hello world</Content>
        </xml>"""
        await adapter._process_message(xml)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.TEXT
        assert msg.content.text == "hello world"
        assert msg.sender.id == "user001"
        assert msg.channel == "wechat"

    @pytest.mark.asyncio
    async def test_process_command(self, adapter):
        xml = """<xml>
            <MsgType>text</MsgType>
            <FromUserName>user001</FromUserName>
            <ToUserName>bot001</ToUserName>
            <MsgId>msg456</MsgId>
            <CreateTime>1700000000</CreateTime>
            <AgentID>1000001</AgentID>
            <Content>/status workers</Content>
        </xml>"""
        await adapter._process_message(xml)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "status"
        assert msg.content.args == ["workers"]

    @pytest.mark.asyncio
    async def test_process_image(self, adapter):
        xml = """<xml>
            <MsgType>image</MsgType>
            <FromUserName>user001</FromUserName>
            <ToUserName>bot001</ToUserName>
            <MsgId>msg789</MsgId>
            <CreateTime>1700000000</CreateTime>
            <AgentID>1000001</AgentID>
            <PicUrl>https://example.com/pic.jpg</PicUrl>
        </xml>"""
        await adapter._process_message(xml)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "image"
        assert msg.content.media_url == "https://example.com/pic.jpg"

    @pytest.mark.asyncio
    async def test_event_messages_skipped(self, adapter):
        xml = """<xml>
            <MsgType>event</MsgType>
            <FromUserName>user001</FromUserName>
            <ToUserName>bot001</ToUserName>
            <CreateTime>1700000000</CreateTime>
            <Event>subscribe</Event>
        </xml>"""
        await adapter._process_message(xml)
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_chat_id_is_sender(self, adapter):
        xml = """<xml>
            <MsgType>text</MsgType>
            <FromUserName>user002</FromUserName>
            <ToUserName>bot001</ToUserName>
            <MsgId>msg999</MsgId>
            <CreateTime>1700000000</CreateTime>
            <Content>hi</Content>
        </xml>"""
        await adapter._process_message(xml)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.chat_id == "user002"


class TestWeChatCrypto:
    def test_pkcs7_pad_unpad(self):
        from unified_channel.adapters.wechat import _pkcs7_pad, _pkcs7_unpad
        data = b"hello"
        padded = _pkcs7_pad(data)
        assert len(padded) % 32 == 0
        assert _pkcs7_unpad(padded) == data

    def test_pkcs7_pad_exact_block(self):
        from unified_channel.adapters.wechat import _pkcs7_pad, _pkcs7_unpad
        data = b"x" * 32
        padded = _pkcs7_pad(data)
        assert len(padded) == 64  # full extra block
        assert _pkcs7_unpad(padded) == data

    def test_verify_signature(self):
        from unified_channel.adapters.wechat import WeChatCrypto
        crypto = WeChatCrypto(token="test_token", encoding_aes_key="a" * 43, corp_id="corp1")
        # Manually compute expected signature
        import hashlib
        items = sorted(["test_token", "12345", "nonce1", "encrypted_str"])
        expected = hashlib.sha1("".join(items).encode()).hexdigest()
        assert crypto.verify_signature(expected, "12345", "nonce1", "encrypted_str")
        assert not crypto.verify_signature("wrong", "12345", "nonce1", "encrypted_str")


# ── DingTalk (钉钉) adapter tests ───────────────────────────────────────

class TestDingTalkAdapter:
    @pytest.fixture
    def webhook_adapter(self):
        with patch.dict(sys.modules, {
            "aiohttp": MagicMock(), "aiohttp.web": MagicMock(),
            "requests": MagicMock(),
        }):
            from unified_channel.adapters.dingtalk import DingTalkAdapter
            return DingTalkAdapter(
                webhook_url="https://oapi.dingtalk.com/robot/send?access_token=test123",
                secret="SEC_test_secret",
            )

    @pytest.fixture
    def enterprise_adapter(self):
        with patch.dict(sys.modules, {
            "aiohttp": MagicMock(), "aiohttp.web": MagicMock(),
            "requests": MagicMock(),
        }):
            from unified_channel.adapters.dingtalk import DingTalkAdapter
            return DingTalkAdapter(
                app_key="dingtest123",
                app_secret="secret456",
            )

    def test_channel_id(self, webhook_adapter):
        assert webhook_adapter.channel_id == "dingtalk"

    @pytest.mark.asyncio
    async def test_get_status_disconnected(self, webhook_adapter):
        status = await webhook_adapter.get_status()
        assert status.connected is False
        assert status.channel == "dingtalk"

    @pytest.mark.asyncio
    async def test_enterprise_status(self, enterprise_adapter):
        status = await enterprise_adapter.get_status()
        assert status.account_id == "dingtest123"

    def test_sign_webhook(self, webhook_adapter):
        sig = webhook_adapter._sign_webhook("1700000000000")
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_verify_callback_no_secret(self):
        with patch.dict(sys.modules, {
            "aiohttp": MagicMock(), "aiohttp.web": MagicMock(),
            "requests": MagicMock(),
        }):
            from unified_channel.adapters.dingtalk import DingTalkAdapter
            adapter = DingTalkAdapter(webhook_url="https://test.com")
            # Without app_secret, verification always passes
            assert adapter._verify_callback_signature("ts", "any") is True

    @pytest.mark.asyncio
    async def test_process_text_message(self, enterprise_adapter):
        body = {
            "msgtype": "text",
            "text": {"content": "hello dingtalk"},
            "senderStaffId": "staff001",
            "senderNick": "Alice",
            "conversationId": "conv123",
            "msgId": "msg001",
            "conversationType": "2",
            "createAt": 1700000000000,
        }
        await enterprise_adapter._process_message(body)
        msg = await asyncio.wait_for(enterprise_adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.TEXT
        assert msg.content.text == "hello dingtalk"
        assert msg.sender.id == "staff001"
        assert msg.sender.display_name == "Alice"
        assert msg.chat_id == "conv123"

    @pytest.mark.asyncio
    async def test_process_command(self, enterprise_adapter):
        body = {
            "msgtype": "text",
            "text": {"content": "/deploy staging"},
            "senderStaffId": "staff001",
            "senderNick": "Bob",
            "conversationId": "conv456",
            "msgId": "msg002",
            "conversationType": "2",
            "createAt": 1700000000000,
        }
        await enterprise_adapter._process_message(body)
        msg = await asyncio.wait_for(enterprise_adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "deploy"
        assert msg.content.args == ["staging"]

    @pytest.mark.asyncio
    async def test_process_picture(self, enterprise_adapter):
        body = {
            "msgtype": "picture",
            "content": {"downloadCode": "dl_123"},
            "senderStaffId": "staff001",
            "conversationId": "conv789",
            "msgId": "msg003",
            "conversationType": "2",
            "createAt": 1700000000000,
        }
        await enterprise_adapter._process_message(body)
        msg = await asyncio.wait_for(enterprise_adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "image"
        assert msg.content.media_url == "dl_123"

    @pytest.mark.asyncio
    async def test_1v1_chat_uses_sender_as_chat_id(self, enterprise_adapter):
        body = {
            "msgtype": "text",
            "text": {"content": "hi"},
            "senderStaffId": "staff001",
            "conversationId": "conv001",
            "msgId": "msg004",
            "conversationType": "1",
            "createAt": 1700000000000,
        }
        await enterprise_adapter._process_message(body)
        msg = await asyncio.wait_for(enterprise_adapter._queue.get(), timeout=1)
        assert msg.chat_id == "staff001"

    @pytest.mark.asyncio
    async def test_process_rich_text(self, enterprise_adapter):
        body = {
            "msgtype": "richText",
            "content": {"richText": [{"text": "part1"}, {"text": "part2"}]},
            "senderStaffId": "staff001",
            "conversationId": "conv002",
            "msgId": "msg005",
            "conversationType": "2",
            "createAt": 1700000000000,
        }
        await enterprise_adapter._process_message(body)
        msg = await asyncio.wait_for(enterprise_adapter._queue.get(), timeout=1)
        assert msg.content.text == "part1part2"


# ── QQ Bot (QQ 官方机器人) adapter tests ────────────────────────────────

class TestQQAdapter:
    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"aiohttp": MagicMock()}):
            from unified_channel.adapters.qq import QQAdapter
            a = QQAdapter(app_id="app123", token="token456", secret="secret789")
            a._bot_id = "bot001"
            a._bot_username = "TestBot"
            a._connected = True
            return a

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "qq"

    @pytest.mark.asyncio
    async def test_get_status_disconnected(self):
        with patch.dict(sys.modules, {"aiohttp": MagicMock()}):
            from unified_channel.adapters.qq import QQAdapter
            a = QQAdapter(app_id="app123", token="token456")
            status = await a.get_status()
            assert status.connected is False
            assert status.channel == "qq"
            assert status.account_id == "app123"

    @pytest.mark.asyncio
    async def test_get_status_connected(self, adapter):
        status = await adapter.get_status()
        assert status.connected is True
        assert status.account_id == "TestBot"

    @pytest.mark.asyncio
    async def test_process_guild_message(self, adapter):
        data = {
            "id": "msg001",
            "content": "hello qq",
            "author": {"id": "user001", "username": "Alice", "bot": False},
            "channel_id": "chan001",
            "guild_id": "guild001",
            "timestamp": "2024-01-01T00:00:00+00:00",
        }
        await adapter._process_guild_message(data, "MESSAGE_CREATE")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.TEXT
        assert msg.content.text == "hello qq"
        assert msg.sender.id == "user001"
        assert msg.sender.username == "Alice"
        assert msg.chat_id == "chan001"

    @pytest.mark.asyncio
    async def test_process_guild_command(self, adapter):
        data = {
            "id": "msg002",
            "content": "/status workers",
            "author": {"id": "user001", "username": "Alice"},
            "channel_id": "chan001",
            "guild_id": "guild001",
        }
        await adapter._process_guild_message(data, "MESSAGE_CREATE")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "status"
        assert msg.content.args == ["workers"]

    @pytest.mark.asyncio
    async def test_process_at_message_strips_mention(self, adapter):
        data = {
            "id": "msg003",
            "content": f"<@!bot001> hello bot",
            "author": {"id": "user001", "username": "Alice"},
            "channel_id": "chan001",
            "guild_id": "guild001",
        }
        await adapter._process_guild_message(data, "AT_MESSAGE_CREATE")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.text == "hello bot"

    @pytest.mark.asyncio
    async def test_process_dm(self, adapter):
        data = {
            "id": "msg004",
            "content": "private hello",
            "author": {"id": "user001", "username": "Alice"},
            "channel_id": "chan002",
            "guild_id": "guild002",
        }
        await adapter._process_guild_message(data, "DIRECT_MESSAGE_CREATE")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.chat_id == "dm:guild002"

    @pytest.mark.asyncio
    async def test_process_group_message(self, adapter):
        data = {
            "id": "msg005",
            "content": "group hello",
            "author": {"member_openid": "member001"},
            "group_openid": "group001",
        }
        await adapter._process_group_message(data)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.sender.id == "member001"
        assert msg.chat_id == "group:group001"

    @pytest.mark.asyncio
    async def test_process_c2c_message(self, adapter):
        data = {
            "id": "msg006",
            "content": "c2c hello",
            "author": {"user_openid": "openid001"},
        }
        await adapter._process_c2c_message(data)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.sender.id == "openid001"
        assert msg.chat_id == "openid001"

    @pytest.mark.asyncio
    async def test_ignores_own_guild_messages(self, adapter):
        data = {
            "id": "msg007",
            "content": "echo",
            "author": {"id": "bot001", "username": "TestBot", "bot": True},
            "channel_id": "chan001",
            "guild_id": "guild001",
        }
        await adapter._process_guild_message(data, "MESSAGE_CREATE")
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_process_attachment(self, adapter):
        data = {
            "id": "msg008",
            "content": "look at this",
            "author": {"id": "user001", "username": "Alice"},
            "channel_id": "chan001",
            "guild_id": "guild001",
            "attachments": [{"content_type": "image/png", "url": "https://example.com/img.png"}],
        }
        await adapter._process_guild_message(data, "MESSAGE_CREATE")
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "image/png"
        assert msg.content.media_url == "https://example.com/img.png"

    def test_parse_content_text(self, adapter):
        mc = adapter._parse_content("hello", {})
        assert mc.type == ContentType.TEXT
        assert mc.text == "hello"

    def test_parse_content_command(self, adapter):
        mc = adapter._parse_content("/deploy prod", {})
        assert mc.type == ContentType.COMMAND
        assert mc.command == "deploy"
        assert mc.args == ["prod"]

    @pytest.mark.asyncio
    async def test_dispatch_heartbeat_ack(self, adapter):
        # Heartbeat ACK should not produce any messages
        await adapter._dispatch({"op": 11, "s": None, "t": None, "d": {}})
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_dispatch_message_create(self, adapter):
        payload = {
            "op": 0,
            "s": 5,
            "t": "MESSAGE_CREATE",
            "d": {
                "id": "msg010",
                "content": "dispatch test",
                "author": {"id": "user001", "username": "Alice"},
                "channel_id": "chan001",
                "guild_id": "guild001",
            },
        }
        await adapter._dispatch(payload)
        msg = await asyncio.wait_for(adapter._queue.get(), timeout=1)
        assert msg.content.text == "dispatch test"
        assert adapter._sequence == 5

    def test_sandbox_api_base(self):
        with patch.dict(sys.modules, {"aiohttp": MagicMock()}):
            from unified_channel.adapters.qq import QQAdapter, QQ_SANDBOX_API_BASE
            a = QQAdapter(app_id="app1", token="tok1", sandbox=True)
            assert a._api_base == QQ_SANDBOX_API_BASE

    def test_default_intents(self, adapter):
        from unified_channel.adapters.qq import QQAdapter
        assert adapter._intents == QQAdapter.DEFAULT_INTENTS


# ── Lazy import tests for new adapters ─────────────────────────────────

class TestNewAdapterLazyImports:
    def test_wechat_in_adapters_all(self):
        from unified_channel.adapters import __all__
        assert "WeChatAdapter" in __all__

    def test_dingtalk_in_adapters_all(self):
        from unified_channel.adapters import __all__
        assert "DingTalkAdapter" in __all__

    def test_qq_in_adapters_all(self):
        from unified_channel.adapters import __all__
        assert "QQAdapter" in __all__

    def test_wechat_in_package_all(self):
        import unified_channel
        assert "WeChatAdapter" in unified_channel.__all__

    def test_dingtalk_in_package_all(self):
        import unified_channel
        assert "DingTalkAdapter" in unified_channel.__all__

    def test_qq_in_package_all(self):
        import unified_channel
        assert "QQAdapter" in unified_channel.__all__
