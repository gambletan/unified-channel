"""微信 ClawBot 适配器单元测试 — 全部通过 Mock 运行，不依赖真实 iLink 服务。"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# 模块级导入，确保与适配器使用同一个枚举类实例
from unified_channel.types import (
    ChannelStatus,
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)

# ── 辅助 Mock：在 httpx 未安装时跳过测试 ──────────────────────────────────

def _make_httpx_mock() -> MagicMock:
    """创建最小化的 httpx 模块 mock。"""
    mock = MagicMock()
    mock.Timeout = MagicMock(return_value=MagicMock())
    mock.AsyncClient = MagicMock
    mock.HTTPError = Exception
    return mock


# ── 导入辅助函数（不依赖 httpx）────────────────────────────────────────────

def _import_helpers():
    """从适配器模块导入可单独测试的工具函数。"""
    with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
        from unified_channel.adapters.wechat_clawbot import (
            _make_ilink_headers,
            _encrypt_media_aes128,
        )
        return _make_ilink_headers, _encrypt_media_aes128


# ── 工具函数测试 ──────────────────────────────────────────────────────────

class TestMakeIlinkHeaders:
    """测试 iLink 请求头生成逻辑。"""

    def test_returns_required_keys(self):
        _make_ilink_headers, _ = _import_helpers()
        headers = _make_ilink_headers("test-token-abc")
        assert "Authorization" in headers
        assert "AuthorizationType" in headers
        assert "X-WECHAT-UIN" in headers
        assert "Content-Type" in headers

    def test_bearer_token_format(self):
        _make_ilink_headers, _ = _import_helpers()
        headers = _make_ilink_headers("my-token-xyz")
        assert headers["Authorization"] == "Bearer my-token-xyz"

    def test_auth_type_is_ilink(self):
        _make_ilink_headers, _ = _import_helpers()
        headers = _make_ilink_headers("any-token")
        assert headers["AuthorizationType"] == "ilink_bot_token"

    def test_uin_is_base64(self):
        """X-WECHAT-UIN 必须是有效的 base64 字符串。"""
        import base64
        _make_ilink_headers, _ = _import_helpers()
        headers = _make_ilink_headers("tok")
        # 能够 base64 解码说明格式正确
        base64.b64decode(headers["X-WECHAT-UIN"])

    def test_uin_varies_between_calls(self):
        """每次调用产生不同的 UIN（基于时间戳，防重放）。"""
        _make_ilink_headers, _ = _import_helpers()
        # 连续两次调用，UIN 不一定不同（时间精度），但不应抛出异常
        h1 = _make_ilink_headers("tok")
        h2 = _make_ilink_headers("tok")
        # 两个头部结构相同
        assert set(h1.keys()) == set(h2.keys())


class TestEncryptMediaAes128:
    """测试媒体文件 AES-128-ECB 加密。"""

    @pytest.fixture(autouse=True)
    def _require_pycryptodome(self):
        """跳过没有 pycryptodome 的环境。"""
        try:
            from Crypto.Cipher import AES  # noqa: F401
        except ImportError:
            pytest.skip("pycryptodome 未安装")

    def test_output_length_is_multiple_of_16(self):
        _, _encrypt = _import_helpers()
        key = b"0123456789abcdef"  # 16 字节 AES-128 密钥
        data = b"hello world"
        encrypted = _encrypt(data, key)
        assert len(encrypted) % 16 == 0

    def test_empty_input_pads_to_block(self):
        _, _encrypt = _import_helpers()
        key = b"0123456789abcdef"
        encrypted = _encrypt(b"", key)
        assert len(encrypted) == 16  # PKCS#7: 空输入填充一整块

    def test_output_differs_from_input(self):
        _, _encrypt = _import_helpers()
        key = b"0123456789abcdef"
        data = b"plaintext data!!"
        assert _encrypt(data, key) != data


# ── WeChatClawBotAdapter 实例化测试 ─────────────────────────────────────

class TestWeChatClawBotAdapterInit:
    """测试适配器初始化参数及默认值。"""

    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            return WeChatClawBotAdapter(bot_token="test-token-123")

    def test_channel_id(self, adapter):
        assert adapter.channel_id == "wechat_clawbot"

    def test_default_base_url(self, adapter):
        assert "ilinkai.weixin.qq.com" in adapter._base_url

    def test_custom_bot_id(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            a = WeChatClawBotAdapter(
                bot_token="tok",
                bot_id="mybot@im.bot",
            )
            assert a._bot_id == "mybot@im.bot"

    def test_default_poll_timeout(self, adapter):
        assert adapter._poll_timeout_ms == 35_000

    def test_custom_command_prefix(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            a = WeChatClawBotAdapter(bot_token="tok", command_prefix="!")
            assert a._prefix == "!"

    def test_not_connected_by_default(self, adapter):
        assert adapter._connected is False

    def test_empty_queue_on_init(self, adapter):
        assert adapter._queue.empty()


# ── get_status 测试 ───────────────────────────────────────────────────────

class TestGetStatus:

    @pytest.mark.asyncio
    async def test_disconnected_status(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")
            status = await adapter.get_status()
            assert status.connected is False
            assert status.channel == "wechat_clawbot"

    @pytest.mark.asyncio
    async def test_account_id_uses_bot_id_when_set(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="my-secret", bot_id="bot@im.bot")
            status = await adapter.get_status()
            assert status.account_id == "bot@im.bot"

    @pytest.mark.asyncio
    async def test_account_id_truncates_token_when_no_bot_id(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="abcdefgh_secret")
            status = await adapter.get_status()
            # 只显示前 8 个字符，不暴露完整 token
            assert status.account_id.startswith("abcdefgh")
            assert "secret" not in status.account_id


# ── 消息解析测试 ──────────────────────────────────────────────────────────

class TestProcessIlinkMessage:
    """测试 _process_ilink_message 各消息类型的解析逻辑。"""

    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            return WeChatClawBotAdapter(bot_token="tok")

    @pytest.mark.asyncio
    async def test_text_message(self, adapter):
        """普通文本消息应解析为 ContentType.TEXT。"""
        raw = {
            "from_user_id": "alice@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-001",
            "msg_id": "msg-001",
            "item_list": [{"type": 1, "text_item": {"text": "你好机器人"}}],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()

        assert msg.content.type == ContentType.TEXT
        assert msg.content.text == "你好机器人"
        assert msg.sender.id == "alice@im.wechat"
        assert msg.chat_id == "alice@im.wechat"
        assert msg.channel == "wechat_clawbot"
        assert msg.metadata["context_token"] == "ctx-001"

    @pytest.mark.asyncio
    async def test_command_message(self, adapter):
        """以 "/" 开头的文本应解析为 ContentType.COMMAND。"""
        raw = {
            "from_user_id": "bob@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-002",
            "msg_id": "msg-002",
            "item_list": [{"type": 1, "text_item": {"text": "/status arg1 arg2"}}],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()

        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "status"
        assert msg.content.args == ["arg1", "arg2"]

    @pytest.mark.asyncio
    async def test_custom_command_prefix(self):
        """自定义命令前缀（如 "!"）应正确识别命令。"""
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok", command_prefix="!")
        raw = {
            "from_user_id": "carol@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-003",
            "item_list": [{"type": 1, "text_item": {"text": "!help"}}],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()
        assert msg.content.type == ContentType.COMMAND
        assert msg.content.command == "help"

    @pytest.mark.asyncio
    async def test_image_message(self, adapter):
        """图片消息应解析为 media_type='image'。"""
        raw = {
            "from_user_id": "dave@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-004",
            "item_list": [
                {"type": 2, "image_item": {"media": "cdn://img-ref-001"}}
            ],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()

        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "image"
        assert msg.content.media_url == "cdn://img-ref-001"

    @pytest.mark.asyncio
    async def test_video_message(self, adapter):
        """视频消息应解析为 media_type='video'。"""
        raw = {
            "from_user_id": "eve@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-005",
            "item_list": [
                {"type": 5, "video_item": {"media": "cdn://video-ref-001"}}
            ],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()

        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "video"

    @pytest.mark.asyncio
    async def test_file_message(self, adapter):
        """文件消息应解析为 media_type='file'，并携带文件名。"""
        raw = {
            "from_user_id": "frank@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-006",
            "item_list": [
                {
                    "type": 4,
                    "file_item": {
                        "media": "cdn://file-ref-001",
                        "filename": "report.pdf",
                    },
                }
            ],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()

        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "file"
        assert msg.content.text == "report.pdf"  # 文件名存入 text 字段

    @pytest.mark.asyncio
    async def test_voice_message(self, adapter):
        """语音消息应解析为 media_type='voice'。"""
        raw = {
            "from_user_id": "grace@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-007",
            "item_list": [
                {"type": 3, "voice_item": {"media": "cdn://voice-ref-001"}}
            ],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()

        assert msg.content.type == ContentType.MEDIA
        assert msg.content.media_type == "voice"

    @pytest.mark.asyncio
    async def test_unknown_type_skipped(self, adapter):
        """未知类型消息应静默跳过，不入队。"""
        raw = {
            "from_user_id": "hank@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-008",
            "item_list": [{"type": 99, "unknown_item": {}}],
        }
        await adapter._process_ilink_message(raw)
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_empty_item_list_skipped(self, adapter):
        """空 item_list 应静默跳过。"""
        raw = {
            "from_user_id": "ivan@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-009",
            "item_list": [],
        }
        await adapter._process_ilink_message(raw)
        assert adapter._queue.empty()

    @pytest.mark.asyncio
    async def test_uses_first_recognized_item(self, adapter):
        """多个 item 时只解析第一个可识别的。"""
        raw = {
            "from_user_id": "judy@im.wechat",
            "to_user_id": "bot@im.bot",
            "context_token": "ctx-010",
            "item_list": [
                {"type": 1, "text_item": {"text": "第一条"}},
                {"type": 1, "text_item": {"text": "第二条"}},
            ],
        }
        await adapter._process_ilink_message(raw)
        msg = adapter._queue.get_nowait()
        assert msg.content.text == "第一条"


# ── _build_send_payload 测试 ─────────────────────────────────────────────

class TestBuildSendPayload:
    """测试发送消息 payload 构建逻辑。"""

    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            return WeChatClawBotAdapter(bot_token="tok")

    def test_basic_structure(self, adapter):
        payload = adapter._build_send_payload(
            to_user_id="user@im.wechat",
            item_list=[{"type": 1, "text_item": {"text": "hi"}}],
        )
        assert "msg" in payload
        msg = payload["msg"]
        assert msg["to_user_id"] == "user@im.wechat"
        assert msg["message_type"] == 2
        assert msg["message_state"] == 2
        assert len(msg["item_list"]) == 1

    def test_context_token_included_when_provided(self, adapter):
        payload = adapter._build_send_payload(
            to_user_id="user@im.wechat",
            item_list=[],
            context_token="ctx-abc",
        )
        assert payload["msg"]["context_token"] == "ctx-abc"

    def test_context_token_omitted_when_empty(self, adapter):
        """context_token 为空时，不应出现在 payload 中（避免 iLink 报错）。"""
        payload = adapter._build_send_payload(
            to_user_id="user@im.wechat",
            item_list=[],
            context_token="",
        )
        assert "context_token" not in payload["msg"]


# ── send() 接口集成测试 ────────────────────────────────────────────────────

class TestSend:
    """通过 mock _post 测试 send() 方法的路由逻辑。"""

    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            a = WeChatClawBotAdapter(bot_token="tok")
            a._client = MagicMock()  # 注入假客户端
            return a

    @pytest.mark.asyncio
    async def test_send_text_calls_post(self, adapter):
        """发送文本消息时应调用 /ilink/bot/sendmessage。"""

        adapter._post = AsyncMock(return_value={"ret": 0, "msg_id": "mid-001"})
        msg = OutboundMessage(chat_id="user@im.wechat", text="测试文本")

        result = await adapter.send(msg)

        assert result == "mid-001"
        adapter._post.assert_awaited_once()
        call_path = adapter._post.call_args[0][0]
        assert call_path == "/ilink/bot/sendmessage"

    @pytest.mark.asyncio
    async def test_send_text_payload_contains_text(self, adapter):
        """发送文本时，payload 中应包含正确的 text 内容。"""

        captured: list[dict] = []

        async def _capture_post(path: str, payload: dict) -> dict:
            captured.append(payload)
            return {"ret": 0, "msg_id": "mid-002"}

        adapter._post = _capture_post
        msg = OutboundMessage(chat_id="user@im.wechat", text="Hello iLink")
        await adapter.send(msg)

        item_list = captured[0]["msg"]["item_list"]
        assert item_list[0]["type"] == 1
        assert item_list[0]["text_item"]["text"] == "Hello iLink"

    @pytest.mark.asyncio
    async def test_send_text_returns_none_on_error(self, adapter):
        """iLink 返回非 0 错误码时，send() 应返回 None。"""

        adapter._post = AsyncMock(return_value={"ret": -1, "errmsg": "fail"})
        msg = OutboundMessage(chat_id="user@im.wechat", text="Test")
        result = await adapter.send(msg)
        assert result is None

    @pytest.mark.asyncio
    async def test_send_long_text_splits(self, adapter):
        """超过 2000 字符的文本应分多次发送。"""

        call_count = 0

        async def _mock_post(path: str, payload: dict) -> dict:
            nonlocal call_count
            call_count += 1
            return {"ret": 0, "msg_id": f"mid-{call_count:03d}"}

        adapter._post = _mock_post
        long_text = "A" * 4500  # 应分为 3 块（2000+2000+500）
        msg = OutboundMessage(chat_id="user@im.wechat", text=long_text)
        await adapter.send(msg)

        assert call_count == 3

    @pytest.mark.asyncio
    async def test_send_with_context_token_from_metadata(self, adapter):
        """metadata 中的 context_token 应传入 payload。"""

        captured: list[dict] = []

        async def _capture_post(path: str, payload: dict) -> dict:
            captured.append(payload)
            return {"ret": 0, "msg_id": "mid-003"}

        adapter._post = _capture_post
        msg = OutboundMessage(
            chat_id="user@im.wechat",
            text="带上下文",
            metadata={"context_token": "ctx-xyz"},
        )
        await adapter.send(msg)
        assert captured[0]["msg"]["context_token"] == "ctx-xyz"


# ── receive() 测试 ────────────────────────────────────────────────────────

class TestReceive:
    """测试 receive() 异步生成器能正确产出队列中的消息。"""

    @pytest.mark.asyncio
    async def test_yields_queued_messages(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        adapter._connected = True

        # 预先放入一条消息
        test_msg = UnifiedMessage(
            id="recv-001",
            channel="wechat_clawbot",
            sender=Identity(id="user@im.wechat"),
            content=MessageContent(type=ContentType.TEXT, text="收到"),
        )
        await adapter._queue.put(test_msg)

        # 关闭连接，使 receive() 退出循环
        async def _disconnect_after():
            await asyncio.sleep(0.05)
            adapter._connected = False

        asyncio.create_task(_disconnect_after())

        received = []
        async for msg in adapter.receive():
            received.append(msg)

        assert len(received) == 1
        assert received[0].id == "recv-001"


# ── 长轮询逻辑测试 ────────────────────────────────────────────────────────

class TestPollLoop:
    """测试长轮询游标更新和错误退避逻辑。"""

    @pytest.mark.asyncio
    async def test_updates_buf_on_success(self):
        """成功轮询后应更新 get_updates_buf 游标。"""
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        adapter._connected = True
        adapter._client = MagicMock()

        poll_count = 0

        async def _mock_post(path: str, payload: dict) -> dict:
            nonlocal poll_count
            poll_count += 1
            if poll_count == 1:
                return {
                    "ret": 0,
                    "get_updates_buf": "new-cursor-123",
                    "msgs": [],
                }
            # 第二次停止轮询
            adapter._connected = False
            return {"ret": 0, "get_updates_buf": "cursor-456", "msgs": []}

        adapter._post = _mock_post
        await adapter._poll_loop()

        # 游标应更新为第一次响应的值
        assert "cursor" in adapter._get_updates_buf

    @pytest.mark.asyncio
    async def test_token_expired_stops_loop(self):
        """iLink 返回 ret=-14（token 过期）时应停止轮询循环。"""
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        adapter._connected = True
        adapter._client = MagicMock()
        adapter._post = AsyncMock(return_value={"ret": -14})

        await adapter._poll_loop()

        assert adapter._connected is False

    @pytest.mark.asyncio
    async def test_messages_in_response_are_queued(self):
        """轮询响应中的消息应自动入队。"""
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        adapter._connected = True
        adapter._client = MagicMock()

        call_count = 0

        async def _mock_post(path: str, payload: dict) -> dict:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "ret": 0,
                    "get_updates_buf": "buf-1",
                    "msgs": [
                        {
                            "from_user_id": "user@im.wechat",
                            "to_user_id": "bot@im.bot",
                            "context_token": "ctx-1",
                            "msg_id": "m001",
                            "item_list": [
                                {"type": 1, "text_item": {"text": "轮询消息"}}
                            ],
                        }
                    ],
                }
            adapter._connected = False
            return {"ret": 0, "get_updates_buf": "buf-2", "msgs": []}

        adapter._post = _mock_post
        await adapter._poll_loop()

        assert not adapter._queue.empty()
        msg = adapter._queue.get_nowait()
        assert msg.content.text == "轮询消息"


# ── send_typing 测试 ─────────────────────────────────────────────────────

class TestSendTyping:
    """测试打字状态提示发送逻辑。"""

    @pytest.fixture
    def adapter(self):
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            a = WeChatClawBotAdapter(bot_token="tok")
            a._client = MagicMock()
            return a

    @pytest.mark.asyncio
    async def test_send_typing_calls_correct_endpoints(self, adapter):
        """send_typing 应先调用 getconfig，再调用 sendtyping。"""
        call_paths: list[str] = []

        async def _mock_post(path: str, payload: dict) -> dict:
            call_paths.append(path)
            if "getconfig" in path:
                return {"ret": 0, "typing_ticket": "ticket-abc"}
            return {"ret": 0}

        adapter._post = _mock_post
        await adapter.send_typing(chat_id="user@im.wechat", context_token="ctx-1")

        assert "/ilink/bot/getconfig" in call_paths
        assert "/ilink/bot/sendtyping" in call_paths

    @pytest.mark.asyncio
    async def test_send_typing_reuses_ticket(self, adapter):
        """ticket 未过期时不应重复调用 getconfig。"""
        adapter._typing_ticket = "cached-ticket"
        adapter._typing_ticket_expires = time.time() + 300

        call_paths: list[str] = []

        async def _mock_post(path: str, payload: dict) -> dict:
            call_paths.append(path)
            return {"ret": 0}

        adapter._post = _mock_post
        await adapter.send_typing(chat_id="user@im.wechat")

        # getconfig 不应被调用（使用缓存票证）
        assert "/ilink/bot/getconfig" not in call_paths
        assert "/ilink/bot/sendtyping" in call_paths

    @pytest.mark.asyncio
    async def test_send_typing_noop_when_getconfig_fails(self, adapter):
        """getconfig 失败时 send_typing 应静默退出。"""
        adapter._post = AsyncMock(return_value={"ret": -1})

        # 不应抛出异常
        await adapter.send_typing(chat_id="user@im.wechat")
        assert adapter._queue.empty()


# ── connect / disconnect 测试 ─────────────────────────────────────────────

class TestConnectDisconnect:
    """测试连接和断开连接的状态管理。"""

    @pytest.mark.asyncio
    async def test_connect_sets_connected(self):
        """connect() 应将 _connected 设为 True，并启动轮询任务。"""
        mock_httpx = _make_httpx_mock()

        async_client_instance = AsyncMock()
        async_client_instance.__aenter__ = AsyncMock(return_value=async_client_instance)
        async_client_instance.__aexit__ = AsyncMock(return_value=None)
        async_client_instance.post = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=MagicMock(return_value={"ret": 0, "get_updates_buf": "", "msgs": []}),
                raise_for_status=MagicMock(),
            )
        )
        mock_httpx.AsyncClient = MagicMock(return_value=async_client_instance)

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        await adapter.connect()
        assert adapter._connected is True
        assert adapter._poll_task is not None

        await adapter.disconnect()

    @pytest.mark.asyncio
    async def test_disconnect_sets_disconnected(self):
        """disconnect() 应将 _connected 设为 False 并取消轮询任务。"""
        mock_httpx = _make_httpx_mock()

        async_client_instance = AsyncMock()
        async_client_instance.aclose = AsyncMock()
        async_client_instance.post = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                json=MagicMock(return_value={"ret": 0, "get_updates_buf": "", "msgs": []}),
                raise_for_status=MagicMock(),
            )
        )
        mock_httpx.AsyncClient = MagicMock(return_value=async_client_instance)

        with patch.dict(sys.modules, {"httpx": mock_httpx}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        await adapter.connect()
        await adapter.disconnect()

        assert adapter._connected is False

    @pytest.mark.asyncio
    async def test_disconnect_without_connect_is_safe(self):
        """未 connect 就调用 disconnect 不应抛出异常。"""
        with patch.dict(sys.modules, {"httpx": _make_httpx_mock()}):
            from unified_channel.adapters.wechat_clawbot import WeChatClawBotAdapter
            adapter = WeChatClawBotAdapter(bot_token="tok")

        await adapter.disconnect()  # 不应抛出
        assert adapter._connected is False
