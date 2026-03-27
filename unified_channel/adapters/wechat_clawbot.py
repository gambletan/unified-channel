"""微信 ClawBot 适配器 — 基于腾讯官方 iLink 协议。

通过 iLink HTTP API 连接微信机器人，支持：
- Bearer Token 鉴权
- 长轮询接收消息
- 发送文本、图片、视频、文件消息
- 打字状态提示
- 媒体文件 AES-128-ECB 加密上传

依赖：pip install httpx aiohttp pycryptodome
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from datetime import datetime
from typing import Any, AsyncIterator

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad
except ImportError:
    _AES = None  # type: ignore[assignment]
    _pad = None  # type: ignore[assignment]

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

# iLink 协议基础 URL
_ILINK_BASE = "https://ilinkai.weixin.qq.com"

# 媒体消息类型编号（iLink 协议定义）
_MEDIA_TYPE_IMAGE = 2
_MEDIA_TYPE_VOICE = 3
_MEDIA_TYPE_FILE  = 4
_MEDIA_TYPE_VIDEO = 5

# unified-channel 媒体类型 -> iLink 媒体类型编号
_MEDIA_MAP: dict[str, int] = {
    "image": _MEDIA_TYPE_IMAGE,
    "voice": _MEDIA_TYPE_VOICE,
    "audio": _MEDIA_TYPE_VOICE,
    "file":  _MEDIA_TYPE_FILE,
    "video": _MEDIA_TYPE_VIDEO,
}


def _make_ilink_headers(bot_token: str) -> dict[str, str]:
    """生成 iLink API 所需的鉴权请求头。

    iLink 要求两个额外头部：
    - AuthorizationType: 固定为 ilink_bot_token
    - X-WECHAT-UIN: 随机 uint32 的 base64 编码（防重放攻击）
    """
    random_uin = base64.b64encode(
        str(int(time.time() * 1000) % (2**32)).encode()
    ).decode()
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bot_token}",
        "AuthorizationType": "ilink_bot_token",
        "X-WECHAT-UIN": random_uin,
    }


def _encrypt_media_aes128(data: bytes, key: bytes) -> bytes:
    """使用 AES-128-ECB 模式加密媒体文件内容。

    iLink 要求上传前先用 AES-128-ECB + PKCS#7 填充加密文件。
    """
    if _AES is None or _pad is None:
        raise RuntimeError("pycryptodome 未安装：pip install pycryptodome")
    cipher = _AES.new(key, _AES.MODE_ECB)
    return cipher.encrypt(_pad(data, _AES.block_size))


class WeChatClawBotAdapter(ChannelAdapter):
    """微信 ClawBot 适配器（iLink 协议）。

    基于腾讯官方 iLink Bot API，通过长轮询方式接收微信消息，
    并通过 HTTP API 发送文本/图片/视频/文件消息。

    配置参数：
        bot_token:       iLink Bot Token（通过扫码授权获取）
        bot_id:          机器人 ID，格式为 xxxx@im.bot（可选）
        base_url:        iLink API 地址（默认 https://ilinkai.weixin.qq.com）
        poll_timeout_ms: 长轮询超时毫秒数（默认 35000，即 35 秒）
        command_prefix:  命令前缀（默认 "/"）
        reconnect_delay: 断线重连等待秒数（默认 5）
        max_retries:     连续失败最大重试次数，超过后延长等待（默认 3）

    使用示例：
        adapter = WeChatClawBotAdapter(bot_token="your-ilink-bot-token")
        manager = ChannelManager().add_channel(adapter)
        await manager.run()
    """

    channel_id = "wechat_clawbot"

    def __init__(
        self,
        bot_token: str,
        *,
        bot_id: str = "",
        base_url: str = _ILINK_BASE,
        poll_timeout_ms: int = 35_000,
        command_prefix: str = "/",
        reconnect_delay: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        if httpx is None:
            raise RuntimeError("httpx 未安装：pip install httpx")

        self._bot_token = bot_token
        self._bot_id = bot_id
        self._base_url = base_url.rstrip("/")
        self._poll_timeout_ms = poll_timeout_ms
        self._prefix = command_prefix
        self._reconnect_delay = reconnect_delay
        self._max_retries = max_retries

        # 内部状态
        self._queue: asyncio.Queue[UnifiedMessage] = asyncio.Queue()
        self._connected = False
        self._last_activity: datetime | None = None
        self._poll_task: asyncio.Task[None] | None = None

        # iLink 长轮询游标（每次轮询响应后更新，下次发送）
        self._get_updates_buf: str = ""

        # 打字状态票证（从 /ilink/bot/getconfig 获取）
        self._typing_ticket: str = ""
        self._typing_ticket_expires: float = 0

        # HTTP 客户端（持久复用连接）
        self._client: httpx.AsyncClient | None = None

    # ─────────────────────────────────────────────────────────────────────
    # 生命周期管理
    # ─────────────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """启动 iLink 长轮询循环，开始接收微信消息。"""
        if httpx is None:
            raise RuntimeError("httpx 未安装：pip install httpx")

        # 创建持久 HTTP 客户端，超时略长于轮询窗口
        timeout = httpx.Timeout(
            connect=10.0,
            read=self._poll_timeout_ms / 1000 + 10,
            write=30.0,
            pool=None,
        )
        self._client = httpx.AsyncClient(timeout=timeout)
        self._connected = True

        # 后台启动长轮询任务
        self._poll_task = asyncio.create_task(
            self._poll_loop(), name="wechat_clawbot_poll"
        )
        logger.info(
            "wechat_clawbot 已连接：bot_id=%s base_url=%s",
            self._bot_id or "(unknown)",
            self._base_url,
        )

    async def disconnect(self) -> None:
        """优雅停止长轮询并释放 HTTP 连接。"""
        self._connected = False

        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass

        if self._client:
            await self._client.aclose()
            self._client = None

        logger.info("wechat_clawbot 已断开连接")

    async def receive(self) -> AsyncIterator[UnifiedMessage]:
        """异步迭代从微信收到的消息。"""
        while self._connected:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                yield msg
            except asyncio.TimeoutError:
                continue

    async def get_status(self) -> ChannelStatus:
        """返回当前连接状态。"""
        return ChannelStatus(
            connected=self._connected,
            channel="wechat_clawbot",
            account_id=self._bot_id or self._bot_token[:8] + "...",
            last_activity=self._last_activity,
        )

    # ─────────────────────────────────────────────────────────────────────
    # 发送消息
    # ─────────────────────────────────────────────────────────────────────

    async def send(self, msg: OutboundMessage) -> str | None:
        """发送消息到指定微信用户。

        根据 OutboundMessage 的字段自动选择消息类型：
        - media_url + media_type -> 上传并发送媒体消息
        - 否则 -> 发送文本消息

        Returns:
            成功时返回 iLink 消息 ID（字符串），失败返回 None。
        """
        # 从 metadata 中获取 context_token（回复消息时必须携带）
        context_token: str = msg.metadata.get("context_token", "")

        if msg.media_url and msg.media_type:
            return await self._send_media(
                to_user_id=msg.chat_id,
                media_url=msg.media_url,
                media_type=msg.media_type,
                context_token=context_token,
                filename=msg.metadata.get("filename", ""),
            )
        else:
            return await self._send_text(
                to_user_id=msg.chat_id,
                text=msg.text,
                context_token=context_token,
            )

    async def send_typing(self, chat_id: str, context_token: str = "") -> None:
        """向指定用户发送"正在输入"状态提示。

        调用流程：
        1. 获取/复用打字票证（typing_ticket，从 getconfig 接口获取）
        2. 调用 sendtyping 接口发送输入状态

        Args:
            chat_id:       目标用户 ID（格式 xxxx@im.wechat）
            context_token: 来自接收消息的 context_token（用于关联会话）
        """
        ticket = await self._get_typing_ticket()
        if not ticket:
            return

        payload: dict[str, Any] = {
            "typing_ticket": ticket,
            "base_info": {"channel_version": "1.0.0"},
        }
        if context_token:
            payload["context_token"] = context_token

        try:
            resp = await self._post("/ilink/bot/sendtyping", payload)
            if resp.get("ret", -1) != 0:
                logger.warning("wechat_clawbot sendtyping 失败：%s", resp)
        except Exception as exc:
            logger.warning("wechat_clawbot sendtyping 异常：%s", exc)

    # ─────────────────────────────────────────────────────────────────────
    # 长轮询核心
    # ─────────────────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """iLink 长轮询主循环。

        不断向 /ilink/bot/getupdates 发起请求，服务端最多持连 35 秒；
        超时视为空响应，立即发起下一次轮询。连续失败则指数退避重试。
        """
        consecutive_errors = 0

        while self._connected:
            try:
                data = await self._post(
                    "/ilink/bot/getupdates",
                    {
                        "get_updates_buf": self._get_updates_buf,
                        "base_info": {"channel_version": "1.0.0"},
                    },
                )

                ret = data.get("ret", -1)

                if ret == 0:
                    consecutive_errors = 0

                    # 更新游标，供下次请求使用
                    new_buf = data.get("get_updates_buf", "")
                    if new_buf:
                        self._get_updates_buf = new_buf

                    # 处理收到的消息列表
                    msgs = data.get("msgs") or []
                    for raw_msg in msgs:
                        await self._process_ilink_message(raw_msg)

                elif ret == -14:
                    # 会话过期，token 失效
                    logger.error("wechat_clawbot：iLink token 已过期（ret=-14）")
                    self._connected = False
                    break
                else:
                    logger.warning("wechat_clawbot getupdates 返回错误：%s", data)
                    consecutive_errors += 1

            except asyncio.CancelledError:
                break
            except Exception as exc:
                consecutive_errors += 1
                logger.warning(
                    "wechat_clawbot 轮询异常（第 %d 次）：%s",
                    consecutive_errors,
                    exc,
                )

            # 连续失败超过阈值时，指数退避
            if consecutive_errors >= self._max_retries:
                wait = min(self._reconnect_delay * (2 ** (consecutive_errors - self._max_retries)), 120)
                logger.warning("wechat_clawbot 退避等待 %.1f 秒", wait)
                await asyncio.sleep(wait)
            # 正常情况下立即发起下一次轮询（服务端已持连 ~35 秒）

    # ─────────────────────────────────────────────────────────────────────
    # 消息解析
    # ─────────────────────────────────────────────────────────────────────

    async def _process_ilink_message(self, raw: dict[str, Any]) -> None:
        """将 iLink 原始消息解析为 UnifiedMessage 并推入队列。

        iLink 消息结构：
        {
          "message_type": 1,          # 1=接收
          "from_user_id": "xxx@im.wechat",
          "to_user_id": "xxx@im.bot",
          "context_token": "...",     # 回复时必须携带
          "item_list": [
            {"type": 1, "text_item": {"text": "消息内容"}},
            {"type": 2, "image_item": {"media": "..."}},
            ...
          ]
        }
        """
        from_user = raw.get("from_user_id", "")
        to_user = raw.get("to_user_id", "")
        context_token = raw.get("context_token", "")
        msg_id = raw.get("msg_id", str(int(time.time() * 1000)))

        self._last_activity = datetime.now()

        # 解析 item_list 中的第一个有效内容项
        item_list: list[dict[str, Any]] = raw.get("item_list") or []
        mc: MessageContent | None = None

        for item in item_list:
            item_type = item.get("type", 0)

            if item_type == 1:
                # 文本消息
                text = item.get("text_item", {}).get("text", "")
                if text.startswith(self._prefix):
                    parts = text[len(self._prefix):].split()
                    cmd = parts[0] if parts else ""
                    args = parts[1:]
                    mc = MessageContent(
                        type=ContentType.COMMAND,
                        text=text,
                        command=cmd,
                        args=args,
                    )
                else:
                    mc = MessageContent(type=ContentType.TEXT, text=text)

            elif item_type == _MEDIA_TYPE_IMAGE:
                # 图片消息
                image_data = item.get("image_item", {})
                mc = MessageContent(
                    type=ContentType.MEDIA,
                    text="",
                    media_type="image",
                    media_url=image_data.get("media", ""),
                )

            elif item_type == _MEDIA_TYPE_VOICE:
                # 语音消息
                mc = MessageContent(
                    type=ContentType.MEDIA,
                    text="",
                    media_type="voice",
                    media_url=item.get("voice_item", {}).get("media", ""),
                )

            elif item_type == _MEDIA_TYPE_FILE:
                # 文件消息
                file_data = item.get("file_item", {})
                mc = MessageContent(
                    type=ContentType.MEDIA,
                    text=file_data.get("filename", ""),
                    media_type="file",
                    media_url=file_data.get("media", ""),
                )

            elif item_type == _MEDIA_TYPE_VIDEO:
                # 视频消息
                mc = MessageContent(
                    type=ContentType.MEDIA,
                    text="",
                    media_type="video",
                    media_url=item.get("video_item", {}).get("media", ""),
                )

            if mc:
                break  # 取第一个可识别内容项，跳出循环

        if mc is None:
            # 未识别的消息类型，记录日志并跳过
            logger.debug("wechat_clawbot：跳过未识别消息类型，item_list=%s", item_list)
            return

        msg = UnifiedMessage(
            id=msg_id,
            channel="wechat_clawbot",
            sender=Identity(id=from_user),
            content=mc,
            timestamp=datetime.now(),
            chat_id=from_user,   # 回复目标为发送者
            raw=raw,
            metadata={
                "context_token": context_token,  # 回复时必须携带
                "to_user_id": to_user,
                "bot_id": self._bot_id or to_user,
            },
        )
        await self._queue.put(msg)

    # ─────────────────────────────────────────────────────────────────────
    # 发送文本消息
    # ─────────────────────────────────────────────────────────────────────

    async def _send_text(
        self,
        to_user_id: str,
        text: str,
        context_token: str = "",
    ) -> str | None:
        """发送文本消息。单条最大 2000 字符，超长自动分割发送。

        Args:
            to_user_id:    目标用户 ID（格式 xxxx@im.wechat）
            text:          消息正文
            context_token: 关联上下文令牌（可选）

        Returns:
            最后一条消息的 ID，失败返回 None。
        """
        # 超过 2000 字符时分割发送
        chunks = [text[i:i + 2000] for i in range(0, max(len(text), 1), 2000)]
        last_msg_id: str | None = None

        for chunk in chunks:
            payload = self._build_send_payload(
                to_user_id=to_user_id,
                context_token=context_token,
                item_list=[{"type": 1, "text_item": {"text": chunk}}],
            )
            try:
                resp = await self._post("/ilink/bot/sendmessage", payload)
                if resp.get("ret", -1) == 0:
                    last_msg_id = resp.get("msg_id", "")
                    self._last_activity = datetime.now()
                else:
                    logger.error("wechat_clawbot 发送文本失败：%s", resp)
                    return None
            except Exception as exc:
                logger.error("wechat_clawbot 发送文本异常：%s", exc)
                return None

        return last_msg_id

    # ─────────────────────────────────────────────────────────────────────
    # 发送媒体消息（图片/视频/文件）
    # ─────────────────────────────────────────────────────────────────────

    async def _send_media(
        self,
        to_user_id: str,
        media_url: str,
        media_type: str,
        context_token: str = "",
        filename: str = "",
    ) -> str | None:
        """发送媒体消息（图片、视频、文件）。

        iLink 媒体上传三步流程：
        1. 调用 getuploadurl 获取预签名 CDN 上传地址和 AES 密钥
        2. 本地 AES-128-ECB 加密文件内容
        3. PUT 加密数据到 CDN，获取媒体引用
        4. 调用 sendmessage 发送含媒体引用的消息

        Args:
            to_user_id:    目标用户 ID
            media_url:     本地文件路径或 HTTP URL
            media_type:    "image" | "video" | "file" | "voice"
            context_token: 关联上下文令牌
            filename:      文件消息显示的文件名

        Returns:
            成功返回消息 ID，失败返回 None。
        """
        if _AES is None:
            logger.error("wechat_clawbot：发送媒体需要 pycryptodome：pip install pycryptodome")
            return None

        # 步骤 1：读取文件内容
        try:
            file_data = await self._read_media(media_url)
        except Exception as exc:
            logger.error("wechat_clawbot：读取媒体文件失败：%s", exc)
            return None

        # 步骤 2：获取上传 URL 和 AES 密钥
        try:
            upload_info = await self._post(
                "/ilink/bot/getuploadurl",
                {"base_info": {"channel_version": "1.0.0"}},
            )
        except Exception as exc:
            logger.error("wechat_clawbot：getuploadurl 失败：%s", exc)
            return None

        if upload_info.get("ret", -1) != 0:
            logger.error("wechat_clawbot：getuploadurl 返回错误：%s", upload_info)
            return None

        cdn_url: str = upload_info.get("upload_url", "")
        aes_key_b64: str = upload_info.get("aes_key", "")

        if not cdn_url or not aes_key_b64:
            logger.error("wechat_clawbot：getuploadurl 响应缺少 upload_url 或 aes_key")
            return None

        # 步骤 3：解码 AES 密钥（支持原始16字节和十六进制两种格式）
        try:
            aes_key = base64.b64decode(aes_key_b64)
            if len(aes_key) == 32:
                # 十六进制字符串格式：将 32 字符 hex 再解码为 16 字节
                aes_key = bytes.fromhex(aes_key.decode())
        except Exception as exc:
            logger.error("wechat_clawbot：AES 密钥解码失败：%s", exc)
            return None

        # 步骤 4：AES-128-ECB 加密文件内容
        try:
            encrypted_data = _encrypt_media_aes128(file_data, aes_key)
        except Exception as exc:
            logger.error("wechat_clawbot：媒体加密失败：%s", exc)
            return None

        # 步骤 5：PUT 加密内容到腾讯 CDN
        try:
            assert self._client is not None
            cdn_resp = await self._client.put(
                cdn_url,
                content=encrypted_data,
                headers={"Content-Type": "application/octet-stream"},
            )
            cdn_resp.raise_for_status()
        except Exception as exc:
            logger.error("wechat_clawbot：CDN 上传失败：%s", exc)
            return None

        # 从 CDN 响应中获取媒体引用（通常在响应体或 Location 头中）
        media_ref: str = cdn_resp.headers.get("X-Media-Id", "")
        if not media_ref:
            try:
                cdn_body = cdn_resp.json()
                media_ref = cdn_body.get("media_id", cdn_body.get("media", ""))
            except Exception:
                media_ref = cdn_url  # 降级：直接使用上传 URL 作为引用

        # 步骤 6：构建媒体消息 item
        ilink_type = _MEDIA_MAP.get(media_type, _MEDIA_TYPE_FILE)
        item: dict[str, Any]

        if ilink_type == _MEDIA_TYPE_IMAGE:
            item = {
                "type": ilink_type,
                "image_item": {
                    "media": media_ref,
                    "aes_key": aes_key_b64,
                },
            }
        elif ilink_type == _MEDIA_TYPE_VIDEO:
            item = {
                "type": ilink_type,
                "video_item": {
                    "media": media_ref,
                    "aes_key": aes_key_b64,
                },
            }
        elif ilink_type == _MEDIA_TYPE_VOICE:
            item = {
                "type": ilink_type,
                "voice_item": {
                    "media": media_ref,
                    "aes_key": aes_key_b64,
                },
            }
        else:
            # 文件消息需要 filename
            if not filename:
                filename = os.path.basename(media_url) or "file"
            item = {
                "type": ilink_type,
                "file_item": {
                    "media": media_ref,
                    "filename": filename,
                    "aes_key": aes_key_b64,
                },
            }

        # 步骤 7：发送消息
        payload = self._build_send_payload(
            to_user_id=to_user_id,
            context_token=context_token,
            item_list=[item],
        )
        try:
            resp = await self._post("/ilink/bot/sendmessage", payload)
            if resp.get("ret", -1) == 0:
                self._last_activity = datetime.now()
                return resp.get("msg_id", "")
            else:
                logger.error("wechat_clawbot 发送媒体消息失败：%s", resp)
                return None
        except Exception as exc:
            logger.error("wechat_clawbot 发送媒体消息异常：%s", exc)
            return None

    # ─────────────────────────────────────────────────────────────────────
    # 打字状态票证管理
    # ─────────────────────────────────────────────────────────────────────

    async def _get_typing_ticket(self) -> str:
        """获取或复用打字状态票证（typing_ticket）。

        票证有有效期，本方法实现简单缓存（5分钟有效）。
        """
        now = time.time()
        if self._typing_ticket and now < self._typing_ticket_expires:
            return self._typing_ticket

        try:
            resp = await self._post(
                "/ilink/bot/getconfig",
                {"base_info": {"channel_version": "1.0.0"}},
            )
            if resp.get("ret", -1) == 0:
                self._typing_ticket = resp.get("typing_ticket", "")
                self._typing_ticket_expires = now + 300  # 缓存 5 分钟
                return self._typing_ticket
            else:
                logger.warning("wechat_clawbot getconfig 失败：%s", resp)
        except Exception as exc:
            logger.warning("wechat_clawbot getconfig 异常：%s", exc)

        return ""

    # ─────────────────────────────────────────────────────────────────────
    # 工具方法
    # ─────────────────────────────────────────────────────────────────────

    def _build_send_payload(
        self,
        to_user_id: str,
        item_list: list[dict[str, Any]],
        context_token: str = "",
    ) -> dict[str, Any]:
        """构建 /ilink/bot/sendmessage 请求体。

        iLink 发送消息格式：
        {
          "msg": {
            "to_user_id": "...",
            "message_type": 2,    # 2 = 发送方向
            "message_state": 2,
            "context_token": "...",
            "item_list": [...]
          }
        }
        """
        msg: dict[str, Any] = {
            "to_user_id": to_user_id,
            "message_type": 2,
            "message_state": 2,
            "item_list": item_list,
        }
        if context_token:
            msg["context_token"] = context_token
        return {"msg": msg}

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """向 iLink API 发送 POST 请求。

        Args:
            path:    API 路径，如 "/ilink/bot/getupdates"
            payload: 请求体（自动序列化为 JSON）

        Returns:
            响应 JSON 字典。

        Raises:
            httpx.HTTPError: 网络错误或非 2xx 状态码
            RuntimeError:    客户端未初始化
        """
        if self._client is None:
            raise RuntimeError("wechat_clawbot：HTTP 客户端未初始化，请先调用 connect()")

        url = f"{self._base_url}{path}"
        headers = _make_ilink_headers(self._bot_token)

        resp = await self._client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    async def _read_media(self, media_url: str) -> bytes:
        """读取媒体内容（支持本地文件路径和 HTTP URL）。

        Args:
            media_url: 本地文件路径（以 "/" 开头）或 HTTP/HTTPS URL

        Returns:
            文件二进制内容。
        """
        if media_url.startswith(("http://", "https://")):
            assert self._client is not None
            resp = await self._client.get(media_url)
            resp.raise_for_status()
            return resp.content
        else:
            # 本地文件路径
            with open(media_url, "rb") as f:
                return f.read()
