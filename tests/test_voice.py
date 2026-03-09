"""Tests for voice middleware — STT/TTS processing."""

from __future__ import annotations

import pytest

from unified_channel.types import (
    ContentType,
    Identity,
    MessageContent,
    OutboundMessage,
    UnifiedMessage,
)
from unified_channel.voice import (
    STTProvider,
    TTSProvider,
    VoiceMiddleware,
)


# ---------------------------------------------------------------------------
# Mock providers
# ---------------------------------------------------------------------------


class MockSTT(STTProvider):
    """Mock STT that returns a fixed transcription."""

    def __init__(self, text: str = "transcribed text", fail: bool = False) -> None:
        self.text = text
        self.fail = fail
        self.calls: list[tuple[bytes, str]] = []

    async def transcribe(self, audio: bytes, format: str = "ogg") -> str:
        self.calls.append((audio, format))
        if self.fail:
            raise RuntimeError("STT service unavailable")
        return self.text


class MockTTS(TTSProvider):
    """Mock TTS that returns fixed audio bytes."""

    def __init__(self, audio: bytes = b"fake-audio", fail: bool = False) -> None:
        self.audio = audio
        self.fail = fail
        self.calls: list[str] = []

    async def synthesize(self, text: str) -> tuple[bytes, str]:
        self.calls.append(text)
        if self.fail:
            raise RuntimeError("TTS service unavailable")
        return self.audio, "audio/mpeg"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _voice_msg(
    media_type: str = "voice",
    media_url: str = "https://example.com/audio.ogg",
) -> UnifiedMessage:
    return UnifiedMessage(
        id="v1",
        channel="telegram",
        sender=Identity(id="user1"),
        content=MessageContent(
            type=ContentType.MEDIA,
            media_url=media_url,
            media_type=media_type,
        ),
        chat_id="chat1",
    )


def _text_msg(text: str = "hello") -> UnifiedMessage:
    return UnifiedMessage(
        id="t1",
        channel="telegram",
        sender=Identity(id="user1"),
        content=MessageContent(type=ContentType.TEXT, text=text),
        chat_id="chat1",
    )


async def _echo_handler(msg: UnifiedMessage) -> str:
    return f"echo: {msg.content.text}"


async def _mock_download(url: str) -> bytes:
    return b"fake-audio-bytes"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("media_type", ["ogg", "mp3", "wav", "voice", "audio"])
async def test_voice_detection_various_types(media_type: str):
    """Voice messages with ogg, mp3, wav, voice, audio types are detected."""
    stt = MockSTT(text="hello world")
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = _voice_msg(media_type=media_type)
    result = await mw.process(msg, _echo_handler)

    assert result == "echo: hello world"
    assert len(stt.calls) == 1


@pytest.mark.asyncio
async def test_non_voice_passthrough():
    """Non-voice messages pass through unchanged."""
    stt = MockSTT()
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = _text_msg("just text")
    result = await mw.process(msg, _echo_handler)

    assert result == "echo: just text"
    assert len(stt.calls) == 0


@pytest.mark.asyncio
async def test_stt_called_with_correct_audio():
    """STT provider receives downloaded audio bytes and format."""
    stt = MockSTT(text="recognized speech")
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = _voice_msg(media_type="mp3")
    await mw.process(msg, _echo_handler)

    assert len(stt.calls) == 1
    audio_bytes, fmt = stt.calls[0]
    assert audio_bytes == b"fake-audio-bytes"
    assert fmt == "mp3"


@pytest.mark.asyncio
async def test_transcribed_text_replaces_content():
    """After transcription, message content is replaced with text."""
    stt = MockSTT(text="what is the weather")
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = _voice_msg()
    received_msgs: list[UnifiedMessage] = []

    async def capture(m: UnifiedMessage) -> str:
        received_msgs.append(m)
        return "reply"

    await mw.process(msg, capture)

    assert len(received_msgs) == 1
    assert received_msgs[0].content.type == ContentType.TEXT
    assert received_msgs[0].content.text == "what is the weather"


@pytest.mark.asyncio
async def test_original_audio_stored_in_metadata():
    """Original audio info is stored in msg.metadata['voice_original']."""
    stt = MockSTT(text="hi")
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = _voice_msg(media_type="ogg", media_url="https://example.com/voice.ogg")
    captured: list[UnifiedMessage] = []

    async def capture(m: UnifiedMessage) -> str:
        captured.append(m)
        return "ok"

    await mw.process(msg, capture)

    voice_orig = captured[0].metadata["voice_original"]
    assert voice_orig["media_url"] == "https://example.com/voice.ogg"
    assert voice_orig["media_type"] == "ogg"


@pytest.mark.asyncio
async def test_auto_tts_generates_audio_reply():
    """When auto_tts is True, reply includes synthesized audio."""
    stt = MockSTT(text="hi")
    tts = MockTTS(audio=b"synthesized-audio")
    mw = VoiceMiddleware(
        stt_provider=stt, tts_provider=tts, auto_tts=True, download_fn=_mock_download
    )

    msg = _voice_msg()
    result = await mw.process(msg, _echo_handler)

    assert isinstance(result, OutboundMessage)
    assert result.metadata["tts_audio"] == b"synthesized-audio"
    assert result.metadata["tts_mime_type"] == "audio/mpeg"
    assert len(tts.calls) == 1


@pytest.mark.asyncio
async def test_tts_disabled_by_default():
    """TTS is not invoked when auto_tts is False (default)."""
    stt = MockSTT(text="hi")
    tts = MockTTS()
    mw = VoiceMiddleware(
        stt_provider=stt, tts_provider=tts, auto_tts=False, download_fn=_mock_download
    )

    msg = _voice_msg()
    result = await mw.process(msg, _echo_handler)

    assert result == "echo: hi"
    assert len(tts.calls) == 0


@pytest.mark.asyncio
async def test_custom_providers():
    """Custom STT/TTS providers work correctly."""

    class CustomSTT(STTProvider):
        async def transcribe(self, audio: bytes, format: str = "ogg") -> str:
            return f"custom:{len(audio)}"

    class CustomTTS(TTSProvider):
        async def synthesize(self, text: str) -> tuple[bytes, str]:
            return text.encode(), "audio/wav"

    mw = VoiceMiddleware(
        stt_provider=CustomSTT(),
        tts_provider=CustomTTS(),
        auto_tts=True,
        download_fn=_mock_download,
    )

    msg = _voice_msg()
    result = await mw.process(msg, _echo_handler)

    assert isinstance(result, OutboundMessage)
    # _mock_download returns b"fake-audio-bytes" (16 bytes)
    assert result.text == "echo: custom:16"
    assert result.metadata["tts_audio"] == b"echo: custom:16"
    assert result.metadata["tts_mime_type"] == "audio/wav"


@pytest.mark.asyncio
async def test_stt_failure_returns_error():
    """STT failure returns an error message instead of crashing."""
    stt = MockSTT(fail=True)
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = _voice_msg()
    result = await mw.process(msg, _echo_handler)

    assert isinstance(result, str)
    assert "Voice transcription error" in result
    assert "STT service unavailable" in result


@pytest.mark.asyncio
async def test_missing_media_url_skips_transcription():
    """Voice message without media_url skips transcription and passes through."""
    stt = MockSTT()
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = UnifiedMessage(
        id="v2",
        channel="telegram",
        sender=Identity(id="user1"),
        content=MessageContent(
            type=ContentType.MEDIA,
            media_type="voice",
            media_url=None,
        ),
        chat_id="chat1",
    )

    async def handler(m: UnifiedMessage) -> str:
        return "passthrough"

    result = await mw.process(msg, handler)
    assert result == "passthrough"
    assert len(stt.calls) == 0


@pytest.mark.asyncio
async def test_no_stt_provider_passthrough():
    """Without an STT provider, voice messages pass through unchanged."""
    mw = VoiceMiddleware(download_fn=_mock_download)

    msg = _voice_msg()
    result = await mw.process(msg, _echo_handler)

    # No STT, so content stays as-is (empty text on the MEDIA content)
    assert result == "echo: "


@pytest.mark.asyncio
async def test_auto_tts_with_outbound_message_reply():
    """Auto TTS adds audio to an OutboundMessage reply from the handler."""
    stt = MockSTT(text="question")
    tts = MockTTS(audio=b"audio-reply")

    async def handler_returning_outbound(msg: UnifiedMessage) -> OutboundMessage:
        return OutboundMessage(chat_id="chat1", text="answer")

    mw = VoiceMiddleware(
        stt_provider=stt, tts_provider=tts, auto_tts=True, download_fn=_mock_download
    )
    msg = _voice_msg()
    result = await mw.process(msg, handler_returning_outbound)

    assert isinstance(result, OutboundMessage)
    assert result.text == "answer"
    assert result.metadata["tts_audio"] == b"audio-reply"


@pytest.mark.asyncio
async def test_tts_failure_returns_text_reply():
    """TTS failure still returns the text reply without audio."""
    stt = MockSTT(text="hi")
    tts = MockTTS(fail=True)
    mw = VoiceMiddleware(
        stt_provider=stt, tts_provider=tts, auto_tts=True, download_fn=_mock_download
    )

    msg = _voice_msg()
    result = await mw.process(msg, _echo_handler)

    # Should return the text reply even though TTS failed
    assert result == "echo: hi"


@pytest.mark.asyncio
async def test_non_media_type_ignored():
    """Media messages with non-voice media_type (e.g. 'image') are ignored."""
    stt = MockSTT()
    mw = VoiceMiddleware(stt_provider=stt, download_fn=_mock_download)

    msg = UnifiedMessage(
        id="m1",
        channel="telegram",
        sender=Identity(id="user1"),
        content=MessageContent(
            type=ContentType.MEDIA,
            media_type="image",
            media_url="https://example.com/photo.jpg",
        ),
        chat_id="chat1",
    )

    result = await mw.process(msg, _echo_handler)
    assert result == "echo: "
    assert len(stt.calls) == 0
