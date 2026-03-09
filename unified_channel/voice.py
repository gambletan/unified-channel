"""Voice middleware — STT/TTS processing for audio messages."""

from __future__ import annotations

import io
import logging
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .middleware import Handler, Middleware
from .types import ContentType, OutboundMessage, UnifiedMessage

logger = logging.getLogger(__name__)

# Audio media types that trigger voice processing
VOICE_MEDIA_TYPES = frozenset({"voice", "audio", "ogg", "mp3", "wav"})


# ---------------------------------------------------------------------------
# Abstract providers
# ---------------------------------------------------------------------------


class STTProvider(ABC):
    """Speech-to-text provider interface."""

    @abstractmethod
    async def transcribe(self, audio: bytes, format: str = "ogg") -> str:
        """Transcribe audio bytes to text."""


class TTSProvider(ABC):
    """Text-to-speech provider interface."""

    @abstractmethod
    async def synthesize(self, text: str) -> tuple[bytes, str]:
        """Synthesize text to audio. Returns (audio_bytes, mime_type)."""


# ---------------------------------------------------------------------------
# OpenAI implementations
# ---------------------------------------------------------------------------


class OpenAISTT(STTProvider):
    """OpenAI Whisper API speech-to-text."""

    def __init__(self, api_key: str, model: str = "whisper-1") -> None:
        self.api_key = api_key
        self.model = model

    async def transcribe(self, audio: bytes, format: str = "ogg") -> str:
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required for OpenAISTT: pip install httpx")

        ext = format if format in ("ogg", "mp3", "wav", "m4a", "webm") else "ogg"
        filename = f"audio.{ext}"

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.openai.com/v1/audio/transcriptions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                files={"file": (filename, audio, f"audio/{ext}")},
                data={"model": self.model},
                timeout=60.0,
            )
            resp.raise_for_status()
            return resp.json()["text"]


class OpenAITTS(TTSProvider):
    """OpenAI TTS API text-to-speech."""

    def __init__(
        self,
        api_key: str,
        model: str = "tts-1",
        voice: str = "alloy",
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.voice = voice

    async def synthesize(self, text: str) -> tuple[bytes, str]:
        try:
            import httpx
        except ImportError:
            raise RuntimeError("httpx is required for OpenAITTS: pip install httpx")

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.openai.com/v1/audio/speech",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "voice": self.voice,
                    "input": text,
                },
                timeout=60.0,
            )
            resp.raise_for_status()
            return resp.content, "audio/mpeg"


# ---------------------------------------------------------------------------
# Local Whisper implementation
# ---------------------------------------------------------------------------


class WhisperLocalSTT(STTProvider):
    """Local Whisper speech-to-text (CLI or Python package)."""

    def __init__(self, model_size: str = "base") -> None:
        self.model_size = model_size

    async def transcribe(self, audio: bytes, format: str = "ogg") -> str:
        # Try CLI first
        try:
            return await self._transcribe_cli(audio, format)
        except (FileNotFoundError, OSError):
            pass

        # Fallback to Python package
        return await self._transcribe_python(audio, format)

    async def _transcribe_cli(self, audio: bytes, format: str) -> str:
        """Use the whisper CLI tool."""
        import asyncio

        ext = format if format in ("ogg", "mp3", "wav", "m4a") else "ogg"
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / f"input.{ext}"
            input_path.write_bytes(audio)

            proc = await asyncio.create_subprocess_exec(
                "whisper",
                str(input_path),
                "--model",
                self.model_size,
                "--output_format",
                "txt",
                "--output_dir",
                tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            await proc.wait()

            txt_path = Path(tmpdir) / f"input.txt"
            if txt_path.exists():
                return txt_path.read_text().strip()

            raise RuntimeError("Whisper CLI did not produce output")

    async def _transcribe_python(self, audio: bytes, format: str) -> str:
        """Use the openai-whisper Python package."""
        try:
            import whisper
        except ImportError:
            raise RuntimeError(
                "No whisper implementation found. Install either the whisper CLI "
                "or the openai-whisper Python package."
            )

        import asyncio

        ext = format if format in ("ogg", "mp3", "wav", "m4a") else "ogg"

        def _run() -> str:
            model = whisper.load_model(self.model_size)
            with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as f:
                f.write(audio)
                f.flush()
                result = model.transcribe(f.name)
            return result["text"].strip()

        return await asyncio.to_thread(_run)


# ---------------------------------------------------------------------------
# Voice middleware
# ---------------------------------------------------------------------------


async def _download_audio(url: str) -> bytes:
    """Download audio bytes from a URL."""
    try:
        import httpx
    except ImportError:
        raise RuntimeError("httpx is required for audio download: pip install httpx")

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
        return resp.content


class VoiceMiddleware(Middleware):
    """Middleware that handles voice/audio messages via STT and optional TTS.

    When a message contains audio media, transcribes it to text before passing
    it down the handler chain. If auto_tts is enabled, synthesizes the text
    reply back to audio.
    """

    def __init__(
        self,
        stt_provider: STTProvider | None = None,
        tts_provider: TTSProvider | None = None,
        auto_tts: bool = False,
        download_fn: callable | None = None,
    ) -> None:
        self.stt_provider = stt_provider
        self.tts_provider = tts_provider
        self.auto_tts = auto_tts
        # Allow injecting download function for testing
        self._download_fn = download_fn or _download_audio

    def _is_voice_message(self, msg: UnifiedMessage) -> bool:
        """Check if a message contains voice/audio content."""
        return (
            msg.content.type == ContentType.MEDIA
            and msg.content.media_type is not None
            and msg.content.media_type.lower() in VOICE_MEDIA_TYPES
        )

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        if not self._is_voice_message(msg):
            return await next_handler(msg)

        # No STT provider configured — pass through unchanged
        if self.stt_provider is None:
            return await next_handler(msg)

        # Missing media_url — skip transcription, pass through
        if not msg.content.media_url:
            logger.warning("Voice message has no media_url, skipping transcription")
            return await next_handler(msg)

        # Download and transcribe
        try:
            audio_bytes = await self._download_fn(msg.content.media_url)
            audio_format = msg.content.media_type or "ogg"
            transcribed_text = await self.stt_provider.transcribe(
                audio_bytes, format=audio_format
            )
        except Exception as e:
            logger.error("STT transcription failed: %s", e)
            return f"[Voice transcription error: {e}]"

        # Store original audio info in metadata
        msg.metadata["voice_original"] = {
            "media_url": msg.content.media_url,
            "media_type": msg.content.media_type,
            "format": audio_format,
        }

        # Replace content with transcribed text
        msg.content = type(msg.content)(
            type=ContentType.TEXT,
            text=transcribed_text,
        )

        # Pass modified message to next handler
        result = await next_handler(msg)

        # Auto TTS: convert text reply to audio
        if self.auto_tts and self.tts_provider and result is not None:
            reply_text = result.text if isinstance(result, OutboundMessage) else result
            if isinstance(reply_text, str) and reply_text:
                try:
                    audio_data, mime_type = await self.tts_provider.synthesize(
                        reply_text
                    )
                    if isinstance(result, OutboundMessage):
                        result.metadata["tts_audio"] = audio_data
                        result.metadata["tts_mime_type"] = mime_type
                    else:
                        result = OutboundMessage(
                            chat_id=msg.chat_id or "",
                            text=reply_text,
                            metadata={
                                "tts_audio": audio_data,
                                "tts_mime_type": mime_type,
                            },
                        )
                except Exception as e:
                    logger.error("TTS synthesis failed: %s", e)
                    # Return text reply without audio on TTS failure

        return result
