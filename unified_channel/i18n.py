"""I18n middleware — auto-detects user locale and provides translation helpers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from .middleware import Handler, Middleware
from .types import OutboundMessage, UnifiedMessage


# Translation map: locale -> key -> translated string
Translations = dict[str, dict[str, str]]

# Translate function signature
TranslateFn = Callable[[str, str | None], str]


class I18nMiddleware(Middleware):
    """Middleware that detects the user's locale and attaches a translate function.

    After processing, ``msg.metadata["locale"]`` contains the resolved locale
    and ``msg.metadata["t"]`` is a callable ``t(key, fallback=None) -> str``.

    Detection order (default):
      1. msg.metadata["locale"] (if already set upstream)
      2. msg.sender.locale (if the Identity carries one)
      3. default_locale (defaults to "en")
    """

    def __init__(
        self,
        translations: Translations,
        *,
        default_locale: str = "en",
        detect_fn: Callable[[UnifiedMessage], str | None] | None = None,
    ) -> None:
        self.translations = translations
        self.default_locale = default_locale
        self._detect_fn = detect_fn or self._default_detect

    @staticmethod
    def _default_detect(msg: UnifiedMessage) -> str | None:
        """Default detection: metadata["locale"] -> sender.locale -> None."""
        meta_locale = msg.metadata.get("locale")
        if isinstance(meta_locale, str) and meta_locale:
            return meta_locale

        sender_locale = getattr(msg.sender, "locale", None)
        if isinstance(sender_locale, str) and sender_locale:
            return sender_locale

        return None

    def _resolve_locale(self, msg: UnifiedMessage) -> str:
        """Resolve effective locale, falling back to default_locale."""
        detected = self._detect_fn(msg)
        if detected and detected in self.translations:
            return detected
        return self.default_locale

    def _build_translate_fn(self, locale: str) -> TranslateFn:
        """Build a translate function bound to a specific locale."""

        def t(key: str, fallback: str | None = None) -> str:
            table = self.translations.get(locale, {})
            if key in table:
                return table[key]
            # Fall back to default locale
            default_table = self.translations.get(self.default_locale, {})
            if key in default_table:
                return default_table[key]
            return fallback if fallback is not None else key

        return t

    async def process(
        self, msg: UnifiedMessage, next_handler: Handler
    ) -> str | OutboundMessage | None:
        locale = self._resolve_locale(msg)
        t = self._build_translate_fn(locale)

        msg.metadata["locale"] = locale
        msg.metadata["t"] = t

        return await next_handler(msg)
