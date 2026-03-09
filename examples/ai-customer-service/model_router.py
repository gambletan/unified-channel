"""
Model Router — task-based LLM routing for Customer Service POC

Routes different tasks (translate, detect_lang, ai_reply, summarize) to
different LLM backends. All backends use OpenAI-compatible chat/completions API.

Configuration via environment variables:
    # Backend API keys
    MINIMAX_API_KEY=...
    MINIMAX_BASE_URL=https://api.minimaxi.com/v1   (optional)
    MINIMAX_MODEL=MiniMax-Text-01                   (optional)
    DEEPSEEK_API_KEY=...
    QWEN_API_KEY=...
    GLM_API_KEY=...
    OPENAI_API_KEY=...
    CLAUDE_API_KEY=...

    # Task routing (which backend handles which task)
    CS_ROUTER_TRANSLATE=minimax
    CS_ROUTER_DETECT_LANG=minimax
    CS_ROUTER_AI_REPLY=deepseek
    CS_ROUTER_SUMMARIZE=deepseek
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger("model_router")

# Task names used throughout the system
TASK_TRANSLATE = "translate"
TASK_DETECT_LANG = "detect_lang"
TASK_AI_REPLY = "ai_reply"
TASK_SUMMARIZE = "summarize"

ALL_TASKS = [TASK_TRANSLATE, TASK_DETECT_LANG, TASK_AI_REPLY, TASK_SUMMARIZE]


@dataclass
class BackendConfig:
    """Configuration for a single LLM backend."""

    name: str
    base_url: str  # Base URL without /chat/completions
    api_key: str
    model: str

    @property
    def chat_url(self) -> str:
        url = self.base_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            url += "/chat/completions"
        return url

    @property
    def available(self) -> bool:
        return bool(self.api_key)


# Default backend definitions (loaded from env)
_BACKEND_DEFAULTS: dict[str, dict[str, str]] = {
    "minimax": {
        "base_url_env": "MINIMAX_BASE_URL",
        "base_url_default": "https://api.minimaxi.com/v1",
        "api_key_env": "MINIMAX_API_KEY",
        "model_env": "MINIMAX_MODEL",
        "model_default": "MiniMax-Text-01",
    },
    "deepseek": {
        "base_url_env": "DEEPSEEK_BASE_URL",
        "base_url_default": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_API_KEY",
        "model_env": "DEEPSEEK_MODEL",
        "model_default": "deepseek-chat",
    },
    "qwen": {
        "base_url_env": "QWEN_BASE_URL",
        "base_url_default": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "api_key_env": "QWEN_API_KEY",
        "model_env": "QWEN_MODEL",
        "model_default": "qwen-plus",
    },
    "glm": {
        "base_url_env": "GLM_BASE_URL",
        "base_url_default": "https://open.bigmodel.cn/api/paas/v4",
        "api_key_env": "GLM_API_KEY",
        "model_env": "GLM_MODEL",
        "model_default": "glm-4-flash",
    },
    "openai": {
        "base_url_env": "OPENAI_BASE_URL",
        "base_url_default": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "model_env": "OPENAI_MODEL",
        "model_default": "gpt-4o-mini",
    },
    "claude": {
        "base_url_env": "CLAUDE_BASE_URL",
        "base_url_default": "https://api.anthropic.com/v1",
        "api_key_env": "CLAUDE_API_KEY",
        "model_env": "CLAUDE_MODEL",
        "model_default": "claude-sonnet-4-20250514",
    },
}

# Default task → backend mapping
_TASK_DEFAULTS: dict[str, str] = {
    TASK_TRANSLATE: "minimax",
    TASK_DETECT_LANG: "minimax",
    TASK_AI_REPLY: "deepseek",
    TASK_SUMMARIZE: "deepseek",
}


@dataclass
class ModelRouter:
    """Routes LLM tasks to configured backends.

    Usage:
        router = ModelRouter.from_env()
        result = await router.chat("translate", [
            {"role": "system", "content": "Translate to English."},
            {"role": "user", "content": "你好"},
        ])
    """

    backends: dict[str, BackendConfig] = field(default_factory=dict)
    task_routing: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> ModelRouter:
        """Build router from environment variables."""
        backends: dict[str, BackendConfig] = {}

        for name, defaults in _BACKEND_DEFAULTS.items():
            api_key = os.environ.get(defaults["api_key_env"], "")
            base_url = os.environ.get(defaults["base_url_env"], defaults["base_url_default"])
            model = os.environ.get(defaults["model_env"], defaults["model_default"])
            backends[name] = BackendConfig(
                name=name,
                base_url=base_url,
                api_key=api_key,
                model=model,
            )

        # Task routing from env (CS_ROUTER_TRANSLATE=minimax, etc.)
        task_routing: dict[str, str] = {}
        for task in ALL_TASKS:
            env_key = f"CS_ROUTER_{task.upper()}"
            backend_name = os.environ.get(env_key, _TASK_DEFAULTS[task])
            task_routing[task] = backend_name

        router = cls(backends=backends, task_routing=task_routing)
        return router

    def get_backend(self, task: str) -> BackendConfig | None:
        """Get the configured backend for a task, with fallback logic.

        Fallback order:
        1. Configured backend for this task
        2. First available backend (minimax > openai > deepseek > others)
        """
        backend_name = self.task_routing.get(task, _TASK_DEFAULTS.get(task, "minimax"))
        backend = self.backends.get(backend_name)

        if backend and backend.available:
            return backend

        # Fallback: try other backends in preference order
        fallback_order = ["minimax", "openai", "deepseek", "qwen", "glm", "claude"]
        for name in fallback_order:
            b = self.backends.get(name)
            if b and b.available:
                logger.warning(
                    "task=%s: configured backend '%s' unavailable, falling back to '%s'",
                    task, backend_name, name,
                )
                return b

        return None

    async def chat(
        self,
        task: str,
        messages: list[dict],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        timeout: float = 10,
    ) -> str:
        """Send a chat completion request routed by task.

        Args:
            task: Task name (translate, detect_lang, ai_reply, summarize).
            messages: OpenAI-format messages list.
            temperature: Optional temperature override.
            max_tokens: Optional max_tokens override.
            timeout: Request timeout in seconds.

        Returns:
            The assistant's reply text.

        Raises:
            RuntimeError: If no backend is available for the task.
        """
        backend = self.get_backend(task)
        if not backend:
            raise RuntimeError(f"No available backend for task '{task}'. Configure an API key.")

        import httpx

        payload: dict = {
            "model": backend.model,
            "messages": messages,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                backend.chat_url,
                headers={"Authorization": f"Bearer {backend.api_key}"},
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"].strip()

    def summary(self) -> list[str]:
        """Return human-readable summary lines for logging."""
        lines: list[str] = []

        available = [name for name, b in self.backends.items() if b.available]
        lines.append(f"Backends: {', '.join(available) if available else '(none)'}")

        for task in ALL_TASKS:
            backend_name = self.task_routing.get(task, "?")
            backend = self.get_backend(task)
            if backend:
                status = f"{backend.name} ({backend.model})"
                if backend.name != backend_name:
                    status += f" [fallback from {backend_name}]"
            else:
                status = f"{backend_name} (unavailable)"
            lines.append(f"  {task}: {status}")

        return lines
