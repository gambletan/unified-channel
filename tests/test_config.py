"""Tests for config loading."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from unified_channel.config import _interpolate_env, _interpolate_dict, load_config


# ---------------------------------------------------------------------------
# Environment variable interpolation
# ---------------------------------------------------------------------------


def test_interpolate_env_basic(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_TOKEN", "secret123")
    assert _interpolate_env("${MY_TOKEN}") == "secret123"


def test_interpolate_env_embedded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOST", "example.com")
    assert _interpolate_env("https://${HOST}/api") == "https://example.com/api"


def test_interpolate_env_missing():
    # Ensure the var doesn't exist
    os.environ.pop("NONEXISTENT_VAR_XYZ", None)
    with pytest.raises(ValueError, match="environment variable not set"):
        _interpolate_env("${NONEXISTENT_VAR_XYZ}")


def test_interpolate_env_non_string():
    """Non-string values pass through unchanged."""
    assert _interpolate_env(42) == 42
    assert _interpolate_env(None) is None


def test_interpolate_dict_nested(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A", "val_a")
    monkeypatch.setenv("B", "val_b")
    result = _interpolate_dict({
        "top": "${A}",
        "nested": {"inner": "${B}"},
        "list_val": ["${A}", "literal"],
    })
    assert result == {
        "top": "val_a",
        "nested": {"inner": "val_b"},
        "list_val": ["val_a", "literal"],
    }


# ---------------------------------------------------------------------------
# Full config loading
# ---------------------------------------------------------------------------


def test_load_config_creates_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """load_config returns a ChannelManager with settings parsed."""
    # We mock adapter instantiation since we don't have real SDK deps
    monkeypatch.setenv("UC_TELEGRAM_TOKEN", "fake-token")

    config_file = tmp_path / "uc.yaml"
    config_file.write_text(textwrap.dedent("""\
        channels:
          telegram:
            token: "${UC_TELEGRAM_TOKEN}"

        middleware:
          access:
            allowed_users: ["admin1", "admin2"]

        settings:
          command_prefix: "!"
    """))

    # Mock the adapter import so we don't need python-telegram-bot
    mock_adapter = MagicMock()
    mock_adapter.channel_id = "telegram"

    with patch("unified_channel.config._make_adapter", return_value=mock_adapter):
        manager = load_config(str(config_file))

    assert "telegram" in manager._channels
    assert manager.metadata["command_prefix"] == "!"  # type: ignore[attr-defined]
    # AccessMiddleware should have been added
    assert len(manager._middlewares) == 1


def test_load_config_empty_file(tmp_path: Path):
    """Empty config raises ValueError."""
    config_file = tmp_path / "empty.yaml"
    config_file.write_text("")

    with pytest.raises(ValueError, match="empty or invalid"):
        load_config(str(config_file))


def test_load_config_no_yaml():
    """Missing PyYAML raises ImportError with helpful message."""
    import importlib
    import sys

    # Temporarily hide yaml
    yaml_mod = sys.modules.get("yaml")
    sys.modules["yaml"] = None  # type: ignore[assignment]
    try:
        # Re-import to trigger the check
        with pytest.raises(ImportError, match="PyYAML"):
            # Force fresh import path
            from unified_channel.config import load_config as lc
            lc("/nonexistent")
    finally:
        if yaml_mod is not None:
            sys.modules["yaml"] = yaml_mod
        else:
            sys.modules.pop("yaml", None)
