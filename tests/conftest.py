"""Keep imports and AstrBot-generated files inside a temporary test root."""

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
_previous = os.environ.get("ASTRBOT_ROOT")
_root = TemporaryDirectory(prefix="qq-security-test-", ignore_cleanup_errors=True)
os.environ["ASTRBOT_ROOT"] = _root.name


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from astrbot.api.star import StarTools
    from astrbot.core.star.context import Context

    from astrbot_plugin_qq_security.main import QQSecurityPlugin

    from .test_runtime import Manager

    monkeypatch.setattr(StarTools, "get_data_dir", lambda name: tmp_path / name)
    context = object.__new__(Context)
    context._star_manager = Manager()
    context._config = {"agent_runner": {"runner_type": "local"}}
    context.astrbot_config_mgr = SimpleNamespace(get_conf=lambda umo: context._config)
    return QQSecurityPlugin(
        context,
        {"computer_qq_whitelist": ["123456789"], "sensitive_terms": ["测试隐私地址"]},
    )


def pytest_sessionfinish():
    if _previous is None:
        os.environ.pop("ASTRBOT_ROOT", None)
    else:
        os.environ["ASTRBOT_ROOT"] = _previous
    _root.cleanup()


@pytest.fixture
def forwarded(plugin):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from astrbot.core.message.components import Forward

    from .test_runtime import Event

    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = ["123456789"]
    event = Event(text="")
    event.message_obj.message = [Forward(id="synthetic-forward-id")]
    event.bot = SimpleNamespace(
        call_action=AsyncMock(
            return_value={
                "messages": [
                    {
                        "sender": {"nickname": "Alice"},
                        "message": [{"type": "text", "data": {"text": "周六打游戏"}}],
                    },
                    {
                        "sender": {"nickname": "Bob"},
                        "message": [{"type": "text", "data": {"text": "我也来"}}],
                    },
                ]
            }
        )
    )
    return event
