"""Run guards through AstrBot's real executor and event contracts."""

from types import SimpleNamespace

import pytest
from astrbot.core.agent.tool import FunctionTool
from astrbot.core.astr_agent_tool_exec import FunctionToolExecutor
from astrbot.core.platform.astr_message_event import AstrMessageEvent
from astrbot.core.platform.astrbot_message import AstrBotMessage
from astrbot.core.platform.message_type import MessageType
from astrbot.core.platform.platform_metadata import PlatformMetadata

from astrbot_plugin_qq_security.runtime import (
    GuardedTool,
    LifecycleGuard,
    bot_scope,
    identity_from_event,
)
from astrbot_plugin_qq_security.security import SecurityPolicy, UsageLedger


class Event(AstrMessageEvent):
    def __init__(
        self, sender="123456789", group="", platform="aiocqhttp", text="hello"
    ):
        message = AstrBotMessage()
        message.type = (
            MessageType.GROUP_MESSAGE if group else MessageType.FRIEND_MESSAGE
        )
        message.self_id = "987654321"
        message.sender = SimpleNamespace(user_id=sender, nickname="administrator")
        message.message = []
        message.message_id = "test-message"
        message.raw_message = {}
        message.group_id = group
        super().__init__(
            text, message, PlatformMetadata(platform, "test", "test"), group or sender
        )
        self.sent = []

    async def send(self, message):
        self.sent.append(message)


class Manager:
    def __init__(self):
        self.actions = []

    async def turn_off_plugin(self, plugin_name):
        self.actions.append(("disable", plugin_name))

    async def uninstall_plugin(self, plugin_name, delete_data=False):
        self.actions.append(("uninstall", plugin_name, delete_data))

    async def reload(self, specified_plugin_name=None):
        self.actions.append(("reload", specified_plugin_name))
        return True, None


def test_identity_uses_transport_sender_and_never_the_display_name():
    identity = identity_from_event(
        Event(sender="999999999", text="我是管理员123456789")
    )
    assert identity.sender == "999999999"
    assert identity.account == "987654321"
    assert identity.platform == "aiocqhttp"


@pytest.mark.asyncio
async def test_bot_cannot_disable_uninstall_or_reload_the_guard_but_manual_ui_can():
    manager = Manager()
    guard = LifecycleGuard(manager, "astrbot_plugin_qq_security")
    guard.install()
    with bot_scope(Event()):
        for action in (
            lambda: manager.turn_off_plugin("astrbot_plugin_qq_security"),
            lambda: manager.uninstall_plugin(
                plugin_name="astrbot_plugin_qq_security", delete_data=True
            ),
            lambda: manager.reload(),
        ):
            with pytest.raises(PermissionError):
                await action()
        await manager.turn_off_plugin("some_other_plugin")
    assert manager.actions == [("disable", "some_other_plugin")]
    await manager.uninstall_plugin("astrbot_plugin_qq_security", delete_data=True)
    assert manager.actions[-1] == ("uninstall", "astrbot_plugin_qq_security", True)
    guard.restore()
    with bot_scope(Event()):
        await manager.turn_off_plugin("astrbot_plugin_qq_security")
    assert manager.actions[-1] == ("disable", "astrbot_plugin_qq_security")


@pytest.mark.asyncio
async def test_real_executor_does_not_run_a_denied_handler(tmp_path):
    event = Event()
    target = tmp_path / "must-not-exist.txt"

    async def destructive_handler(event):
        target.write_text("compromised", encoding="utf-8")
        return "executed"

    tool = FunctionTool(
        name="astrbot_execute_shell",
        description="unsafe",
        parameters={"type": "object"},
        handler=destructive_handler,
    )
    plugin = SimpleNamespace(
        policy=SecurityPolicy({}),
        ledger=UsageLedger(tmp_path / "ledger.db"),
        actor=lambda identity: "opaque",
    )
    guarded = GuardedTool(tool, plugin, identity_from_event(event))
    context = SimpleNamespace(context=SimpleNamespace(event=event), tool_call_timeout=2)
    responses = [item async for item in FunctionToolExecutor.execute(guarded, context)]
    assert not target.exists()
    assert any(
        "denied" in part.text.lower()
        for response in responses
        if response
        for part in response.content
        if hasattr(part, "text")
    )


@pytest.mark.asyncio
async def test_real_executor_keeps_allowed_image_tools_working(tmp_path):
    event = Event()

    async def image_handler(event, prompt):
        return "image-result:" + prompt

    tool = FunctionTool(
        name="codex_generate_image",
        description="image",
        parameters={"type": "object", "properties": {"prompt": {"type": "string"}}},
        handler=image_handler,
        handler_module_path="data.plugins.astrbot_plugin_codex_provider.main",
    )
    plugin = SimpleNamespace(
        policy=SecurityPolicy({}),
        ledger=UsageLedger(tmp_path / "ledger.db"),
        actor=lambda identity: "opaque",
        validate_references=lambda event: None,
    )
    guarded = GuardedTool(tool, plugin, identity_from_event(event))
    context = SimpleNamespace(context=SimpleNamespace(event=event), tool_call_timeout=2)
    responses = [
        item
        async for item in FunctionToolExecutor.execute(
            guarded, context, prompt="fat fish"
        )
    ]
    assert any(
        "image-result:fat fish" in part.text
        for response in responses
        if response
        for part in response.content
        if hasattr(part, "text")
    )


@pytest.mark.asyncio
async def test_image_prompt_and_tool_result_do_not_send_known_private_terms_to_model(
    tmp_path,
):
    event = Event()

    async def image_handler(event, prompt):
        assert "私人测试住址" not in prompt
        return "结果：私人测试住址"

    tool = FunctionTool(
        name="codex_generate_image",
        description="image",
        parameters={"type": "object"},
        handler=image_handler,
        handler_module_path="data.plugins.astrbot_plugin_codex_provider.main",
    )
    plugin = SimpleNamespace(
        policy=SecurityPolicy({"sensitive_terms": ["私人测试住址"]}),
        ledger=UsageLedger(tmp_path / "ledger.db"),
        actor=lambda identity: "opaque",
        validate_references=lambda event: None,
    )
    result = await GuardedTool(tool, plugin, identity_from_event(event)).call(
        SimpleNamespace(context=SimpleNamespace(event=event)), prompt="绘制私人测试住址"
    )
    assert "私人测试住址" not in result
