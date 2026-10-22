"""Keep reviewed memory tools bound to authenticated QQ conversations."""

from types import SimpleNamespace

import pytest
from astrbot.core.agent.tool import FunctionTool, ToolSet

from astrbot_plugin_qq_security.runtime import GuardedTool, identity_from_event

from .test_runtime import Event


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name", ["memory_companion_remember", "memory_companion_recall"]
)
@pytest.mark.parametrize("reviewed", [True, False])
@pytest.mark.parametrize("group", ["", "222222222"])
async def test_request_offers_reviewed_memory_tools_in_qq_conversations(
    plugin, name, reviewed, group
):
    module = "astrbot_plugin_memory_companion" if reviewed else "unreviewed_plugin"
    tool = FunctionTool(
        name=name,
        description="memory",
        parameters={"type": "object"},
        handler_module_path=f"data.plugins.{module}.main",
    )
    plugin.config["computer_qq_whitelist"] = []
    request = SimpleNamespace(
        func_tool=ToolSet([tool]),
        system_prompt="",
        prompt="Remember this in my private memory.",
        contexts=[],
    )
    await plugin.guard_request(Event(sender="999999999", group=group), request)
    assert request.func_tool.names() == ([name] if reviewed else [])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sender, group, platform, account, allowed",
    [
        ("999999999", "", "aiocqhttp", "987654321", True),
        ("999999999", "222222222", "aiocqhttp", "987654321", False),
        ("999999999", "", "webchat", "987654321", False),
        ("", "", "aiocqhttp", "987654321", False),
        ("administrator", "", "aiocqhttp", "987654321", False),
        ("999999999", "", "aiocqhttp", "", False),
    ],
)
async def test_memory_execution_rechecks_current_transport_scope(
    plugin, sender, group, platform, account, allowed
):
    event = Event(sender="999999999")
    records = {}

    async def remember_handler(event, content):
        records[event.get_sender_id()] = content
        return "saved"

    tool = FunctionTool(
        name="memory_companion_remember",
        description="memory",
        parameters={"type": "object"},
        handler=remember_handler,
        handler_module_path="data.plugins.astrbot_plugin_memory_companion.main",
    )
    guarded = GuardedTool(tool, plugin, identity_from_event(event))
    context = SimpleNamespace(
        context=SimpleNamespace(event=Event(sender, group, platform))
    )
    context.context.event.message_obj.self_id = account
    result = await guarded.call(context, content="private test preference")
    assert records == ({"999999999": "private test preference"} if allowed else {})
    assert result == (
        "saved" if allowed else "Operation denied by the security policy."
    )


@pytest.mark.asyncio
async def test_group_memory_executes_with_the_authenticated_current_group(plugin):
    event = Event(sender="999999999", group="222222222")
    records = {}

    async def remember_handler(event, content):
        records[(event.get_group_id(), event.get_sender_id())] = content
        return "saved"

    tool = FunctionTool(
        name="memory_companion_remember",
        description="memory",
        parameters={"type": "object"},
        handler=remember_handler,
        handler_module_path="data.plugins.astrbot_plugin_memory_companion.main",
    )
    result = await GuardedTool(tool, plugin, identity_from_event(event)).call(
        SimpleNamespace(context=SimpleNamespace(event=event)),
        content="group preference",
    )
    assert result == "saved"
    assert records == {("222222222", "999999999"): "group preference"}


@pytest.mark.asyncio
async def test_memory_management_tools_remain_unavailable(plugin):
    tools = [
        FunctionTool(
            name=name,
            description="unreviewed memory administration",
            parameters={"type": "object"},
            handler_module_path="data.plugins.astrbot_plugin_memory_companion.main",
        )
        for name in (
            "memory_companion_note_delete",
            "memory_companion_core_memory",
            "memory_companion_sources",
        )
    ]
    request = SimpleNamespace(
        func_tool=ToolSet(tools), system_prompt="", prompt="hello", contexts=[]
    )
    await plugin.guard_request(Event(), request)
    assert request.func_tool.names() == []
