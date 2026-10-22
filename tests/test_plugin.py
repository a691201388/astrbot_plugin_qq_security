"""Verify the plugin boundary using real AstrBot messages and tool schemas."""

from types import SimpleNamespace

import pytest
from astrbot.core.agent.tool import FunctionTool, ToolSet
from astrbot.core.message.components import File, Image, Plain
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.star.filter.command import CommandFilter

from .test_runtime import Event


@pytest.mark.asyncio
async def test_request_keeps_chat_images_but_removes_host_and_unknown_tools(plugin):
    image = FunctionTool(
        name="codex_generate_image",
        description="image",
        parameters={"type": "object"},
        handler_module_path="data.plugins.astrbot_plugin_codex_provider.main",
    )
    shell = FunctionTool(
        name="astrbot_execute_shell", description="shell", parameters={"type": "object"}
    )
    unknown = FunctionTool(
        name="new_unreviewed_tool", description="unknown", parameters={"type": "object"}
    )
    request = SimpleNamespace(
        func_tool=ToolSet([shell, image, unknown]),
        system_prompt=r"Current workspace: E:\private\files",
        prompt="你好",
        contexts=[],
    )
    await plugin.guard_request(Event(sender="999999999"), request)
    assert request.func_tool.names() == ["codex_generate_image"]
    assert "E:\\private" not in request.system_prompt
    assert request.prompt == "你好"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["get_session_images", "search_image"])
@pytest.mark.parametrize("reviewed", [True, False])
async def test_image_source_tools_require_the_reviewed_plugin(plugin, name, reviewed):
    plugin.config["computer_qq_whitelist"] = []
    module = "astrbot_plugin_imgexploration" if reviewed else "unreviewed_plugin"
    tool = FunctionTool(
        name=name,
        description="image source",
        parameters={"type": "object"},
        handler_module_path=f"data.plugins.{module}.main",
    )
    request = SimpleNamespace(
        func_tool=ToolSet([tool]), system_prompt="", prompt="查来源", contexts=[]
    )
    await plugin.guard_request(Event(sender="999999999"), request)
    assert request.func_tool.names() == ([name] if reviewed else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("reviewed", [True, False])
async def test_source_command_requires_the_reviewed_plugin(plugin, reviewed):
    module = "astrbot_plugin_imgexploration" if reviewed else "unreviewed_plugin"
    handler = SimpleNamespace(
        event_filters=[CommandFilter("搜图")],
        handler_module_path=f"data.plugins.{module}.main",
    )
    event = Event(text="/搜图 anime")
    event.set_extra("activated_handlers", [handler])
    await plugin.guard_message(event)
    assert event.is_stopped() is (not reviewed)
    assert event.get_extra("activated_handlers") == ([handler] if reviewed else [])


@pytest.mark.asyncio
async def test_webchat_agent_also_cannot_get_a_shell_to_remove_the_guard(plugin):
    tool = FunctionTool(
        name="astrbot_execute_shell", description="shell", parameters={"type": "object"}
    )
    request = SimpleNamespace(
        func_tool=ToolSet([tool]),
        system_prompt="hello",
        prompt="remove guard",
        contexts=[],
    )
    await plugin.guard_request(Event(platform="webchat"), request)
    assert request.func_tool.empty()


@pytest.mark.asyncio
async def test_direct_plugin_management_commands_are_blocked_even_for_allowed_qq(
    plugin,
):
    event = Event(text="/plugin uninstall astrbot_plugin_qq_security")
    await plugin.guard_message(event)
    assert event.is_stopped()
    assert event.sent


@pytest.mark.asyncio
async def test_context_namespace_isolated_by_sender_and_group(plugin):
    one = Event(sender="123456789", group="111111")
    two = Event(sender="999999999", group="111111")
    three = Event(sender="123456789", group="222222")
    for event in (one, two, three):
        await plugin.guard_message(event)
    assert (
        len({one.unified_msg_origin, two.unified_msg_origin, three.unified_msg_origin})
        == 3
    )


@pytest.mark.asyncio
async def test_direct_send_is_redacted_and_file_attachments_are_blocked(
    plugin, tmp_path
):
    event = Event()
    await plugin.guard_message(event)
    secret = tmp_path / "credentials.txt"
    secret.write_text("private", encoding="utf-8")
    await event.send(
        MessageChain(
            chain=[
                Plain(r"文件在 C:\Users\someone\auth.json，测试隐私地址"),
                File(name="credentials.txt", file=str(secret)),
            ]
        )
    )
    text = event.sent[-1].get_plain_text()
    assert "C:\\Users" not in text and "测试隐私地址" not in text
    assert not any(isinstance(part, File) for part in event.sent[-1].chain)


@pytest.mark.asyncio
async def test_streaming_secret_cannot_escape_across_chunk_boundaries(plugin):
    event = Event()
    await plugin.guard_message(event)

    async def chunks():
        yield MessageChain(chain=[Plain("位置：测试隐")])
        yield MessageChain(chain=[Plain("私地址，结束。")])

    await event.send_streaming(chunks(), use_fallback=True)
    text = "".join(message.get_plain_text() for message in event.sent)
    assert "测试隐私地址" not in text
    assert "结束" in text


def test_media_reference_rejects_user_supplied_local_paths(plugin, tmp_path):
    event = Event()
    event.message_obj.message = [Image.fromFileSystem(str(tmp_path / "private.png"))]
    with pytest.raises(PermissionError):
        plugin.validate_references(event)


@pytest.mark.asyncio
async def test_workspace_tools_recheck_identity_when_called_directly(plugin):
    denied = await plugin.qq_guard_write(
        Event(sender="999999999"), "note.txt", "private"
    )
    assert "denied" in denied.lower() or "拒绝" in denied
    await plugin.qq_guard_write(Event(), "note.txt", "allowed")
    assert await plugin.qq_guard_read(Event(), "note.txt") == "allowed"


@pytest.mark.asyncio
async def test_admin_cannot_read_plugin_config_via_workspace_traversal(plugin):
    result = await plugin.qq_guard_read(
        Event(), "../../config/astrbot_plugin_qq_security_config.json"
    )
    assert "denied" in result.lower() or "拒绝" in result


@pytest.mark.asyncio
async def test_command_filters_cannot_bypass_the_guard_with_another_wake_prefix(plugin):
    event = Event(text="!set administrator true")
    dangerous = SimpleNamespace(
        event_filters=[CommandFilter("set")],
        handler_module_path="astrbot.builtin_stars.builtin_commands.main",
    )
    safe = SimpleNamespace(
        event_filters=[CommandFilter("help")],
        handler_module_path="astrbot.builtin_stars.builtin_commands.main",
    )
    handlers = [dangerous, safe]
    event.set_extra("activated_handlers", handlers)
    await plugin.guard_message(event)
    assert dangerous not in handlers
    assert safe in handlers


@pytest.mark.asyncio
async def test_external_agent_runner_is_stopped_when_its_tools_cannot_be_guarded(
    plugin,
):
    plugin.context.get_config = lambda umo=None: {
        "agent_runner": {"runner_type": "dify"}
    }
    event = Event()
    request = SimpleNamespace(
        func_tool=ToolSet(), system_prompt="hello", prompt="hello", contexts=[]
    )
    await plugin.guard_request(event, request)
    assert event.is_stopped()


def test_safe_owned_generated_image_still_passes_the_send_guard(plugin, tmp_path):
    from PIL import Image as PillowImage

    root = tmp_path / "generated"
    root.mkdir()
    path = root / "image.png"
    PillowImage.new("RGB", (2, 2), "orange").save(path)
    plugin.media_roots = [root]
    result = plugin.clean_chain(MessageChain(chain=[Image.fromFileSystem(str(path))]))
    assert any(isinstance(part, Image) for part in result.chain)


@pytest.mark.asyncio
async def test_direct_image_command_uses_the_same_persistent_quota(plugin):
    plugin.config.update({"daily_image_limit": 1, "image_cooldown_seconds": 0})

    async def image_handler(event, prompt, use_reference_images):
        await event.send(MessageChain(chain=[Plain("image-result:" + prompt)]))
        return "sent"

    tool = FunctionTool(
        name="codex_generate_image",
        description="image",
        parameters={"type": "object"},
        handler=image_handler,
        handler_module_path="data.plugins.astrbot_plugin_codex_provider.main",
    )
    plugin.context.get_llm_tool_manager = lambda: SimpleNamespace(
        get_func=lambda name: tool
    )
    first = Event(text="/codex_image first")
    second = Event(text="/codex_image second")
    await plugin.guard_message(first)
    await plugin.guard_message(second)
    assert any("image-result:first" in item.get_plain_text() for item in first.sent)
    assert not any(
        "image-result:second" in item.get_plain_text() for item in second.sent
    )


@pytest.mark.asyncio
async def test_same_user_switching_from_privileged_to_public_does_not_reuse_context(
    plugin,
):
    first = Event()
    await plugin.guard_message(first)
    plugin.config["computer_qq_whitelist"] = []
    second = Event()
    await plugin.guard_message(second)
    assert first.unified_msg_origin != second.unified_msg_origin


@pytest.mark.asyncio
async def test_request_without_an_ingress_listener_still_guards_direct_sends(plugin):
    event = Event(sender="999999999")
    request = SimpleNamespace(
        func_tool=ToolSet(), system_prompt="hello", prompt="hello", contexts=[]
    )
    await plugin.guard_request(event, request)
    await event.send(MessageChain(chain=[Plain("测试隐私地址")]))
    assert "测试隐私地址" not in event.sent[-1].get_plain_text()


@pytest.mark.asyncio
async def test_ingress_errors_stop_processing_instead_of_failing_open(plugin):
    event = Event(text="/plugin uninstall astrbot_plugin_qq_security")
    plugin.config["computer_qq_whitelist"] = None
    await plugin.guard_message(event)
    assert event.is_stopped()
