"""Real waking/dispatch paths must not leak command replies outside admin DM."""

from types import SimpleNamespace

import pytest
from astrbot.core.agent.tool import ToolSet
from astrbot.core.message.components import At, Plain, Reply
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.pipeline.process_stage.method.star_request import StarRequestSubStage
from astrbot.core.pipeline.waking_check.stage import WakingCheckStage
from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter
from astrbot.core.star.filter.permission import PermissionType, PermissionTypeFilter
from astrbot.core.star.filter.regex import RegexFilter
from astrbot.core.star.session_plugin_manager import SessionPluginManager
from astrbot.core.star.star import star_map
from astrbot.core.star.star_handler import (
    EventType,
    StarHandlerMetadata,
    star_handlers_registry,
)

from .test_runtime import Event


@pytest.fixture
def command_stage(plugin, monkeypatch):
    config = plugin.context._config
    config.update(admins_id=["123456789"], wake_prefix=["/", "!"], plugin_set=["*"])
    stage = WakingCheckStage()
    stage.ctx = SimpleNamespace(astrbot_config=config)
    stage.no_permission_reply = True
    stage.friend_message_needs_wake_prefix = False
    stage.ignore_bot_self_message = False
    stage.ignore_at_all = False
    stage.disable_builtin_commands = False
    # Name recording and per-session settings are external persistence, not the
    # admission path under test. Registry, filters and dispatch remain real.
    stage._umo_auto_name_recorder = SimpleNamespace(schedule=lambda event: None)

    async def session_settings(event, handlers):
        return handlers

    monkeypatch.setattr(
        SessionPluginManager, "filter_handlers_by_session", session_settings
    )
    monkeypatch.setattr(star_handlers_registry, "_handlers", [])
    monkeypatch.setattr(star_handlers_registry, "star_handlers_map", {})
    effects = []

    def register(filters, module="test_plugin.main"):
        async def handler(event, **kwargs):
            effects.append(kwargs)
            await event.send(event.plain_result("command executed"))

        md = StarHandlerMetadata(
            EventType.AdapterMessageEvent,
            f"{module}.command",
            "command",
            module,
            handler,
            filters,
        )
        monkeypatch.setitem(
            star_map,
            module,
            SimpleNamespace(name="test_plugin", display_name="test", activated=True),
        )
        star_handlers_registry.append(md)
        return md

    return stage, register, effects


def make_command(name="help", *, required=False):
    command = CommandFilter(name, alias={"帮助"})
    command.handler_params = {"number": int} if required else {}
    return command


async def wake_and_dispatch(stage, event):
    await stage.process(event)
    if not event.is_stopped():
        async for _ in StarRequestSubStage().process(event):
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind,text",
    [
        ("plain", "/help"),
        ("plain", "!帮助"),
        ("plain", "help"),
        ("required", "/help"),
        ("permission", "/help"),
        ("group", "/插件"),
        ("group", "/插件 设置"),
        ("regex", "表情包帮助"),
        ("image", "/codex_image 一条鱼"),
        ("source", "/搜图"),
        ("social", "/鱼聊 状态"),
        ("status", "/qq_guard_status"),
    ],
)
@pytest.mark.parametrize("sender,group", [("123456789", "111111"), ("999999999", "")])
async def test_commands_silent_before_errors_or_handler_effects(
    plugin, command_stage, kind, text, sender, group
):
    stage, register, effects = command_stage
    module = "test_plugin.main"
    if kind == "group":
        filters = [CommandGroupFilter("plugin", alias={"插件"})]
    elif kind == "regex":
        filters = [RegexFilter("^表情包帮助$")]
    else:
        name = {
            "image": "codex_image",
            "source": "搜图",
            "social": "鱼聊",
            "status": "qq_guard_status",
        }.get(kind, "help")
        filters = [make_command(name, required=kind == "required")]
        if kind == "permission":
            filters.insert(0, PermissionTypeFilter(PermissionType.ADMIN))
        if kind == "plain":
            module = "astrbot.builtin_stars.builtin_commands.main"
    register(filters, module)
    event = Event(sender=sender, group=group, text=text)
    event.message_obj.message = [At(qq=event.get_self_id()), Plain(text)]
    await plugin.initialize()
    try:
        plugin._wrap_send(event)
        await wake_and_dispatch(stage, event)
        assert event.is_stopped()
        assert event.sent == []
        assert effects == []
        # A downstream handler cannot accidentally revive this command reply.
        await event.send(event.plain_result("permission error"))
        assert event.sent == []
        request = SimpleNamespace(
            func_tool=ToolSet(), system_prompt="", prompt=text, contexts=[]
        )
        await plugin.guard_request(event, request)
        assert event.get_extra("qq_security_request_ready") is None
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "native,whitelist,group,allowed",
    [
        (True, True, "", True),
        (False, True, "", False),
        (True, False, "", False),
        (True, True, "111111", False),
    ],
)
async def test_command_exception_requires_both_lists_and_private_transport(
    plugin, command_stage, native, whitelist, group, allowed
):
    stage, register, effects = command_stage
    plugin.context._config["admins_id"] = ["123456789"] if native else []
    plugin.config["computer_qq_whitelist"] = ["123456789"] if whitelist else []
    plugin.config.update(admin_codex_enabled=False, emergency_stop=True)
    register([make_command()], "astrbot.builtin_stars.builtin_commands.main")
    event = Event(group=group, text="/help")
    event.role = "admin"  # A claimed role or nickname cannot grant the exception.
    event.message_obj.message = [Plain("/help")]
    await plugin.initialize()
    try:
        plugin._wrap_send(event)
        await wake_and_dispatch(stage, event)
        assert bool(effects) is allowed
        assert bool(event.sent) is allowed
        assert event.is_stopped() is not allowed
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text",
    [
        "/你好",
        "/解释 Python 列表推导式",
        "/helpful",
        "/帮我画一条鱼",
        "/帮我看看这张图的出处",
    ],
)
async def test_slash_chat_is_not_a_command(plugin, command_stage, text):
    stage, register, effects = command_stage
    register([make_command()])
    event = Event(group="111111", text=text)
    event.message_obj.message = [
        Reply(id="quote", message=[Plain("/help")]),
        Plain(text),
    ]
    await plugin.initialize()
    try:
        await wake_and_dispatch(stage, event)
        assert not event.is_stopped()
        assert event.is_at_or_wake_command
        assert event.message_str == text[1:]
        assert event.sent == [] and effects == []
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_late_activated_plugin_command_is_silent(plugin):
    event = Event(group="111111", text="搜图")
    event.set_extra(
        "activated_handlers",
        [
            SimpleNamespace(
                event_filters=[make_command("搜图")],
                handler_module_path="data.plugins.astrbot_plugin_imgexploration.main",
            )
        ],
    )
    await plugin.guard_message(event)
    assert event.is_stopped() and not event.sent
    assert not event.get_extra("activated_handlers")


@pytest.mark.asyncio
async def test_silence_marker_is_not_sent_in_streamed_or_model_output(plugin):
    event = Event(group="111111")
    plugin._wrap_send(event)

    async def chunks():
        yield MessageChain(chain=[Plain("[QQ_SILENT_")])
        yield MessageChain(chain=[Plain("COMMAND]")])

    await event.send_streaming(chunks())
    assert event.sent == []
    response = SimpleNamespace(completion_text="[QQ_SILENT_COMMAND]")
    await plugin.guard_response(event, response)
    assert response.completion_text == ""


@pytest.mark.asyncio
async def test_waking_wrapper_is_restored_on_termination(plugin):
    original = WakingCheckStage.process
    await plugin.initialize()
    try:
        assert WakingCheckStage.process is not original
    finally:
        await plugin.terminate()
    assert WakingCheckStage.process is original
