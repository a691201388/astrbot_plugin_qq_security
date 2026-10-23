"""Regression coverage for actual AstrBot lifecycle and wire serialization."""

import socket
from types import SimpleNamespace

import aiohttp
import pytest
from astrbot.core.agent.message import TextPart
from astrbot.core.agent.tool import ToolSet
from astrbot.core.message.components import Image, Plain
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.pipeline.preprocess_stage.stage import PreProcessStage
from astrbot.core.pipeline.scheduler import PipelineScheduler
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_message_event import (
    AiocqhttpMessageEvent,
)
from astrbot.core.provider.entities import ProviderRequest
from astrbot.core.utils.active_event_registry import active_event_registry

from astrbot_plugin_qq_security.runtime import LifecycleGuard, bot_scope

from .test_runtime import Event, Manager


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["dns", "timeout", "private_dns"])
async def test_image_fetch_errors_stop_turn_with_accurate_safe_feedback(
    plugin, monkeypatch, failure
):
    cause = (
        PermissionError("private target https://private.invalid/secret")
        if failure == "private_dns"
        else socket.gaierror(-2, "unresolved https://private.invalid/secret")
    )
    error = (
        TimeoutError("https://private.invalid/secret")
        if failure == "timeout"
        else aiohttp.ClientConnectorDNSError(
            SimpleNamespace(host="gchat.qpic.cn", port=443, ssl=True), cause
        )
    )

    async def download(url):
        raise error

    monkeypatch.setattr(plugin, "_download_media", download)
    event = Event()
    event.message_obj.message = [Image.fromURL("https://gchat.qpic.cn/example")]
    stage = PreProcessStage()
    stage.config = {}
    await plugin.initialize()
    try:
        await stage.process(event)
        assert event.is_stopped()
        assert len(event.sent) == 1
        text = "".join(
            part.text for part in event.sent[0].chain if isinstance(part, Plain)
        )
        assert "private.invalid" not in text
        if failure == "private_dns":
            assert "安全检查" in text
        else:
            assert "图片" in text and "下载失败" in text
            assert "安全检查" not in text
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_stopped_webchat_still_receives_its_completion_frame(plugin):
    event = Event(platform="webchat")
    event.stop_event()
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert event.sent == [None]
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_webchat_error_response_failure_still_attempts_completion(plugin):
    event = Event(platform="webchat")
    completions = []

    async def broken_send(message):
        if message is None:
            completions.append(True)
        else:
            raise OSError("Synthetic response failure")

    def broken_namespace(current):
        raise ValueError("Synthetic admission failure")

    event.send = broken_send
    plugin._namespace = broken_namespace
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})
    await plugin.initialize()
    try:
        with pytest.raises(OSError):
            await scheduler.execute(event)
        assert completions == [True]
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_cancelled_image_preparation_cleans_previous_owned_download(
    plugin, monkeypatch
):
    import asyncio
    from pathlib import Path

    from astrbot.core.utils.astrbot_path import get_astrbot_temp_path

    root = Path(get_astrbot_temp_path()) / "astrbot_plugin_qq_security" / "incoming"
    root.mkdir(parents=True, exist_ok=True)
    downloaded = root / "cancel-test.image"
    calls = []

    async def download(url):
        calls.append(url)
        if len(calls) == 1:
            downloaded.write_bytes(b"synthetic")
            return downloaded
        raise asyncio.CancelledError

    monkeypatch.setattr(plugin, "_download_media", download)
    event = Event()
    event.message_obj.message = [
        Image.fromURL("https://gchat.qpic.cn/one"),
        Image.fromURL("https://gchat.qpic.cn/two"),
    ]
    stage = PreProcessStage()
    stage.config = {}
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})

    async def process(current):
        await stage.process(current)

    scheduler._process_stages = process
    await plugin.initialize()
    try:
        with pytest.raises(asyncio.CancelledError):
            await scheduler.execute(event)
        assert len(calls) == 2
        assert not downloaded.exists()
    finally:
        await plugin.terminate()
        downloaded.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_active_profile_cannot_bypass_runner_guard(plugin):
    event = Event()
    plugin.context.astrbot_config_mgr.get_conf = lambda umo: {
        "agent_runner": {"runner_type": "dify"}
    }
    request = ProviderRequest(prompt="hello", func_tool=ToolSet())
    await plugin.guard_request(event, request)
    assert event.is_stopped()


@pytest.mark.asyncio
async def test_attachment_text_is_redacted_before_actual_request_assembly(plugin):
    request = ProviderRequest(
        prompt="hello",
        func_tool=ToolSet(),
        extra_user_content_parts=[
            TextPart(text=r"测试隐私地址 C:\Users\private\secret.txt")
        ],
    )
    await plugin.guard_request(Event(), request)
    assembled = str(await request.assemble_context())
    assert "测试隐私地址" not in assembled
    assert "C:\\\\Users" not in assembled


@pytest.mark.asyncio
async def test_bot_unknown_reload_target_cannot_trigger_reload_all():
    manager = Manager()
    guard = LifecycleGuard(manager, "astrbot_plugin_qq_security")
    guard.install()
    try:
        with bot_scope(Event()):
            for name in ("", "missing-plugin-name", "some_other_plugin"):
                with pytest.raises(PermissionError):
                    await manager.reload(name)
        assert not manager.actions
        await manager.reload("missing-plugin-name")
        assert manager.actions == [("reload", "missing-plugin-name")]
    finally:
        guard.restore()


@pytest.mark.asyncio
async def test_output_checks_the_reference_used_by_actual_qq_serialization(
    plugin, tmp_path
):
    from PIL import Image as PillowImage

    root = tmp_path / "owned"
    root.mkdir()
    allowed, secret = root / "allowed.png", tmp_path / "private.png"
    PillowImage.new("RGB", (2, 2), "blue").save(allowed)
    PillowImage.new("RGB", (2, 2), "red").save(secret)
    plugin.media_roots = [root]
    image = Image.fromFileSystem(str(allowed))
    image.url = secret.as_uri()
    clean = plugin.clean_chain(MessageChain(chain=[image]))
    wire = await AiocqhttpMessageEvent._parse_onebot_json(clean)
    assert not any(item["type"] == "image" for item in wire)


@pytest.mark.asyncio
async def test_wire_concatenation_cannot_reconstruct_a_private_term(plugin):
    clean = plugin.clean_chain(MessageChain(chain=[Plain("测试隐"), Plain("私地址")]))
    wire = await AiocqhttpMessageEvent._parse_onebot_json(clean)
    text = "".join(item["data"]["text"] for item in wire if item["type"] == "text")
    assert "测试隐私地址" not in text


@pytest.mark.asyncio
async def test_pipeline_namespace_is_final_before_registry_and_keeps_selected_profile(
    plugin,
):
    selected = {"agent_runner": {"runner_type": "local"}, "profile": "chosen"}
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config=selected)
    event = Event()
    original = event.unified_msg_origin

    async def process(current):
        active_event_registry.register(current)
        try:
            registered = current.unified_msg_origin
            await plugin.guard_message(current)
            assert current.unified_msg_origin == registered
            assert plugin.context.get_config(current.unified_msg_origin) is selected
            assert active_event_registry.request_agent_stop_all(registered) == 1
        finally:
            active_event_registry.unregister(current)

    scheduler._process_stages = process
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert event.unified_msg_origin != original
        assert not any(
            event in events for events in active_event_registry._events.values()
        )
    finally:
        await plugin.terminate()
        # Do not pollute other tests when the regression intentionally fails.
        for key in list(active_event_registry._events):
            active_event_registry._events[key].discard(event)
            if not active_event_registry._events[key]:
                del active_event_registry._events[key]


@pytest.mark.asyncio
async def test_bad_media_is_blocked_before_any_pipeline_resolver(plugin, monkeypatch):
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})
    entered = []
    stage = PreProcessStage()
    stage.config, stage.platform_settings, stage.stt_settings = {}, {}, {}

    async def forbidden_resolver(component):
        entered.append(True)
        raise AssertionError("Forbidden image reached the native resolver")

    monkeypatch.setattr(Image, "convert_to_file_path", forbidden_resolver)

    async def process(event):
        await stage.process(event)

    scheduler._process_stages = process
    event = Event()
    event.message_obj.message = [Image.fromURL("http://127.0.0.1/private.png")]
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert event.is_stopped()
        assert not entered
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_ignored_group_message_has_no_quota_reply_or_download(
    plugin, monkeypatch
):
    from astrbot.core.pipeline.waking_check.stage import WakingCheckStage
    from astrbot.core.star.star_handler import star_handlers_registry

    plugin.config["chat_messages_per_minute"] = 0
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})
    event = Event(group="111111")
    event.message_obj.message = [
        Plain("ordinary group chatter"),
        Image.fromURL("https://gchat.qpic.cn/a"),
    ]
    passive = SimpleNamespace(
        event_filters=[SimpleNamespace(filter=lambda event, config: True)],
        handler_module_path="synthetic.passive",
        handler_full_name="synthetic.passive.handler",
    )
    monkeypatch.setattr(
        star_handlers_registry,
        "get_handlers_by_event_type",
        lambda *args, **kwargs: [passive],
    )
    waking = WakingCheckStage()
    waking.ctx = SimpleNamespace(
        astrbot_config={"admins_id": [], "wake_prefix": ["/"], "plugin_set": ["*"]}
    )
    waking.friend_message_needs_wake_prefix = False
    waking.ignore_bot_self_message = waking.ignore_at_all = (
        waking.disable_builtin_commands
    ) = False
    waking._umo_auto_name_recorder = SimpleNamespace(schedule=lambda event: None)
    stage = PreProcessStage()
    stage.config, stage.platform_settings, stage.stt_settings = {}, {}, {}
    calls = []

    async def forbidden_download(url):
        calls.append(url)
        raise AssertionError("A quiet group message must not trigger a download")

    monkeypatch.setattr(plugin, "_download_media", forbidden_download)

    async def no_wake(current):
        await waking.process(current)
        if not current.is_stopped():
            await stage.process(current)

    scheduler._process_stages = no_wake
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert not event.sent
        assert not calls
        assert not event.get_extra("qq_security_chat_counted")
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_native_private_umo_allowlist_still_matches_after_namespacing(plugin):
    from astrbot.core.pipeline.whitelist_check.stage import WhitelistCheckStage

    event = Event()
    stage = WhitelistCheckStage()
    stage.enable_whitelist_check = True
    stage.whitelist = [event.unified_msg_origin]
    stage.wl_ignore_admin_on_group = stage.wl_ignore_admin_on_friend = stage.wl_log = (
        False
    )
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})

    async def process(current):
        await stage.process(current)

    scheduler._process_stages = process
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert not event.is_stopped()
        assert stage.whitelist == [event.get_extra("qq_security_original_umo")]
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_native_original_session_and_plugin_denials_are_preserved(
    plugin, monkeypatch
):
    from astrbot.core import sp
    from astrbot.core.star.session_llm_manager import SessionServiceManager
    from astrbot.core.star.session_plugin_manager import SessionPluginManager

    event = Event()
    original = event.unified_msg_origin

    async def settings(*, scope, scope_id, key, default):
        if scope_id != original:
            return {}
        if key == "session_service_config":
            return {"session_enabled": False, "llm_enabled": False}
        if key == "session_plugin_config":
            return {original: {"disabled_plugins": ["some_plugin"]}}
        return {}

    monkeypatch.setattr(sp, "get_async", settings)
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})

    async def process(current):
        assert not await SessionServiceManager.is_session_enabled(
            current.unified_msg_origin
        )
        assert not await SessionServiceManager.is_llm_enabled_for_session(
            current.unified_msg_origin
        )
        assert not await SessionPluginManager.is_plugin_enabled_for_session(
            current.unified_msg_origin, "some_plugin"
        )

    scheduler._process_stages = process
    await plugin.initialize()
    try:
        await scheduler.execute(event)
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_valid_qq_image_retains_event_provenance_through_real_preprocess(
    plugin, monkeypatch, tmp_path
):
    from PIL import Image as PillowImage

    downloaded = tmp_path / "download.png"
    PillowImage.new("RGB", (2, 2), "orange").save(downloaded)
    calls = []

    async def download(url):
        calls.append(url)
        return downloaded

    async def localized_path(component):
        return str(downloaded)

    monkeypatch.setattr(plugin, "_download_media", download, raising=False)
    monkeypatch.setattr(Image, "convert_to_file_path", localized_path)
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})
    stage = PreProcessStage()
    stage.config, stage.platform_settings, stage.stt_settings = {}, {}, {}
    event = Event()
    event.message_obj.message = [Image.fromURL("https://gchat.qpic.cn/example.png")]

    async def process(current):
        await stage.process(current)
        await plugin.guard_message(current)
        plugin.validate_references(current)

    scheduler._process_stages = process
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert not event.is_stopped()
        assert calls == ["https://gchat.qpic.cn/example.png"]
    finally:
        await plugin.terminate()
