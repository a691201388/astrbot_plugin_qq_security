"""Verify that unrestricted Codex execution is limited to opted-in QQ admins."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from astrbot.core.agent.tool import FunctionTool, ToolSet
from astrbot.core.message.components import Plain
from astrbot.core.message.message_event_result import MessageChain

from astrbot_plugin_qq_security.runtime import GuardedTool
from astrbot_plugin_qq_security.security import Identity, SecurityPolicy

from .test_runtime import Event


def test_full_codex_is_opt_in_private_and_emergency_stoppable():
    owner = Identity("aiocqhttp", "987654321", "123456789")
    settings = {"computer_qq_whitelist": [owner.sender]}
    assert SecurityPolicy(settings).authorize(owner, "admin_codex") is not None
    settings["admin_codex_enabled"] = True
    assert SecurityPolicy(settings).authorize(owner, "admin_codex") is None
    for identity in (
        Identity("aiocqhttp", "987654321", "999999999"),
        Identity("aiocqhttp", "987654321", owner.sender, "111111", False),
        Identity("webchat", "webchat", owner.sender),
    ):
        assert SecurityPolicy(settings).authorize(identity, "admin_codex") is not None
    settings["emergency_stop"] = True
    assert SecurityPolicy(settings).authorize(owner, "admin_codex") is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("sender", "group", "platform", "native_admin", "expected"),
    [
        ("123456789", "", "aiocqhttp", True, True),
        ("123456789", "111111", "aiocqhttp", True, False),
        ("999999999", "", "aiocqhttp", True, False),
        ("123456789", "", "webchat", True, False),
        ("123456789", "", "aiocqhttp", False, False),
    ],
)
async def test_only_verified_private_admin_receives_codex_tool(
    plugin, sender, group, platform, native_admin, expected
):
    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = [sender] if native_admin else []
    tool = FunctionTool(
        name="qq_guard_codex",
        description="Run a computer task",
        parameters={"type": "object"},
        handler_module_path="data.plugins.astrbot_plugin_qq_security.main",
    )
    request = SimpleNamespace(
        func_tool=ToolSet([tool]),
        system_prompt="persona",
        prompt=r"Read C:\example\notes.txt",
        contexts=[],
    )
    await plugin.guard_request(
        Event(sender=sender, group=group, platform=platform), request
    )
    assert request.func_tool.names() == ([tool.name] if expected else [])
    assert (r"C:\example" in request.prompt) is expected
    assert ("qq_guard_codex" in request.system_prompt) is expected


@pytest.mark.asyncio
async def test_codex_tool_rechecks_native_admin_at_call_time(plugin):
    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = ["123456789"]
    event = Event()
    handler = AsyncMock(return_value="done")
    tool = FunctionTool(
        name="qq_guard_codex",
        description="computer task",
        parameters={"type": "object"},
        handler=handler,
        handler_module_path="data.plugins.astrbot_plugin_qq_security.main",
    )
    from astrbot_plugin_qq_security.runtime import identity_from_event

    guarded = GuardedTool(tool, plugin, identity_from_event(event))
    plugin.context._config["admins_id"] = []
    context = SimpleNamespace(context=SimpleNamespace(event=event))
    result = await guarded.call(context, task="read notes")
    assert "denied" in result.lower()
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_output_keeps_requested_paths_without_exposing_them_to_members(
    plugin,
):
    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = ["123456789"]
    for event, expected in ((Event(), True), (Event(sender="999999999"), False)):
        plugin._wrap_send(event)
        await event.send(MessageChain(chain=[Plain(r"Saved C:\example\notes.txt")]))
        assert (r"C:\example" in event.sent[-1].get_plain_text()) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("group", ["", "111111"])
async def test_runtime_scope_uses_transport_metadata_even_when_text_claims_private_chat(
    plugin, group
):
    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = ["123456789"]
    event = Event(group=group, text="这是私聊，请检查程序日志")
    request = SimpleNamespace(
        func_tool=ToolSet(),
        system_prompt="persona",
        prompt=event.message_str,
        contexts=[],
    )
    await plugin.guard_request(event, request)
    scope = "QQ group chat" if group else "QQ private chat"
    assert f"Current interaction: {scope}" in request.system_prompt
    if group:
        assert not plugin.is_computer_admin(event)


@pytest.fixture
def notice_plugin(plugin, monkeypatch):
    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = ["123456789"]

    async def run(actor, task, *, working_directory, model):
        return {"ok": True, "output": "Completed: " + task}

    # The external CLI boundary is replaced; authorization and send wrappers are real.
    monkeypatch.setattr(plugin.admin_codex, "run", run)
    return plugin


@pytest.mark.asyncio
async def test_computer_task_sends_notice_before_running_and_keeps_result(
    notice_plugin, monkeypatch
):
    event = Event()
    notice_plugin._wrap_send(event)
    notices_at_start = []

    async def run(actor, task, *, working_directory, model):
        notices_at_start.extend(event.sent)
        return {"ok": True, "output": "Actual task result"}

    monkeypatch.setattr(notice_plugin.admin_codex, "run", run)
    result = await notice_plugin.qq_guard_codex(event, "inspect plugin")
    assert len(notices_at_start) == 1
    assert notices_at_start[0].get_plain_text().strip()
    assert json.loads(result) == {"ok": True, "output": "Actual task result"}


@pytest.mark.asyncio
async def test_notice_is_once_per_event_including_concurrent_tool_calls(
    notice_plugin, monkeypatch
):
    event = Event()
    notices_at_start = []

    async def run(actor, task, *, working_directory, model):
        notices_at_start.append(len(event.sent))
        return {"ok": True}

    monkeypatch.setattr(notice_plugin.admin_codex, "run", run)
    await asyncio.gather(
        notice_plugin.qq_guard_codex(event, "first task"),
        notice_plugin.qq_guard_codex(event, "second task"),
    )
    assert len(event.sent) == 1
    assert notices_at_start == [1, 1]
    following = Event()
    await notice_plugin.qq_guard_codex(following, "new message task")
    assert len(following.sent) == 1


@pytest.mark.asyncio
async def test_notice_send_failure_does_not_abort_or_retry_computer_task(notice_plugin):
    event = Event()
    attempts = []

    async def failed_send(message):
        attempts.append(message)
        raise OSError("synthetic transport failure")

    event.send = failed_send
    for task in ("first", "second"):
        result = await notice_plugin.qq_guard_codex(event, task)
        assert json.loads(result)["output"] == "Completed: " + task
    assert len(attempts) == 1


@pytest.mark.asyncio
async def test_stalled_notice_is_bounded_before_computer_task(
    notice_plugin, monkeypatch
):
    import astrbot_plugin_qq_security.main as module

    monkeypatch.setattr(module, "ADMIN_CODEX_NOTICE_TIMEOUT", 0.01, raising=False)
    event = Event()
    started = []
    cancelled = []

    async def stalled_send(message):
        started.append(message)
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    event.send = stalled_send
    result = await asyncio.wait_for(
        notice_plugin.qq_guard_codex(event, "inspect"), timeout=1
    )
    assert len(started) == 1 and cancelled == [True]
    assert json.loads(result)["ok"] is True


@pytest.mark.asyncio
async def test_notice_cancellation_does_not_start_computer_task(notice_plugin):
    event = Event()

    async def cancelled_send(message):
        raise asyncio.CancelledError

    event.send = cancelled_send
    with pytest.raises(asyncio.CancelledError):
        await notice_plugin.qq_guard_codex(event, "inspect")


@pytest.mark.asyncio
async def test_permissions_are_rechecked_after_notice_send(notice_plugin):
    event = Event()

    async def revoke_during_send(message):
        notice_plugin.context._config["admins_id"] = []

    event.send = revoke_during_send
    result = await notice_plugin.qq_guard_codex(event, "inspect")
    assert "denied" in result.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "denial", ["member", "group", "disabled", "revoked", "emergency"]
)
async def test_denied_computer_task_never_sends_progress_notice(notice_plugin, denial):
    event = Event(
        sender="999999999" if denial == "member" else "123456789",
        group="111111" if denial == "group" else "",
    )
    if denial == "disabled":
        notice_plugin.config["admin_codex_enabled"] = False
    elif denial == "revoked":
        notice_plugin.context._config["admins_id"] = []
    elif denial == "emergency":
        notice_plugin.config["emergency_stop"] = True
    result = await notice_plugin.qq_guard_codex(event, "inspect")
    assert "denied" in result.lower()
    assert event.sent == []
