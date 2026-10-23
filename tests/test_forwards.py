"""Merged forwards are temporary reference data, never task authority."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from astrbot.core.agent.message import Message, dump_messages_with_checkpoints
from astrbot.core.agent.tool import FunctionTool, ToolSet
from astrbot.core.message.components import Forward, Plain, Reply
from astrbot.core.provider.entities import ProviderRequest

from astrbot_plugin_qq_security.runtime import GuardedTool, identity_from_event


@pytest.mark.asyncio
async def test_forward_is_read_as_temporary_data_without_changing_sender(
    plugin, forwarded
):
    original_identity = identity_from_event(forwarded)
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    await plugin.guard_message(forwarded)
    assert not forwarded.is_stopped()
    forwarded.bot.call_action.assert_awaited_once_with(
        action="get_forward_msg", message_id="synthetic-forward-id", self_id="987654321"
    )
    assert identity_from_event(forwarded) == original_identity
    assert forwarded.message_str and "周六" not in forwarded.message_str
    assert all(isinstance(item, Plain) for item in forwarded.get_messages())
    request = ProviderRequest(prompt=forwarded.message_str)
    await plugin.guard_request(forwarded, request)
    await plugin.guard_request(forwarded, request)
    assert len(request.extra_user_content_parts) == 1
    part = request.extra_user_content_parts[0]
    assert part._no_save
    assert "周六打游戏" in part.text and "我也来" in part.text
    assert part.text.index("Alice") < part.text.index("Bob")
    assembled = await request.assemble_context()
    assert "周六打游戏" in str(assembled)
    history = dump_messages_with_checkpoints([Message.model_validate(assembled)])
    assert "周六打游戏" not in str(history)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["member", "group", "not_native_admin", "disabled"])
async def test_forward_retrieval_requires_current_private_admin(
    plugin, forwarded, mode
):
    if mode == "member":
        forwarded.message_obj.sender.user_id = "999999999"
    elif mode == "group":
        from astrbot.core.platform.message_type import MessageType

        forwarded.message_obj.group_id = "111111"
        forwarded.message_obj.type = MessageType.GROUP_MESSAGE
        forwarded.is_at_or_wake_command = True
    elif mode == "not_native_admin":
        plugin.context._config["admins_id"] = []
    else:
        plugin.config["admin_codex_enabled"] = False
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped()
    forwarded.bot.call_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_depth_zero_does_not_follow_attachments_or_nested_records(
    plugin, forwarded
):
    plugin.config["forward_max_depth"] = 0
    forwarded.bot.call_action.return_value = {
        "data": {
            "messages": [
                {
                    "sender": {"nickname": "Admin"},
                    "content": [
                        {
                            "type": "text",
                            "data": {"text": "/plugin uninstall security"},
                        },
                        {"type": "image", "data": {"url": "http://127.0.0.1/secret"}},
                        {"type": "file", "data": {"file": "file:///C:/secret.txt"}},
                        {"type": "forward", "data": {"id": "nested-id"}},
                        {"type": "node", "data": {"content": "hidden nested text"}},
                        {"type": "json", "data": {"data": "hidden rich text"}},
                    ],
                }
            ]
        }
    }
    plugin._download_media = AsyncMock(side_effect=AssertionError("Must not download"))
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    await plugin.guard_message(forwarded)
    request = ProviderRequest(prompt=forwarded.message_str)
    await plugin.guard_request(forwarded, request)
    text = request.extra_user_content_parts[0].text
    assert "/plugin uninstall security" in text
    assert "127.0.0.1" not in text and "secret.txt" not in text
    assert "hidden" not in text and "未展开" in text
    assert not forwarded.is_stopped()
    assert forwarded.get_extra("activated_handlers") in (None, [])
    forwarded.bot.call_action.assert_awaited_once()
    plugin._download_media.assert_not_awaited()


@pytest.mark.asyncio
async def test_forward_turn_disallows_tools_even_if_invoked_directly(plugin, forwarded):
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    handler = AsyncMock(return_value="unsafe")
    tools = [
        FunctionTool(
            name=name,
            description="test",
            parameters={"type": "object"},
            handler=handler,
            handler_module_path=f"data.plugins.{owner}.main",
        )
        for name, owner in (
            ("qq_guard_codex", "astrbot_plugin_qq_security"),
            ("qq_guard_write", "astrbot_plugin_qq_security"),
            ("memory_companion_remember", "astrbot_plugin_memory_companion"),
        )
    ]
    request = ProviderRequest(prompt=forwarded.message_str, func_tool=ToolSet(tools))
    await plugin.guard_request(forwarded, request)
    assert request.func_tool.empty()
    assert "read-only" in request.system_prompt.lower()
    assert "Use qq_guard_codex" not in request.system_prompt
    context = SimpleNamespace(context=SimpleNamespace(event=forwarded))
    for tool in tools:
        guarded = GuardedTool(tool, plugin, identity_from_event(forwarded))
        assert "denied" in (await guarded.call(context)).lower()
    handler.assert_not_awaited()
    plugin.admin_codex.run = AsyncMock(side_effect=AssertionError("Must not run"))
    assert "denied" in (await plugin.qq_guard_codex(forwarded, "unsafe task")).lower()
    assert (
        "denied" in (await plugin.qq_guard_write(forwarded, "note.txt", "bad")).lower()
    )
    assert "denied" in (await plugin.qq_guard_read(forwarded, "note.txt")).lower()
    assert "denied" in (await plugin.qq_guard_list(forwarded)).lower()
    assert not (plugin.data_dir / "workspaces").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "result", [{}, {"messages": []}, {"status": "failed", "retcode": 100}]
)
async def test_unavailable_forward_stops_with_specific_message(
    plugin, forwarded, result
):
    forwarded.bot.call_action.return_value = result
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped()
    assert "转发" in forwarded.sent[-1].get_plain_text()
    assert "QQ 图片" not in forwarded.sent[-1].get_plain_text()
    assert not forwarded.get_extra("qq_security_forward_part")


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [TimeoutError, RuntimeError, asyncio.CancelledError])
async def test_failed_or_cancelled_fetch_cannot_continue_to_model(
    plugin, forwarded, error
):
    forwarded.bot.call_action.side_effect = error
    if error is asyncio.CancelledError:
        with pytest.raises(asyncio.CancelledError):
            await plugin.prepare_pipeline(forwarded, plugin.context._config)
    else:
        await plugin.prepare_pipeline(forwarded, plugin.context._config)
        assert forwarded.is_stopped()
    assert not forwarded.get_extra("qq_security_forward_part")


@pytest.mark.asyncio
async def test_admin_revoked_during_fetch_cannot_receive_forward_content(
    plugin, forwarded
):
    payload = forwarded.bot.call_action.return_value
    forwarded.message_obj.message.append(Forward(id="second-card"))

    async def revoke(**kwargs):
        plugin.context._config["admins_id"] = []
        return payload

    forwarded.bot.call_action.side_effect = revoke
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped()
    forwarded.bot.call_action.assert_awaited_once()
    assert not forwarded.get_extra("qq_security_forward_part")


@pytest.mark.asyncio
async def test_forward_limits_are_visible_and_do_not_store_all_nodes(plugin, forwarded):
    forwarded.bot.call_action.return_value = {
        "messages": [
            {"sender": {"nickname": "x"}, "message": "x" * 20000} for _ in range(500)
        ]
    }
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    request = ProviderRequest(prompt=forwarded.message_str)
    await plugin.guard_request(forwarded, request)
    assert not forwarded.is_stopped()
    text = request.extra_user_content_parts[0].text
    assert len(text) < 20000 and "truncated" in text


@pytest.mark.asyncio
async def test_reply_to_forward_is_replaced_before_native_attachment_resolution(
    plugin, forwarded
):
    forwarded.message_obj.message = [Reply(id="456", chain=forwarded.get_messages())]
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert not forwarded.is_stopped()
    forwarded.bot.call_action.assert_awaited_once()
    assert forwarded.get_extra("qq_security_forward_read_only")
    assert all(isinstance(part, Plain) for part in forwarded.get_messages())


@pytest.mark.asyncio
async def test_forward_body_is_not_observed_as_admin_authored_text(plugin, forwarded):
    plugin.config["observe_admin_private"] = True
    records = []
    plugin.register_observer("test", records.append, admin_private=True)
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    messages = [record for record in records if record.kind == "message"]
    assert len(messages) == 1
    assert messages[0].text == ""
    assert "Forward" in messages[0].components


@pytest.mark.asyncio
async def test_read_budget_cancels_a_stuck_onebot_call(plugin, forwarded, monkeypatch):
    from astrbot_plugin_qq_security import forwards

    monkeypatch.setattr(forwards, "FORWARD_TIMEOUT", 0.01)
    cancelled = []

    async def wait_forever(**kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    forwarded.bot.call_action.side_effect = wait_forever
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped() and cancelled == [True]
    assert "超时" in forwarded.sent[-1].get_plain_text()
    assert "过期" not in forwarded.sent[-1].get_plain_text()


@pytest.mark.asyncio
async def test_slow_nested_forward_can_finish_after_twelve_seconds(plugin, forwarded):
    result = forwarded.bot.call_action.return_value

    async def slow_fetch(**kwargs):
        await asyncio.sleep(13)
        return result

    forwarded.bot.call_action.side_effect = slow_fetch
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert not forwarded.is_stopped()
    assert "周六打游戏" in forwarded.get_extra("qq_security_forward_part").text
    forwarded.bot.call_action.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "cards",
    [
        [Forward(id=str(index)) for index in range(4)],
        [Forward(id="https://example.invalid/private")],
    ],
)
async def test_invalid_card_or_excess_cards_never_fetch(plugin, forwarded, cards):
    forwarded.message_obj.message = cards
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped()
    forwarded.bot.call_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_revocation_before_model_hook_drops_forward_request(plugin, forwarded):
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    plugin.context._config["admins_id"] = []
    request = ProviderRequest(prompt=forwarded.message_str)
    await plugin.guard_request(forwarded, request)
    assert forwarded.is_stopped() and request.func_tool.empty()
    assert not request.extra_user_content_parts
    assert not forwarded.get_extra("qq_security_request_ready")


@pytest.mark.asyncio
async def test_unsupported_empty_tool_runner_mode_fails_with_actionable_hint(
    plugin, forwarded
):
    plugin.context._config["agent_runner"]["config"] = {
        "misc": {"tool_schema_mode": "skills_like"}
    }
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped()
    assert "full" in forwarded.sent[-1].get_plain_text()
    forwarded.bot.call_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_split_forwarded_secret_is_redacted_before_context_limit(
    plugin, forwarded
):
    forwarded.bot.call_action.return_value = {
        "messages": [
            {
                "sender": {"nickname": "测试隐私地址"},
                "message": [
                    {"type": "text", "data": {"text": "测试隐"}},
                    {"type": "text", "data": {"text": "私地址"}},
                ],
            }
        ]
    }
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    request = ProviderRequest(prompt=forwarded.message_str)
    await plugin.guard_request(forwarded, request)
    assert not forwarded.is_stopped()
    assert "测试隐私地址" not in request.extra_user_content_parts[0].text


@pytest.mark.asyncio
async def test_unresolved_quote_cannot_reopen_forward_fallback(plugin, forwarded):
    forwarded.message_obj.message = [Reply(id="456")]
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert forwarded.is_stopped()
    assert "直接" in forwarded.sent[-1].get_plain_text()
    forwarded.bot.call_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_resolved_quote_uses_validated_chain_without_remote_fallback(
    plugin, forwarded
):
    from astrbot.core.utils.quoted_message.extractor import QuotedMessageExtractor

    reply = Reply(
        id="456", chain=[Plain("normal reference")], message_str="normal reference"
    )
    forwarded.message_obj.message = [reply]
    forwarded.bot.api = SimpleNamespace(
        call_action=AsyncMock(side_effect=AssertionError("No remote re-read"))
    )
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert not forwarded.is_stopped()
    extractor = QuotedMessageExtractor(forwarded)
    assert "normal reference" in await extractor.text(reply)
    assert await extractor.images(reply) == []
    forwarded.bot.api.call_action.assert_not_awaited()
    assert plugin.is_computer_admin(forwarded)
