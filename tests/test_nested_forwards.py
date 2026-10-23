"""Bounded nested references and explicitly woken group forward reading."""

import json
from types import SimpleNamespace

import pytest
from astrbot.core.agent.tool import FunctionTool, ToolSet
from astrbot.core.message.components import At, Forward, Plain, Reply
from astrbot.core.platform.message_type import MessageType
from astrbot.core.provider.entities import ProviderRequest


def payload(text, *nested):
    return {
        "messages": [
            {
                "sender": {"nickname": "Untrusted speaker"},
                "message": [{"type": "text", "data": {"text": text}}, *nested],
            }
        ]
    }


def ref(value):
    return {"type": "forward", "data": {"id": value}}


def reference_data(event):
    return json.loads(
        event.get_extra("qq_security_forward_part")
        .text.split("\n", 1)[1]
        .rsplit("\n", 1)[0]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", [0, 1, 3, 5, 99])
async def test_depth_limit_counts_only_nested_levels(plugin, forwarded, depth):
    plugin.config["forward_max_depth"] = depth
    forwarded.message_obj.message = [Forward(id="0")]

    async def fetch(**kwargs):
        index = int(kwargs["message_id"])
        return payload(f"text-{index}", ref(str(index + 1)))

    forwarded.bot.call_action.side_effect = fetch
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    assert not forwarded.is_stopped()
    effective_depth = min(depth, 5)
    data = reference_data(forwarded)
    assert [r["depth"] for r in data["records"]] == list(range(effective_depth + 1))
    assert forwarded.bot.call_action.await_count == effective_depth + 1
    assert "层数" in str(data["notices"])
    assert data["truncated"] is True
    assert data["records"][0]["parent"] is None
    assert all(r["parent"] == i - 1 for i, r in enumerate(data["records"]) if i)


@pytest.mark.asyncio
async def test_cycle_and_duplicate_references_fetch_once(plugin, forwarded):
    graph = {
        "synthetic-forward-id": payload("root", ref("child"), ref("child")),
        "child": payload("child text", ref("synthetic-forward-id")),
    }
    forwarded.bot.call_action.side_effect = lambda **kw: graph[kw["message_id"]]
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert len(data["records"]) == 2
    assert forwarded.bot.call_action.await_count == 2
    assert "重复" in str(data["notices"])


@pytest.mark.asyncio
async def test_inline_nodes_share_depth_and_record_budgets(plugin, forwarded):
    child = {
        "type": "node",
        "data": {
            "name": "Child",
            "content": [
                {"type": "text", "data": {"text": "inline child"}},
                {"type": "image", "data": {"url": "http://127.0.0.1/secret"}},
            ],
        },
    }
    forwarded.bot.call_action.return_value = payload("root", child)
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert [r["depth"] for r in data["records"]] == [0, 1]
    assert data["records"][1]["sender"] == "Child"
    assert "inline child" in data["records"][1]["text"]
    assert "127.0.0.1" not in str(data)
    forwarded.bot.call_action.assert_awaited_once()


@pytest.mark.asyncio
async def test_total_fetch_limit_bounds_wide_nested_forwards(plugin, forwarded):
    async def fetch(**kwargs):
        if kwargs["message_id"] == "synthetic-forward-id":
            return payload("root", *(ref(f"child-{i}") for i in range(50)))
        return payload(kwargs["message_id"])

    forwarded.bot.call_action.side_effect = fetch
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert forwarded.bot.call_action.await_count == 12
    assert "读取次数" in str(data["notices"])
    assert data["truncated"]


@pytest.mark.asyncio
async def test_nested_failure_keeps_root_and_other_children(plugin, forwarded):
    async def fetch(**kwargs):
        if kwargs["message_id"] == "synthetic-forward-id":
            return payload("root", ref("expired"), ref("good"))
        if kwargs["message_id"] == "expired":
            raise RuntimeError("expired")
        return payload("readable child")

    forwarded.bot.call_action.side_effect = fetch
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert "readable child" in str(data)
    assert "失败" in str(data["notices"])
    assert not forwarded.is_stopped()


@pytest.fixture
def group_forward(plugin, forwarded):
    forwarded.message_obj.group_id = "555555"
    forwarded.message_obj.type = MessageType.GROUP_MESSAGE
    forwarded.message_obj.sender.user_id = "999999999"
    forwarded.is_at_or_wake_command = True
    plugin.config["forward_group_ids"] = ["555555"]
    return forwarded


@pytest.mark.asyncio
@pytest.mark.parametrize("quoted", [False, True])
async def test_woken_group_member_can_read_but_has_no_computer_tools(
    plugin, group_forward, quoted
):
    if quoted:
        group_forward.message_obj.message = [
            Reply(id="456", chain=group_forward.get_messages()),
            At(qq=group_forward.get_self_id()),
            Plain("看看这个转发"),
        ]
        group_forward.message_str = "看看这个转发"
    await plugin.prepare_pipeline(group_forward, plugin.context._config)
    assert not group_forward.is_stopped()
    assert not plugin.is_computer_admin(group_forward)
    assert not any(
        isinstance(p, (Forward, Reply)) for p in group_forward.get_messages()
    )
    tools = ToolSet(
        [
            FunctionTool(
                name="qq_guard_codex",
                description="test",
                parameters={"type": "object"},
                handler_module_path="data.plugins.astrbot_plugin_qq_security.main",
            )
        ]
    )
    request = ProviderRequest(prompt=group_forward.message_str, func_tool=tools)
    await plugin.guard_request(group_forward, request)
    assert not group_forward.is_stopped()
    assert request.func_tool.empty()
    assert "周六打游戏" in str(await request.assemble_context())
    assert request.extra_user_content_parts[0]._no_save
    assert plugin.config.get("observe_groups", []) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["unwoken", "other_group", "false_identity"])
async def test_unapproved_group_scope_does_not_fetch(plugin, group_forward, mode):
    if mode == "unwoken":
        group_forward.is_at_or_wake_command = False
    elif mode == "other_group":
        group_forward.message_obj.group_id = "666666"
    else:
        group_forward.message_obj.sender.user_id = "Admin"
    await plugin.prepare_pipeline(group_forward, plugin.context._config)
    assert group_forward.is_stopped()
    group_forward.bot.call_action.assert_not_awaited()
    if mode == "unwoken":
        assert not group_forward.sent


@pytest.mark.asyncio
async def test_group_revocation_during_nested_fetch_stops_further_reads(
    plugin, group_forward
):
    calls = []

    async def fetch(**kwargs):
        current = kwargs["message_id"]
        calls.append(current)
        if current == "synthetic-forward-id":
            return payload("root", ref("child"), ref("later"))
        plugin.config["forward_group_ids"] = []
        return payload("secret child")

    group_forward.bot.call_action.side_effect = fetch
    await plugin.prepare_pipeline(group_forward, plugin.context._config)
    assert group_forward.is_stopped()
    assert calls == ["synthetic-forward-id", "child"]
    assert not group_forward.get_extra("qq_security_forward_part")


@pytest.mark.asyncio
async def test_forward_quota_is_checked_before_external_reads(plugin, group_forward):
    plugin.config["chat_messages_per_minute"] = 0
    await plugin.prepare_pipeline(group_forward, plugin.context._config)
    assert group_forward.is_stopped()
    group_forward.bot.call_action.assert_not_awaited()
    assert "频繁" in group_forward.sent[-1].get_plain_text()


@pytest.mark.asyncio
@pytest.mark.parametrize("wake", ["at", "prefix", "none"])
async def test_native_wake_stage_controls_group_forward_fetch(
    plugin, group_forward, monkeypatch, wake
):
    from astrbot.core.pipeline.waking_check.stage import WakingCheckStage
    from astrbot.core.star.star_handler import star_handlers_registry

    monkeypatch.setattr(
        star_handlers_registry, "get_handlers_by_event_type", lambda *a, **kw: []
    )
    stage = WakingCheckStage()
    stage.ctx = SimpleNamespace(
        astrbot_config={"admins_id": [], "wake_prefix": ["/"], "plugin_set": ["*"]}
    )
    stage.friend_message_needs_wake_prefix = False
    stage.ignore_bot_self_message = stage.ignore_at_all = (
        stage.disable_builtin_commands
    ) = False
    stage._umo_auto_name_recorder = SimpleNamespace(schedule=lambda event: None)
    group_forward.is_at_or_wake_command = False
    card = group_forward.get_messages()[0]
    group_forward.message_str = "/看看这个转发" if wake == "prefix" else "看看这个转发"
    group_forward.message_obj.message = [
        Reply(id="456", chain=[card]),
        Plain(group_forward.message_str),
    ]
    if wake == "at":
        group_forward.message_obj.message.append(At(qq=group_forward.get_self_id()))
    await stage.process(group_forward)
    if not group_forward.is_stopped():
        await plugin.prepare_pipeline(group_forward, plugin.context._config)
    if wake == "none":
        group_forward.bot.call_action.assert_not_awaited()
        assert not group_forward.sent
    else:
        assert not group_forward.is_stopped()
        group_forward.bot.call_action.assert_awaited_once()
        assert group_forward.get_extra("qq_security_forward_part")


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", ["records", "text", "segments"])
@pytest.mark.parametrize("embedded", [False, True])
async def test_nested_content_shares_all_outer_budgets(
    plugin, forwarded, limit, embedded
):
    from astrbot_plugin_qq_security.forwards import MAX_RECORDS, MAX_TEXT

    text = "x" * (MAX_TEXT // 2) if limit == "text" else "child"
    count = 150 if limit == "records" else 3
    child_nodes = [payload(text)["messages"][0] for _ in range(count)]
    if limit == "segments":
        child_nodes = [
            payload("", *({"type": "face"} for _ in range(1100)))["messages"][0]
        ]
    child = ref("child")
    if embedded:
        child["data"]["content"] = child_nodes
    graph = {
        "synthetic-forward-id": payload("root", child, ref("later")),
        "child": {"messages": child_nodes},
        "later": payload("must not fetch"),
    }
    forwarded.bot.call_action.side_effect = lambda **kw: graph[kw["message_id"]]
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert not forwarded.is_stopped()
    assert forwarded.bot.call_action.await_count == (1 if embedded else 2)
    assert len(data["records"]) <= MAX_RECORDS
    assert sum(len(r["text"]) for r in data["records"]) <= MAX_TEXT
    assert data["truncated"]


@pytest.mark.asyncio
@pytest.mark.parametrize("depth", [0, 1, 3])
async def test_napcat_embedded_forward_uses_returned_body_not_inner_id(
    plugin, forwarded, depth
):
    plugin.config["forward_max_depth"] = depth
    inner = ref("12345")
    inner["data"]["content"] = payload("deep text 测试隐私地址")["messages"]
    middle = ref("67890")
    middle["data"]["content"] = payload("middle text", inner)["messages"]

    async def fetch(**kwargs):
        if kwargs["message_id"] == "synthetic-forward-id":
            return payload("outer text", middle)
        return {"status": "failed", "retcode": 200, "message": "Cannot fetch inner ID"}

    forwarded.bot.call_action.side_effect = fetch
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert [r["depth"] for r in data["records"]] == list(range(min(depth, 2) + 1))
    assert ("deep text" in str(data)) == (depth >= 2)
    assert "测试隐私地址" not in str(data)
    assert data["truncated"] == (depth < 2)
    forwarded.bot.call_action.assert_awaited_once()


@pytest.mark.asyncio
async def test_embedded_forward_duplicate_and_reference_cycle_are_skipped(
    plugin, forwarded
):
    child = ref("12345")
    child["data"]["content"] = payload("inner body", ref("synthetic-forward-id"))[
        "messages"
    ]
    forwarded.bot.call_action.return_value = payload("root", child, child, ref("12345"))
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert len(data["records"]) == 2
    assert "inner body" in str(data)
    assert "重复或循环" in str(data["notices"])
    forwarded.bot.call_action.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("inline", [[], None])
async def test_empty_embedded_forward_still_uses_reference_lookup(
    plugin, forwarded, inline
):
    child = ref("child")
    child["data"]["content"] = inline
    graph = {
        "synthetic-forward-id": payload("root", child),
        "child": payload("looked up child"),
    }
    forwarded.bot.call_action.side_effect = lambda **kw: graph[kw["message_id"]]
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert "looked up child" in str(data)
    assert forwarded.bot.call_action.await_count == 2


@pytest.mark.asyncio
async def test_failed_inner_lookup_does_not_hide_later_embedded_body(plugin, forwarded):
    child = ref("12345")
    child["data"]["content"] = payload("available inner body")["messages"]

    async def fetch(**kwargs):
        if kwargs["message_id"] == "synthetic-forward-id":
            return payload("root", ref("12345"), ref("12345"), child, child)
        return {"status": "failed", "retcode": 200}

    forwarded.bot.call_action.side_effect = fetch
    await plugin.prepare_pipeline(forwarded, plugin.context._config)
    data = reference_data(forwarded)
    assert len(data["records"]) == 2
    assert "available inner body" in str(data)
    assert forwarded.bot.call_action.await_count == 2
