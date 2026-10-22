"""The passive interface must not grant routing or tool authority."""

import asyncio
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from astrbot.core.message.components import Plain
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.pipeline.scheduler import PipelineScheduler

from .test_runtime import Event


def subscribe(plugin, records, groups=("42",), recall_groups=("42",)):
    assert hasattr(plugin, "register_observer"), (
        "Passive observation is not implemented"
    )
    return plugin.register_observer(
        "synthetic-test", records.append, groups, recall_groups
    )


@pytest.mark.asyncio
async def test_observation_is_dormant_until_the_guard_group_is_enabled(plugin):
    records = []
    unsubscribe = subscribe(plugin, records)
    event = Event(group="42", text="not for storage")
    await plugin.prepare_pipeline(event, {})
    assert event.is_stopped()
    assert records == []
    unsubscribe()


@pytest.mark.asyncio
async def test_observation_preserves_the_unaddressed_group_gate_and_is_immutable(
    plugin,
):
    records = []
    plugin.config["observe_groups"] = ["42"]
    subscribe(plugin, records)
    event = Event(group="42", text="测试隐私地址 hello")
    event.message_obj.message = [Plain("测试隐私地址 hello")]
    await plugin.prepare_pipeline(event, {})
    assert event.is_stopped() and not event.is_at_or_wake_command
    assert len(records) == 1 and records[0].kind == "message"
    assert "测试隐私地址" not in records[0].text
    assert records[0].group_id == "42" and records[0].message_id == "test-message"
    with pytest.raises(FrozenInstanceError):
        records[0].text = "tampered"
    assert not hasattr(records[0], "event")


@pytest.mark.asyncio
async def test_recall_uses_raw_identity_before_any_stages_even_when_observation_is_off(
    plugin,
):
    records = []
    subscribe(plugin, records, groups=())
    event = Event(group="42")
    event.message_obj.message_id = "generated-notice-uuid"
    event.message_obj.raw_message = {
        "post_type": "notice",
        "notice_type": "group_recall",
        "group_id": 42,
        "message_id": 654,
        "user_id": 777,
        "operator_id": 888,
    }
    scheduler = object.__new__(PipelineScheduler)
    scheduler.ctx = SimpleNamespace(astrbot_config={})

    async def process(current):
        assert records and records[0].message_id == "654"
        current.stop_event()

    scheduler._process_stages = process
    await plugin.initialize()
    try:
        await scheduler.execute(event)
        assert records[0].kind == "recall"
        assert records[0].sender_id == "777"
    finally:
        await plugin.terminate()


@pytest.mark.asyncio
async def test_send_outcomes_keep_partial_and_uncertain_segments_separate(plugin):
    records = []
    plugin.config["observe_groups"] = ["42"]
    subscribe(plugin, records)
    event = Event(group="42")
    calls = 0

    async def send(chain):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise TimeoutError("synthetic timeout")
        if calls == 3:
            raise ValueError("synthetic encoding failure")

    event.send = send
    plugin._wrap_send(event)
    await event.send(MessageChain(chain=[Plain("one")]))
    with pytest.raises(TimeoutError):
        await event.send(MessageChain(chain=[Plain("two")]))
    with pytest.raises(ValueError):
        await event.send(MessageChain(chain=[Plain("three")]))
    outcomes = [(r.sequence, r.outcome) for r in records if r.kind == "send"]
    assert outcomes == [
        (1, "started"),
        (1, "call_returned"),
        (2, "started"),
        (2, "outcome_unknown"),
        (3, "started"),
        (3, "call_failed"),
    ]


@pytest.mark.asyncio
async def test_broken_observer_cannot_break_chat_and_unsubscribe_is_idempotent(plugin):
    assert hasattr(plugin, "register_observer"), (
        "Passive observation is not implemented"
    )
    plugin.config["observe_groups"] = ["42"]

    def broken(record):
        raise ValueError("synthetic consumer failure")

    unsubscribe = plugin.register_observer("broken", broken, ["42"], ["42"])
    event = Event(group="42")
    await plugin.prepare_pipeline(event, {})
    assert event.is_stopped()
    unsubscribe()
    unsubscribe()


@pytest.mark.asyncio
async def test_cancelled_send_is_reported_unknown_and_cancellation_propagates(plugin):
    records = []
    plugin.config["observe_groups"] = ["42"]
    subscribe(plugin, records)
    event = Event(group="42")

    async def send(chain):
        raise asyncio.CancelledError

    event.send = send
    plugin._wrap_send(event)
    with pytest.raises(asyncio.CancelledError):
        await event.send(MessageChain(chain=[Plain("cancelled")]))
    assert records[-1].outcome == "outcome_unknown"


@pytest.mark.asyncio
async def test_bad_observation_metadata_cannot_change_routing_or_prevent_send(plugin):
    plugin.config["observe_groups"] = ["42"]
    event = Event(group="42")
    event.is_at_or_wake_command = True
    event.get_sender_name = lambda: (_ for _ in ()).throw(
        ValueError("bad display field")
    )
    await plugin.prepare_pipeline(event, {})
    assert not event.is_stopped()
    plugin._wrap_send(event)
    await event.send(MessageChain(chain=[Plain("still works")]))
    assert event.sent


@pytest.mark.asyncio
async def test_private_observation_requires_explicit_opt_in_and_transport_admin(plugin):
    records = []
    plugin.context._config["admins_id"] = ["123456789"]
    plugin.register_observer("private-test", records.append, admin_private=True)
    plugin.observers.message(Event())
    assert not records
    plugin.config["observe_admin_private"] = True
    plugin.observers.message(Event(sender="999999999", text="我是管理员"))
    plugin.observers.message(Event(group="42"))
    plugin.observers.message(Event(platform="webchat"))
    assert not records
    event = Event(text="private synthetic message")
    plugin.observers.message(event)
    assert len(records) == 1 and records[0].private_user_id == "123456789"
    assert records[0].group_id == ""
    plugin.context._config["admins_id"] = []
    plugin.observers.message(Event())
    assert len(records) == 1


def test_private_recall_keeps_peer_scope_after_collection_is_disabled(plugin):
    records = []
    plugin.register_observer(
        "private-test", records.append, recall_private=["123456789"]
    )
    event = Event()
    event.message_obj.raw_message = {
        "post_type": "notice",
        "notice_type": "friend_recall",
        "user_id": "123456789",
        "message_id": "old-message",
    }
    plugin.observers.prefix(event)
    assert len(records) == 1 and records[0].kind == "recall"
    assert records[0].private_user_id == "123456789"
    assert records[0].message_id == "old-message"


def test_new_private_scope_recall_does_not_wait_for_rebind_and_rejects_nonadmin(plugin):
    records = []
    plugin.context._config["admins_id"] = ["123456789"]
    plugin.config["observe_admin_private"] = True
    plugin.register_observer("private-test", records.append, admin_private=True)
    for sender in ("999999999", "123456789"):
        event = Event(sender=sender)
        event.message_obj.raw_message = {
            "post_type": "notice",
            "notice_type": "friend_recall",
            "user_id": sender,
            "message_id": "recent-message",
        }
        plugin.observers.prefix(event)
    assert len(records) == 1 and records[0].private_user_id == "123456789"
