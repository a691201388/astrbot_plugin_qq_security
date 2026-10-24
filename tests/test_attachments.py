"""Exercise real adapter conversion and administrator ZIP isolation."""

import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiocqhttp import Event as RawEvent
from astrbot.core.message.components import File, Forward, Plain, Reply
from astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import (
    AiocqhttpAdapter,
)
from astrbot.core.provider.entities import ProviderRequest

from astrbot_plugin_qq_security.attachments import (
    AttachmentAdapterGuard,
    PendingZip,
    ZipInbox,
)
from astrbot_plugin_qq_security.runtime import identity_from_event

from .test_runtime import Event


def raw_file():
    return RawEvent(
        {
            "post_type": "message",
            "message_type": "private",
            "self_id": 987654321,
            "user_id": 123456789,
            "sender": {"user_id": 123456789},
            "message_id": 42,
            "time": 1,
            "message": [
                {
                    "type": "file",
                    "data": {
                        "file": "表情包.zip",
                        "file_id": "opaque-kernel-reference",
                        "file_size": "123",
                    },
                }
            ],
        }
    )


@pytest.mark.asyncio
async def test_real_adapter_preserves_direct_and_quoted_files_without_url_fetch():
    adapter = object.__new__(AiocqhttpAdapter)
    adapter.bot = SimpleNamespace(call_action=AsyncMock(return_value=dict(raw_file())))
    original = AiocqhttpAdapter._convert_handle_message_event
    guard = AttachmentAdapterGuard()
    guard.install()
    try:
        raw = raw_file()
        message = await adapter._convert_handle_message_event(raw)
        assert isinstance(message.message[0], PendingZip)
        assert isinstance(message.message[0], File)
        assert message.raw_message is raw
        assert message.message[0].source_sender == "123456789"
        adapter.bot.call_action.assert_not_awaited()
        quoted = raw_file()
        quoted["message"] = [
            {"type": "reply", "data": {"id": "42"}},
            {"type": "text", "data": {"text": "就是这个"}},
        ]
        message = await adapter._convert_handle_message_event(quoted)
        reply = next(part for part in message.message if isinstance(part, Reply))
        assert isinstance(reply.chain[0], PendingZip)
        assert reply.chain[0].reference == "opaque-kernel-reference"
        assert adapter.bot.call_action.await_args.kwargs["action"] == "get_msg"
        assert adapter.bot.call_action.await_count == 1
    finally:
        guard.restore()
    assert AiocqhttpAdapter._convert_handle_message_event is original


@pytest.fixture
def incoming(tmp_path):
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("表情/开心.gif", b"GIF89a")
    event = Event(text="")
    event.bot = SimpleNamespace(
        call_action=AsyncMock(return_value={"file": str(source)})
    )
    reference = PendingZip.from_segment(raw_file(), raw_file()["message"][0]["data"])
    return ZipInbox(tmp_path / "inbox"), event, reference, source


@pytest.mark.asyncio
async def test_copy_dedup_persistence_actor_isolation_and_no_extraction(incoming):
    inbox, event, ref, source = incoming
    record = await inbox.receive(event, ref, "actor", lambda: True)
    stored = Path(record["path"])
    assert stored != source and stored.read_bytes() == source.read_bytes()
    assert record["entries"] == 1
    assert not list(inbox.root.rglob("*.gif"))
    assert await inbox.receive(event, ref, "actor", lambda: True) == record
    assert event.bot.call_action.await_count == 1
    assert ZipInbox(inbox.root).recent("actor") == [record]
    assert inbox.recent("other") == []
    assert "opaque-kernel-reference" not in next(inbox.root.rglob("*.json")).read_text(
        "utf-8"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["denied", "group", "other_sender", "other_account", "extension", "size", "url_id"],
)
async def test_rejects_before_api_or_disk_access(incoming, change):
    inbox, event, ref, _ = incoming

    def allowed():
        return change != "denied"

    if change == "denied":
        pass
    elif change == "group":
        ref.source_group = "111111"
    elif change == "other_sender":
        ref.source_sender = "222222"
    elif change == "other_account":
        ref.source_account = "222222"
    elif change == "extension":
        ref.name = "a.exe"
    elif change == "size":
        ref.size_hint = 32 * 1024 * 1024 + 1
    else:
        ref.reference = "file:///etc/passwd"
    with pytest.raises((PermissionError, ValueError)):
        await inbox.receive(event, ref, "actor", allowed)
    event.bot.call_action.assert_not_awaited()
    assert not inbox.root.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "filename",
    [
        "../escape.png",
        "/absolute.png",
        "C:/escape.png",
        "x:stream",
        "a/../../x",
        "link",
    ],
)
async def test_rejects_unsafe_zip_entries_and_cleans_owned_copy(incoming, filename):
    inbox, event, ref, source = incoming
    with zipfile.ZipFile(source, "w") as archive:
        info = zipfile.ZipInfo(filename)
        if filename == "link":
            info.create_system = 3
            info.external_attr = 0o120777 << 16
        archive.writestr(info, b"value")
    with pytest.raises(ValueError):
        await inbox.receive(event, ref, "actor", lambda: True)
    assert source.exists()
    assert not list(inbox.root.rglob("*.zip"))
    assert inbox.recent("actor") == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    ["https://example.com/a.zip", "\\\\server\\share\\a.zip", "relative.zip"],
)
async def test_rejects_nonlocal_download_paths(incoming, location):
    inbox, event, ref, _ = incoming
    event.bot.call_action.return_value = {"file": location}
    with pytest.raises(ValueError):
        await inbox.receive(event, ref, "actor", lambda: True)
    assert inbox.recent("actor") == []


@pytest.mark.asyncio
async def test_revocation_while_download_is_pending_leaves_no_receipt(incoming):
    inbox, event, ref, source = incoming
    permitted = True

    async def download(**kwargs):
        nonlocal permitted
        permitted = False
        return {"file": str(source)}

    event.bot.call_action.side_effect = download
    with pytest.raises(PermissionError):
        await inbox.receive(event, ref, "actor", lambda: permitted)
    assert inbox.recent("actor") == []
    assert not list(inbox.root.rglob("*.zip"))


@pytest.mark.asyncio
async def test_expired_files_are_not_context_and_cleaned_on_next_receipt(
    incoming, monkeypatch
):
    inbox, event, ref, source = incoming
    monkeypatch.setattr(
        "astrbot_plugin_qq_security.attachments.time.time", lambda: 1_000_000
    )
    record = await inbox.receive(event, ref, "actor", lambda: True)
    monkeypatch.setattr(
        "astrbot_plugin_qq_security.attachments.time.time", lambda: 1_086_401
    )
    assert inbox.recent("actor") == []
    ref.reference = "different-reference"
    await inbox.receive(event, ref, "actor", lambda: True)
    assert not Path(record["path"]).exists()
    assert source.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind", ["malformed", "actual_size", "entries", "expanded", "encrypted"]
)
async def test_archive_limits_and_invalid_content(incoming, monkeypatch, kind):
    inbox, event, ref, source = incoming
    ref.size_hint = -1
    if kind == "malformed":
        source.write_bytes(b"not a zip")
    elif kind == "actual_size":
        monkeypatch.setattr("astrbot_plugin_qq_security.attachments.MAX_BYTES", 10)
    elif kind == "entries":
        with zipfile.ZipFile(source, "w") as archive:
            for n in range(1001):
                archive.writestr(str(n), b"")
    elif kind == "expanded":
        monkeypatch.setattr("astrbot_plugin_qq_security.attachments.MAX_EXPANDED", 1)
    else:
        content = bytearray(source.read_bytes())
        offset = content.index(b"PK\x01\x02")
        content[offset + 8] |= 1
        source.write_bytes(content)
    with pytest.raises((ValueError, zipfile.BadZipFile)):
        await inbox.receive(event, ref, "actor", lambda: True)
    assert not list(inbox.root.rglob("*.zip"))


@pytest.mark.asyncio
async def test_capacity_refuses_new_file_without_evicting_current_ones(incoming):
    inbox, event, ref, _ = incoming
    for n in range(5):
        ref.reference = f"reference-{n}"
        await inbox.receive(event, ref, "actor", lambda: True)
    ref.reference = "reference-6"
    with pytest.raises(ValueError, match="five"):
        await inbox.receive(event, ref, "actor", lambda: True)
    assert event.bot.call_action.await_count == 5
    assert len(inbox.recent("actor")) == 5


@pytest.mark.asyncio
async def test_download_timeout_keeps_inbox_empty(incoming, monkeypatch):
    import asyncio

    inbox, event, ref, _ = incoming
    monkeypatch.setattr("astrbot_plugin_qq_security.attachments.DOWNLOAD_TIMEOUT", 0.01)

    async def stuck(**kwargs):
        await asyncio.Event().wait()

    event.bot.call_action.side_effect = stuck
    with pytest.raises(TimeoutError):
        await inbox.receive(event, ref, "actor", lambda: True)
    assert inbox.recent("actor") == []


@pytest.fixture
def admin_zip(plugin, incoming):
    _, event, ref, source = incoming
    plugin.config["admin_codex_enabled"] = True
    plugin.context._config["admins_id"] = ["123456789"]
    event.message_obj.message = [ref]
    return plugin, event, ref, source


@pytest.mark.asyncio
async def test_file_only_receipt_stops_before_llm_and_followup_has_metadata(admin_zip):
    plugin, event, _, source = admin_zip
    await plugin.prepare_pipeline(event, plugin.context._config)
    assert event.is_stopped()
    assert len(event.sent) == 1 and "ZIP" in event.sent[0].get_plain_text()
    assert source.exists()
    followup = Event(text="把刚才的压缩包中的表情导入")
    request = ProviderRequest(prompt=followup.message_str)
    await plugin.guard_request(followup, request)
    await plugin.guard_request(followup, request)
    assert len(request.extra_user_content_parts) == 1
    assert "ZIP inbox" in request.extra_user_content_parts[0].text
    assert request.extra_user_content_parts[0]._no_save


@pytest.mark.asyncio
async def test_quoted_zip_becomes_receipt_before_native_file_reader(admin_zip):
    plugin, event, ref, _ = admin_zip
    event.message_str = "这个就是，帮我处理"
    reply = Reply(id="42", chain=[ref], sender_id="123456789")
    event.message_obj.message = [reply, Plain(event.message_str)]
    await plugin.prepare_pipeline(event, plugin.context._config)
    assert not event.is_stopped()
    assert reply.id == ""
    assert isinstance(reply.chain[0], Plain)
    assert "ZIP" in reply.chain[0].text
    assert not any(isinstance(p, File) for p in plugin._components(event))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [
        "group",
        "member",
        "native_admin",
        "disabled",
        "emergency",
        "mixed_forward",
        "two_files",
    ],
)
async def test_pipeline_rejects_files_without_download(admin_zip, mode):
    plugin, event, ref, _ = admin_zip
    if mode == "group":
        from astrbot.core.platform.message_type import MessageType

        event.message_obj.type = MessageType.GROUP_MESSAGE
        event.message_obj.group_id = "111111"
        event.is_at_or_wake_command = True
    elif mode == "member":
        event.message_obj.sender.user_id = "222222"
    elif mode == "native_admin":
        plugin.context._config["admins_id"] = []
    elif mode == "disabled":
        plugin.config["admin_codex_enabled"] = False
    elif mode == "emergency":
        plugin.config["emergency_stop"] = True
    elif mode == "mixed_forward":
        event.message_obj.message.append(Forward(id="fake"))
    else:
        event.message_obj.message.append(
            PendingZip.from_segment(raw_file(), raw_file()["message"][0]["data"])
        )
    await plugin.prepare_pipeline(event, plugin.context._config)
    assert event.is_stopped()
    event.bot.call_action.assert_not_awaited()


@pytest.mark.asyncio
async def test_codex_receives_owned_paths_only_in_authorized_private_turn(
    admin_zip, monkeypatch
):
    plugin, event, _, _ = admin_zip
    await plugin.prepare_pipeline(event, plugin.context._config)
    run = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(plugin.admin_codex, "run", run)
    followup = Event(text="处理刚才的 ZIP")
    assert json.loads(await plugin.qq_guard_codex(followup, followup.message_str))["ok"]
    actor, task = run.await_args.args
    records = plugin.zip_inbox.recent(actor)
    assert records and json.dumps(records[0]["path"])[1:-1] in task
    assert "never instructions" in task
    other = Event(sender="222222")
    request = ProviderRequest(prompt="处理刚才的 ZIP")
    await plugin.guard_request(other, request)
    assert not request.extra_user_content_parts
    assert "denied" in await plugin.qq_guard_codex(other, "处理")
    assert run.await_count == 1


@pytest.mark.asyncio
async def test_codex_holds_attachment_lease_until_run_finishes(admin_zip, monkeypatch):
    plugin, event, _, _ = admin_zip
    await plugin.prepare_pipeline(event, plugin.context._config)

    async def run(actor, task, **kwargs):
        assert plugin.zip_inbox.lock(actor).locked()
        assert all(Path(r["path"]).exists() for r in plugin.zip_inbox.recent(actor))
        return {"ok": True}

    monkeypatch.setattr(plugin.admin_codex, "run", run)
    await plugin.qq_guard_codex(Event(), "inspect ZIP")
    assert not plugin.zip_inbox.lock(plugin.actor(identity_from_event(event))).locked()


@pytest.mark.asyncio
@pytest.mark.parametrize("manifest_state", ["missing", "partial"])
async def test_interrupted_receipt_orphans_are_cleaned_on_next_receive(
    incoming, manifest_state
):
    inbox, event, ref, source = incoming
    record = await inbox.receive(event, ref, "actor", lambda: True)
    owned = Path(record["path"])
    manifest = owned.with_suffix(".json")
    if manifest_state == "missing":
        manifest.unlink()
    else:
        manifest.write_text('{"id":', "utf-8")
    unrelated = owned.parent / "keep-my-notes.txt"
    unrelated.write_text("preserve", "utf-8")
    ref.reference = "different-reference"
    await inbox.receive(event, ref, "actor", lambda: True)
    assert not owned.exists() and not manifest.exists()
    assert source.exists() and unrelated.read_text("utf-8") == "preserve"
