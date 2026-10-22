"""Check subprocess arguments, private task isolation and cancellation."""

import asyncio
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from astrbot_plugin_qq_security.admin_codex import AdminCodexRunner


@pytest.fixture
def runner(tmp_path):
    config = tmp_path / "bridge.json"
    config.write_text(
        json.dumps({"codex_path": "codex", "reasoning_effort": "medium"}),
        encoding="utf-8",
    )
    auth = tmp_path / "CODEX_HOME"
    auth.mkdir()
    (auth / "auth.json").write_text("{}", encoding="utf-8")
    return AdminCodexRunner(
        config, auth, tmp_path / "records", default_directory=tmp_path
    )


@pytest.mark.asyncio
async def test_full_execution_uses_stdin_and_never_reuses_another_session(
    runner, monkeypatch
):
    from astrbot_plugin_qq_security import admin_codex

    monkeypatch.setattr(admin_codex.shutil, "which", lambda value: "test-codex.exe")
    monkeypatch.setenv("CODEX_THREAD_ID", "unrelated-desktop-thread")
    events = [
        {"type": "item.completed", "item": {"type": "command_execution"}},
        {
            "type": "item.completed",
            "item": {"type": "agent_message", "text": "verified"},
        },
    ]
    process = AsyncMock()
    process.returncode = 0
    process.communicate.return_value = (
        "\n".join(map(json.dumps, events)).encode(),
        b"",
    )
    create = AsyncMock(return_value=process)
    monkeypatch.setattr(admin_codex.asyncio, "create_subprocess_exec", create)
    task = "Read my chosen file; $() and backticks are task text, not shell syntax."
    for actor in ("actor-a", "actor-b"):
        result = await runner.run(actor, task, model="model-test")
        assert result["ok"] is True
        assert result["output"] == "verified"
        assert result["commands_executed"] == 1
    args, kwargs = create.call_args
    assert "--dangerously-bypass-approvals-and-sandbox" in args
    assert "--ephemeral" in args and "--last" not in args and "resume" not in args
    assert task not in args and args[-1] == "-"
    assert task in process.communicate.call_args.kwargs["input"].decode()
    assert kwargs["env"]["CODEX_HOME"] == str(runner.codex_home)
    assert "CODEX_THREAD_ID" not in kwargs["env"]
    if os.name == "nt":
        assert kwargs["creationflags"] != 0
    assert len(list((runner.data_dir / "actor-a").glob("*.json"))) == 1
    assert len(list((runner.data_dir / "actor-b").glob("*.json"))) == 1


@pytest.mark.asyncio
async def test_timeout_stops_the_owned_process(runner, monkeypatch):
    from astrbot_plugin_qq_security import admin_codex

    monkeypatch.setattr(admin_codex.shutil, "which", lambda value: "test-codex.exe")
    process = AsyncMock()
    process.returncode = None

    async def blocked(**kwargs):
        await asyncio.Event().wait()

    process.communicate.side_effect = blocked
    monkeypatch.setattr(
        admin_codex.asyncio, "create_subprocess_exec", AsyncMock(return_value=process)
    )
    runner._stop = AsyncMock()
    runner.timeout = 0.01
    result = await runner.run("actor-a", "test timeout")
    assert result["ok"] is False
    runner._stop.assert_awaited_once_with(process)
    assert not runner.active


@pytest.mark.asyncio
async def test_cancellation_stops_the_owned_process(runner, monkeypatch):
    from astrbot_plugin_qq_security import admin_codex

    monkeypatch.setattr(admin_codex.shutil, "which", lambda value: "test-codex.exe")
    process = AsyncMock()
    process.returncode = None
    started = asyncio.Event()

    async def blocked(**kwargs):
        started.set()
        await asyncio.Event().wait()

    process.communicate.side_effect = blocked
    monkeypatch.setattr(
        admin_codex.asyncio, "create_subprocess_exec", AsyncMock(return_value=process)
    )
    runner._stop = AsyncMock()
    task = asyncio.create_task(runner.run("actor-a", "test cancellation"))
    await started.wait()
    assert (await runner.run("actor-a", "another task"))["ok"] is False
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    runner._stop.assert_awaited_once_with(process)
    assert not runner.active


@pytest.mark.asyncio
async def test_closed_runner_cannot_start_another_full_access_task(runner, monkeypatch):
    from astrbot_plugin_qq_security import admin_codex

    monkeypatch.setattr(admin_codex.shutil, "which", lambda value: "test-codex.exe")
    process = AsyncMock()
    process.returncode = 0
    process.communicate.return_value = (
        json.dumps(
            {"type": "item.completed", "item": {"type": "agent_message", "text": "ran"}}
        ).encode(),
        b"",
    )
    monkeypatch.setattr(
        admin_codex.asyncio, "create_subprocess_exec", AsyncMock(return_value=process)
    )
    await runner.close()
    result = await runner.run("actor-a", "must not run after shutdown")
    assert result["ok"] is False
    assert not runner.data_dir.exists()


@pytest.mark.asyncio
async def test_close_waits_for_pending_spawn_and_stops_its_process(runner, monkeypatch):
    from astrbot_plugin_qq_security import admin_codex

    monkeypatch.setattr(admin_codex.shutil, "which", lambda value: "test-codex.exe")
    spawn_started = asyncio.Event()
    release_spawn = asyncio.Event()
    process_stopped = asyncio.Event()

    async def communicate(**kwargs):
        await process_stopped.wait()
        return b"", b""

    process = SimpleNamespace(returncode=None, communicate=communicate)

    async def spawn(*args, **kwargs):
        spawn_started.set()
        await release_spawn.wait()
        return process

    async def stop(owned):
        owned.returncode = -15
        process_stopped.set()

    monkeypatch.setattr(admin_codex.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(runner, "_stop", stop)
    running = asyncio.create_task(runner.run("actor-a", "test pending spawn"))
    await spawn_started.wait()
    closing = asyncio.create_task(runner.close())
    try:
        await asyncio.sleep(0)
        assert not closing.done()
        release_spawn.set()
        await asyncio.wait_for(closing, 2)
        result = await asyncio.wait_for(running, 2)
        assert result["ok"] is False
        assert process.returncode == -15
        assert not runner.active
    finally:
        release_spawn.set()
        process_stopped.set()
        await asyncio.gather(running, closing, return_exceptions=True)
