"""Behavioral regressions for permission, disclosure and storage boundaries."""

import sqlite3

import pytest

from astrbot_plugin_qq_security.security import (
    Identity,
    SafeWorkspace,
    SecurityPolicy,
    UsageLedger,
)


def test_only_an_explicit_qq_private_identity_can_use_workspace_tools():
    policy = SecurityPolicy({"computer_qq_whitelist": ["123456789"]})
    owner = Identity("aiocqhttp", "987654321", "123456789")
    assert policy.authorize(owner, "workspace_write") is None
    for identity in (
        Identity("aiocqhttp", "987654321", "999999999"),
        Identity("aiocqhttp", "987654321", "123456789", "777777", False),
        Identity("webchat", "webchat", "123456789"),
        Identity("aiocqhttp", "987654321", ""),
    ):
        assert policy.authorize(identity, "workspace_write") is not None


def test_whitelist_never_grants_arbitrary_execution_or_plugin_management():
    policy = SecurityPolicy({"computer_qq_whitelist": ["123456789"]})
    owner = Identity("aiocqhttp", "987654321", "123456789")
    for capability in ("shell", "python", "browser", "plugin_uninstall", "unknown"):
        assert policy.authorize(owner, capability) is not None
    assert policy.authorize(owner, "image") is None


def test_empty_whitelist_and_emergency_stop_fail_closed():
    owner = Identity("aiocqhttp", "987654321", "123456789")
    assert SecurityPolicy({}).authorize(owner, "workspace_read") is not None
    policy = SecurityPolicy(
        {"computer_qq_whitelist": ["123456789"], "emergency_stop": True}
    )
    assert policy.authorize(owner, "workspace_read") is not None


@pytest.mark.parametrize(
    "secret",
    [
        r"C:\Users\someone\.codex\auth.json",
        "E:/agent/AstrBot/data/cmd_config.json",
        "file:///C:/private/passwords.txt",
        "192.168.20.10",
        "2001:db8:abcd::1",
        "sk-abcdefghijklmnopqrstuvwxyz1234567890",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZWNyZXQifQ.abcdefghijklmnop",
        "上海市某路123号",
    ],
)
def test_private_material_is_redacted_without_removing_normal_chat(secret):
    policy = SecurityPolicy({"sensitive_terms": ["上海市某路123号"]})
    output = policy.redact("你好，位置或资料是 " + secret + "，今天吃什么？")
    assert secret not in output
    assert "你好" in output and "今天吃什么" in output


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:6185/api/config",
        "https://[::1]/private",
        "http://169.254.169.254/latest/meta-data/",
        "file:///C:/private/auth.json",
        "https://gchat.qpic.cn.evil.example/a.png",
        "https://gchat.qpic.cn@evil.example/a.png",
        "https://gchat.qpic.cn:6185/a.png",
    ],
)
def test_untrusted_media_cannot_target_local_or_lookalike_hosts(url):
    assert not SecurityPolicy({}).validate_media_url(url)


def test_official_qq_media_remains_usable():
    assert SecurityPolicy({}).validate_media_url(
        "https://gchat.qpic.cn/gchatpic_new/a.png"
    )


def test_workspace_round_trip_and_escape_protection(tmp_path):
    workspace = SafeWorkspace(tmp_path / "workspace")
    workspace.write("notes/today.md", "hello")
    assert workspace.read("notes/today.md") == "hello"
    assert "notes/today.md" in workspace.list_files()
    for name in (
        "../config.json",
        "/etc/passwd",
        r"C:\private\auth.json",
        "code.py",
        "x.cmd",
        "file.txt:stream",
    ):
        with pytest.raises((ValueError, PermissionError)):
            workspace.write(name, "bad")
    assert not (tmp_path / "config.json").exists()


def test_workspace_rejects_a_hardlink_to_an_outside_file(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "private.txt"
    outside.write_text("private", encoding="utf-8")
    (root / "linked.txt").hardlink_to(outside)
    with pytest.raises(PermissionError):
        SafeWorkspace(root).read("linked.txt")


def test_limits_survive_reload_and_concurrent_reservations(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    first = UsageLedger(path)
    with first.reserve("alice", daily=2, cooldown=30, concurrent=1, now=1000):
        with pytest.raises(PermissionError):
            with UsageLedger(path).reserve(
                "bob", daily=2, cooldown=0, concurrent=1, now=1001
            ):
                pass
    with pytest.raises(PermissionError):
        with UsageLedger(path).reserve("alice", daily=2, cooldown=30, now=1010):
            pass
    with UsageLedger(path).reserve("alice", daily=2, cooldown=30, now=1040):
        pass
    with pytest.raises(PermissionError):
        with UsageLedger(path).reserve("alice", daily=2, cooldown=0, now=1080):
            pass


def test_lease_is_released_when_generation_fails(tmp_path):
    ledger = UsageLedger(tmp_path / "ledger.sqlite3")
    with pytest.raises(RuntimeError):
        with ledger.reserve("alice", cooldown=0, concurrent=1, now=1000):
            raise RuntimeError("generation failed")
    with ledger.reserve("bob", cooldown=0, concurrent=1, now=1001):
        pass


def test_audit_contains_no_message_or_file_contents(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    UsageLedger(path).audit("opaque-actor", "workspace_read", "denied")
    with sqlite3.connect(path) as connection:
        rows = connection.execute("SELECT actor,action,outcome FROM audit").fetchall()
    assert rows == [("opaque-actor", "workspace_read", "denied")]


def test_message_rate_limits_survive_restart_and_are_per_sender(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    ledger = UsageLedger(path)
    ledger.check_message("alice", limit=2, now=1000)
    UsageLedger(path).check_message("alice", limit=2, now=1001)
    with pytest.raises(PermissionError):
        UsageLedger(path).check_message("alice", limit=2, now=1002)
    UsageLedger(path).check_message("bob", limit=2, now=1002)
    UsageLedger(path).check_message("alice", limit=2, now=1060)
