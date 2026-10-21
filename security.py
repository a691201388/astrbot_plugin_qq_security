"""Deterministic permissions, disclosure controls and bounded local storage."""

import ipaddress
import os
import re
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Identity:
    platform: str
    account: str
    sender: str
    group: str = ""
    private: bool = True


class SecurityPolicy:
    def __init__(self, config):
        self.config = config

    def trusted(self, identity):
        allowed = self.config.get("computer_qq_whitelist", [])
        return (
            identity.platform == "aiocqhttp"
            and bool(re.fullmatch(r"[1-9][0-9]{4,19}", identity.sender))
            and identity.sender in {str(value) for value in allowed}
            and identity.private
            and not identity.group
        )

    def authorize(self, identity, capability):
        if capability in {"image", "meme"}:
            return None
        if capability not in {"workspace_read", "workspace_write", "workspace_list"}:
            return "This operation is not exposed to the bot."
        if self.config.get("emergency_stop", False):
            return "Computer operations are temporarily stopped."
        if not self.trusted(identity):
            return (
                "Computer operations require an explicitly allowed QQ private sender."
            )
        return None

    def redact(self, text):
        result = str(text or "")
        for term in self.config.get("sensitive_terms", []):
            if isinstance(term, str) and len(term.strip()) >= 2:
                result = result.replace(term, "[隐私信息已隐藏]")
        for pattern in (
            r"file://[^\s\"'<>，。！？]+",
            r"(?<![A-Za-z0-9])[A-Za-z]:[\\/][^\s\"'<>，。！？]+",
            r"\\\\[^\s\"'<>，。！？]+",
            r"(?<![A-Za-z0-9:/])/(?:Users|home|root|etc|var|opt|app|data|mnt|srv|tmp)(?:/[^\s\"'<>，。！？]+)?",
            r"\bsk-[A-Za-z0-9_-]{16,}\b",
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            r"(?i)\bBearer\s+[A-Za-z0-9._~-]{12,}",
        ):
            result = re.sub(pattern, "[敏感信息已隐藏]", result)
        for candidate in set(
            re.findall(
                r"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])|[0-9A-Fa-f]*:[0-9A-Fa-f:]+",
                result,
            )
        ):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            result = result.replace(candidate, "[IP已隐藏]")
        return result

    def validate_media_url(self, url):
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower()
            return (
                parsed.scheme == "https"
                and not parsed.username
                and not parsed.password
                and parsed.port in (None, 443)
                and any(
                    host == domain or host.endswith("." + domain)
                    for domain in (
                        "qpic.cn",
                        "multimedia.nt.qq.com",
                        "multimedia.nt.qq.com.cn",
                        "gtimg.cn",
                    )
                )
            )
        except (TypeError, ValueError):
            return False


class SafeWorkspace:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, name):
        """Validate a data-file path without allowing executable or device files.

        Args:
            name: Workspace-relative data-file name.

        Returns:
            Validated path inside the owned workspace.
        """
        path = PurePosixPath(str(name).replace("\\", "/"))
        if (
            not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or len(str(path)) > 240
        ):
            raise PermissionError("Only relative workspace paths are allowed.")
        for part in path.parts:
            if re.search(r'[<>:"|?*\x00-\x1f]', part) or part.endswith((".", " ")):
                raise PermissionError("Invalid workspace file name.")
            if part.split(".")[0].upper() in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }:
                raise PermissionError("Device files are not allowed.")
        if path.suffix.lower() not in {
            ".txt",
            ".md",
            ".csv",
            ".json",
            ".yaml",
            ".yml",
            ".log",
        }:
            raise PermissionError("Only text data files are allowed.")
        target = self.root.joinpath(*path.parts)
        current = self.root
        for part in path.parts:
            current /= part
            if current.is_symlink() or (
                hasattr(current, "is_junction") and current.is_junction()
            ):
                raise PermissionError("Linked paths are not allowed.")
        if not target.resolve().is_relative_to(self.root):
            raise PermissionError("Path is outside the workspace.")
        if target.exists() and (not target.is_file() or target.stat().st_nlink != 1):
            raise PermissionError("Only unlinked regular files are allowed.")
        return target

    def write(self, name, text):
        data = str(text).encode("utf-8")
        if len(data) > 64 * 1024:
            raise ValueError("File exceeds 64 KiB.")
        target = self._path(name)
        if not target.exists() and len(self.list_files()) >= 200:
            raise ValueError("Workspace file limit reached.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target = self._path(name)
        descriptor = os.open(
            target, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PermissionError("Linked or special files are not allowed.")
            handle.truncate(0)
            handle.write(data)
        return f"Saved {len(data)} bytes."

    def read(self, name):
        target = self._path(name)
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PermissionError("Linked or special files are not allowed.")
            data = handle.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            raise ValueError("File exceeds 64 KiB.")
        return data.decode("utf-8")

    def list_files(self):
        result = []
        for directory, folders, files in os.walk(self.root, followlinks=False):
            base = Path(directory)
            folders[:] = [
                name
                for name in folders
                if not (base / name).is_symlink()
                and not (
                    hasattr(base / name, "is_junction") and (base / name).is_junction()
                )
            ]
            for name in files:
                relative = (base / name).relative_to(self.root).as_posix()
                try:
                    self._path(relative)
                except (PermissionError, OSError):
                    continue
                result.append(relative)
                if len(result) >= 200:
                    return sorted(result)
        return sorted(result)


class UsageLedger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS usage(actor TEXT, day INTEGER, count INTEGER, last REAL, PRIMARY KEY(actor,day));
                CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY, actor TEXT, expires REAL);
                CREATE TABLE IF NOT EXISTS audit(time REAL, actor TEXT, action TEXT, outcome TEXT);
                CREATE TABLE IF NOT EXISTS messages(actor TEXT, bucket INTEGER, count INTEGER, PRIMARY KEY(actor,bucket));
            """)

    def check_message(self, actor, *, limit=10, now=None):
        """Atomically admit one chat request per sender into a minute bucket.

        Args:
            actor: Opaque sender key.
            limit: Maximum admitted model requests per minute.
            now: Optional timestamp supplied by a scheduler.
        """
        bucket = int((time.time() if now is None else now) // 60)
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT count FROM messages WHERE actor=? AND bucket=?", (actor, bucket)
            ).fetchone()
            count = row[0] if row else 0
            if count >= max(0, int(limit)):
                raise PermissionError("Message rate limit reached.")
            connection.execute(
                "INSERT OR REPLACE INTO messages VALUES(?,?,?)",
                (actor, bucket, count + 1),
            )
            connection.execute("DELETE FROM messages WHERE bucket < ?", (bucket - 5,))

    @contextmanager
    def reserve(self, actor, *, daily=20, cooldown=60, concurrent=2, now=None):
        timestamp = time.time() if now is None else float(now)
        day = int(timestamp // 86400)
        lease = secrets.token_hex(16)
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM leases WHERE expires <= ?", (timestamp,))
            row = connection.execute(
                "SELECT count,last FROM usage WHERE actor=? AND day=?", (actor, day)
            ).fetchone()
            count, last = row if row else (0, None)
            active = connection.execute("SELECT count(*) FROM leases").fetchone()[0]
            own = connection.execute(
                "SELECT count(*) FROM leases WHERE actor=?", (actor,)
            ).fetchone()[0]
            if (
                count >= max(0, int(daily))
                or (last is not None and timestamp - last < max(0, float(cooldown)))
                or active >= max(0, int(concurrent))
                or own
            ):
                raise PermissionError("Image request limit reached; please try later.")
            connection.execute(
                "INSERT OR REPLACE INTO usage VALUES(?,?,?,?)",
                (actor, day, count + 1, timestamp),
            )
            connection.execute(
                "INSERT INTO leases VALUES(?,?,?)", (lease, actor, timestamp + 300)
            )
            connection.execute("DELETE FROM usage WHERE day < ?", (day - 31,))
        try:
            yield
        finally:
            with sqlite3.connect(self.path, timeout=5) as connection:
                connection.execute("DELETE FROM leases WHERE id=?", (lease,))

    def audit(self, actor, action, outcome):
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute(
                "INSERT INTO audit VALUES(?,?,?,?)",
                (time.time(), actor[:64], action[:64], outcome[:32]),
            )
            connection.execute(
                "DELETE FROM audit WHERE rowid NOT IN (SELECT rowid FROM audit ORDER BY rowid DESC LIMIT 10000)"
            )
