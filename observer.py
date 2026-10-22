"""Bounded passive observations for trusted in-process consumers."""

import inspect
import re
import time
import uuid
from dataclasses import dataclass, replace
from functools import wraps

from astrbot.core.platform.message_type import MessageType


def passive(method):
    """Observation failure must not change the guarded operation's outcome."""

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as error:
            self.plugin.logger.warning(
                "Passive observation unavailable: %s", type(error).__name__
            )
            return None

    return wrapped


@dataclass(frozen=True)
class Observation:
    kind: str
    platform_id: str
    self_id: str
    group_id: str
    event_id: str
    received_at: float
    message_id: str = ""
    sender_id: str = ""
    sender_name: str = ""
    text: str = ""
    reply_to: str = ""
    mentions: tuple[str, ...] = ()
    components: tuple[str, ...] = ()
    sequence: int = 0
    outcome: str = ""
    truncated: bool = False
    private_user_id: str = ""


class ObserverHub:
    """Emit bounded records without exposing mutable events or routing methods."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.sinks = {}

    def register(
        self,
        name,
        callback,
        groups,
        recall_groups,
        *,
        admin_private=False,
        recall_private=(),
    ):
        if not callable(callback) or inspect.iscoroutinefunction(callback):
            raise TypeError("Observers must be synchronous callbacks.")
        entry = [
            callback,
            frozenset(map(str, groups)),
            frozenset(map(str, recall_groups)),
            0,
            bool(admin_private),
            frozenset(map(str, recall_private)),
        ]
        self.sinks[str(name)] = entry

        def unsubscribe():
            if self.sinks.get(str(name)) is entry:
                self.sinks.pop(str(name), None)

        return unsubscribe

    def allows(self, event):
        """Check current transport identity before preparing any observed text.

        Args:
            event: The authenticated inbound QQ event, including its config route.

        Returns:
            Whether the enabled group or explicit private-admin scope permits it.
        """
        if event.get_platform_name() != "aiocqhttp":
            return False
        group = str(event.get_group_id() or "")
        if group:
            return group in set(map(str, self.plugin.config.get("observe_groups", [])))
        sender = str(event.get_sender_id())
        if (
            not self.plugin.config.get("observe_admin_private", False)
            or event.get_message_type() != MessageType.FRIEND_MESSAGE
            or not re.fullmatch(r"[1-9][0-9]{4,19}", sender)
        ):
            return False
        native = self.plugin.context.get_config(
            event.get_extra("qq_security_original_umo") or event.unified_msg_origin
        )
        return sender in set(map(str, native.get("admins_id", [])))

    def stamp(self, event):
        if not event.get_extra("qq_security_event_id"):
            event.set_extra("qq_security_event_id", uuid.uuid4().hex)
            event.set_extra("qq_security_received_at", time.time())

    def base(self, event, kind):
        self.stamp(event)
        return Observation(
            kind=kind,
            platform_id=str(event.get_platform_id()),
            self_id=str(event.get_self_id()),
            group_id=str(event.get_group_id() or ""),
            event_id=event.get_extra("qq_security_event_id"),
            received_at=event.get_extra("qq_security_received_at"),
            message_id=str(event.message_obj.message_id),
            sender_id=str(event.get_sender_id()),
            private_user_id=(
                str(event.get_sender_id()) if not event.get_group_id() else ""
            ),
        )

    def emit(self, record):
        enabled = {str(g) for g in self.plugin.config.get("observe_groups", [])}
        for name, entry in list(self.sinks.items()):
            callback, groups, recalls, failures, admin_private, private_recalls = entry
            if record.group_id:
                permitted = record.group_id in (
                    recalls if record.kind == "recall" else groups & enabled
                )
            else:
                permitted = bool(record.private_user_id) and (
                    (
                        record.private_user_id in private_recalls
                        or (
                            admin_private
                            and self.plugin.config.get("observe_admin_private", False)
                        )
                    )
                    if record.kind == "recall"
                    else admin_private
                    and self.plugin.config.get("observe_admin_private", False)
                )
            if not permitted or failures >= 3:
                continue
            if record.kind == "message" and record.private_user_id:
                # Keep deletion delivery even if admin access is revoked before rebind.
                entry[5] = private_recalls | {record.private_user_id}
            try:
                returned = callback(record)
                if inspect.isawaitable(returned):
                    if inspect.iscoroutine(returned):
                        returned.close()
                    raise TypeError("Observer returned an awaitable.")
                entry[3] = 0
            except Exception as error:
                entry[3] += 1
                self.plugin.logger.warning(
                    "Passive observer %s failed: %s", name, type(error).__name__
                )

    @passive
    def prefix(self, event):
        self.stamp(event)
        if event.get_platform_name() != "aiocqhttp":
            return
        raw = getattr(event.message_obj, "raw_message", None)
        if not isinstance(raw, dict) or raw.get("post_type") != "notice":
            return
        notice = raw.get("notice_type")
        if (
            notice not in {"group_recall", "friend_recall"}
            or raw.get("message_id") is None
        ):
            return
        if event.get_extra("qq_security_recall_emitted"):
            return
        if notice == "friend_recall":
            peer = str(raw.get("user_id", ""))
            known = any(peer in entry[5] for entry in self.sinks.values())
            if not known and not (
                self.allows(event) and peer == str(event.get_sender_id())
            ):
                return
        event.set_extra("qq_security_recall_emitted", True)
        self.emit(
            replace(
                self.base(event, "recall"),
                group_id=str(raw.get("group_id", "")),
                message_id=str(raw["message_id"]),
                sender_id=str(raw.get("user_id", "")),
                private_user_id=str(raw.get("user_id", ""))
                if notice == "friend_recall"
                else "",
            )
        )

    @passive
    def message(self, event):
        if not self.allows(event):
            return
        if event.get_extra("qq_security_observed"):
            return
        raw = getattr(event.message_obj, "raw_message", {}) or {}
        if isinstance(raw, dict) and raw.get("post_type") == "notice":
            return
        event.set_extra("qq_security_observed", True)
        components = list(event.get_messages())[:100]
        text = "".join(str(p.text) for p in components if type(p).__name__ == "Plain")
        if not components:
            text = str(event.message_str or "")
        safe = self.plugin.policy.redact(text[:16384])
        self.emit(
            replace(
                self.base(event, "message"),
                text=safe[:8192],
                sender_name=self.plugin.policy.redact(
                    str(event.get_sender_name() or "")[:80]
                ),
                reply_to=next(
                    (str(p.id) for p in components if type(p).__name__ == "Reply"), ""
                ),
                mentions=tuple(
                    str(p.qq) for p in components if type(p).__name__ == "At"
                ),
                components=tuple(type(p).__name__ for p in components),
                truncated=len(text) > 8192,
            )
        )

    @passive
    def send_start(self, event, chain):
        if not self.allows(event):
            return None
        sequence = int(event.get_extra("qq_security_send_sequence") or 0) + 1
        event.set_extra("qq_security_send_sequence", sequence)
        parts = list(chain.chain)[:100]
        text = "".join(str(p.text) for p in parts if type(p).__name__ == "Plain")
        record = replace(
            self.base(event, "send"),
            text=text[:8192],
            sequence=sequence,
            components=tuple(type(p).__name__ for p in parts),
            outcome="started",
            truncated=len(text) > 8192,
        )
        self.emit(record)
        return record

    @passive
    def send_end(self, record, outcome):
        if record is not None:
            self.emit(replace(record, outcome=outcome))

    @passive
    def finish(self, event):
        if self.allows(event):
            self.emit(
                replace(
                    self.base(event, "turn_end"),
                    outcome="stopped" if event.is_stopped() else "finished",
                )
            )
