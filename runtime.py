"""AstrBot execution adapters and bot-only lifecycle restrictions."""

import asyncio
import copy
import inspect
import sqlite3
from contextlib import contextmanager, nullcontext, suppress
from contextvars import ContextVar

from astrbot.core.agent.tool import FunctionTool
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.message_type import MessageType

from .security import Identity

try:
    from astrbot.core.platform.astr_message_event import current_message_event
except ImportError:
    # Official releases without this optional host context still use bot_scope.
    current_message_event = ContextVar("qq_security_host_event", default=None)

bot_operation = ContextVar("qq_security_bot_operation", default=None)

TOOL_RULES = {
    "qq_guard_codex": ("admin_codex", "astrbot_plugin_qq_security"),
    "codex_generate_image": ("image", "astrbot_plugin_codex_provider"),
    "search_memes": ("meme", "meme_manager"),
    "get_session_images": ("image_source", "astrbot_plugin_imgexploration"),
    "search_image": ("image_source", "astrbot_plugin_imgexploration"),
    "memory_companion_remember": ("memory", "astrbot_plugin_memory_companion"),
    "memory_companion_recall": ("memory", "astrbot_plugin_memory_companion"),
    "qq_guard_read": ("workspace_read", "astrbot_plugin_qq_security"),
    "qq_guard_write": ("workspace_write", "astrbot_plugin_qq_security"),
    "qq_guard_list": ("workspace_list", "astrbot_plugin_qq_security"),
}


@contextmanager
def bot_scope(event):
    token = bot_operation.set(event)
    try:
        yield
    finally:
        bot_operation.reset(token)


def identity_from_event(event):
    return Identity(
        str(event.get_platform_name()),
        str(event.get_self_id()),
        str(event.get_sender_id()),
        str(event.get_group_id() or ""),
        event.get_message_type() == MessageType.FRIEND_MESSAGE,
    )


class LifecycleGuard:
    def __init__(self, manager, plugin_name):
        self.manager = manager
        self.plugin_name = plugin_name
        self.replacements = []

    def install(self):
        for operation in (
            "turn_off_plugin",
            "uninstall_plugin",
            "reload",
            "reload_failed_plugin",
            "_terminate_plugin",
            "update_plugin",
            "install_plugin",
        ):
            original = getattr(self.manager, operation, None)
            if original is None:
                continue

            async def guarded(
                *args, _original=original, _operation=operation, **kwargs
            ):
                event = bot_operation.get() or current_message_event.get()
                target = kwargs.get(
                    "plugin_name",
                    kwargs.get("specified_plugin_name", args[0] if args else None),
                )
                target = getattr(target, "name", target)
                target_name = (
                    str(target or "")
                    .replace("\\", "/")
                    .rstrip("/")
                    .removesuffix(".git")
                    .split("/")[-1]
                )
                if event is not None and (
                    target is None
                    or target_name == self.plugin_name
                    or _operation
                    in {"install_plugin", "reload", "reload_failed_plugin"}
                ):
                    raise PermissionError(
                        "Bot operations cannot disable, replace or remove the security guard. Use the local administrator UI manually."
                    )
                return await _original(*args, **kwargs)

            self.replacements.append((operation, original, guarded))
            setattr(self.manager, operation, guarded)

    def restore(self):
        for operation, original, wrapper in reversed(self.replacements):
            if getattr(self.manager, operation, None) is wrapper:
                setattr(self.manager, operation, original)
        self.replacements.clear()


class PipelineGuard:
    """Wrap the scheduler before registration and preprocessing, reversibly."""

    def __init__(self, plugin):
        self.plugin = plugin
        self.original_execute = None
        self.wrapper = None
        self.original_config = None
        self.config_wrapper = None
        self.original_preprocess = None
        self.preprocess_wrapper = None

    def install(self):
        from astrbot.core.pipeline.preprocess_stage.stage import PreProcessStage
        from astrbot.core.pipeline.scheduler import PipelineScheduler

        original = PipelineScheduler.execute
        plugin = self.plugin

        async def execute(scheduler, event):
            with bot_scope(event):
                try:
                    try:
                        plugin.observers.prefix(event)
                        plugin._wrap_send(event)
                        event.set_extra(
                            "qq_security_effective_config", scheduler.ctx.astrbot_config
                        )
                        plugin._namespace(event)
                    except Exception as error:
                        event.stop_event()
                        plugin.logger.error(
                            "Security pipeline blocked: %s", type(error).__name__
                        )
                        await event.send(
                            event.plain_result(
                                "消息未通过安全检查，请在本机管理端查看设置。"
                            )
                        )
                        if event.get_platform_name() == "webchat":
                            await event.send(None)
                        return
                    if not event.is_stopped():
                        return await original(scheduler, event)
                finally:
                    plugin.observers.finish(event)
                    try:
                        plugin.cleanup_media(event)
                    finally:
                        if (
                            event.get_platform_name() == "webchat"
                            and not event.get_extra("qq_security_stream_closed")
                        ):
                            with suppress(Exception):
                                await event.send(None)

        self.original_execute, self.wrapper = original, execute
        PipelineScheduler.execute = execute
        original_preprocess = PreProcessStage.process

        async def preprocess(stage, event):
            try:
                await plugin.prepare_pipeline(event, stage.config)
                if not event.is_stopped():
                    await plugin.guard_message(event)
            except Exception as error:
                event.stop_event()
                plugin.logger.error("Security media blocked: %s", type(error).__name__)
                await event.send(
                    event.plain_result(
                        "消息未通过安全检查，请使用 QQ 图片或在本机管理端检查设置。"
                    )
                )
                return
            if not event.is_stopped():
                return await original_preprocess(stage, event)

        self.original_preprocess, self.preprocess_wrapper = (
            original_preprocess,
            preprocess,
        )
        PreProcessStage.process = preprocess
        original_config = plugin.context.get_config

        def get_config(umo=None):
            event = bot_operation.get()
            if event is not None and umo == event.unified_msg_origin:
                selected = event.get_extra("qq_security_effective_config")
                if selected is not None:
                    return selected
            return original_config(umo)

        self.original_config, self.config_wrapper = original_config, get_config
        plugin.context.get_config = get_config

    def restore(self):
        from astrbot.core.pipeline.preprocess_stage.stage import PreProcessStage
        from astrbot.core.pipeline.scheduler import PipelineScheduler

        if self.wrapper is not None and PipelineScheduler.execute is self.wrapper:
            PipelineScheduler.execute = self.original_execute
        if (
            self.preprocess_wrapper is not None
            and PreProcessStage.process is self.preprocess_wrapper
        ):
            PreProcessStage.process = self.original_preprocess
        if (
            self.config_wrapper is not None
            and self.plugin.context.get_config is self.config_wrapper
        ):
            self.plugin.context.get_config = self.original_config
        self.wrapper = self.config_wrapper = None
        self.preprocess_wrapper = None


class SessionPolicyGuard:
    """Honor existing owner access denials without reusing old conversation data."""

    def __init__(self):
        self.replacements = []

    def _replace(self, owner, name, wrapper, static=False):
        self.replacements.append((owner, name, owner.__dict__[name], wrapper))
        setattr(owner, name, staticmethod(wrapper) if static else wrapper)

    def install(self):
        from astrbot.core.pipeline.whitelist_check.stage import WhitelistCheckStage
        from astrbot.core.platform.message_session import MessageSesion
        from astrbot.core.star.session_llm_manager import SessionServiceManager
        from astrbot.core.star.session_plugin_manager import SessionPluginManager

        for owner, name in (
            (SessionServiceManager, "is_session_enabled"),
            (SessionServiceManager, "is_llm_enabled_for_session"),
            (SessionServiceManager, "is_tts_enabled_for_session"),
            (SessionPluginManager, "is_plugin_enabled_for_session"),
        ):
            original = getattr(owner, name)

            async def check(session_id, *args, _original=original, **kwargs):
                permitted = await _original(session_id, *args, **kwargs)
                event = bot_operation.get()
                old = event.get_extra("qq_security_original_umo") if event else None
                if old and old != session_id and session_id == event.unified_msg_origin:
                    permitted = permitted and await _original(old, *args, **kwargs)
                return permitted

            self._replace(owner, name, check, static=True)

        original_filter = SessionPluginManager.filter_handlers_by_session

        async def filter_handlers(event, handlers):
            kept = await original_filter(event, handlers)
            old = event.get_extra("qq_security_original_umo")
            if old and old != event.unified_msg_origin:
                original_event = copy.copy(event)
                original_event.session = MessageSesion.from_str(old)
                kept = await original_filter(original_event, kept)
            return kept

        self._replace(
            SessionPluginManager,
            "filter_handlers_by_session",
            filter_handlers,
            static=True,
        )
        original_whitelist = WhitelistCheckStage.process

        async def whitelist(stage, event):
            old = event.get_extra("qq_security_original_umo")
            if old and old in stage.whitelist:
                stage = copy.copy(stage)
                stage.whitelist = [*stage.whitelist, event.unified_msg_origin]
            return await original_whitelist(stage, event)

        self._replace(WhitelistCheckStage, "process", whitelist)

    def restore(self):
        for owner, name, original, wrapper in reversed(self.replacements):
            if getattr(owner, name) is wrapper:
                setattr(owner, name, original)
        self.replacements.clear()


class GuardedTool(FunctionTool):
    def __init__(self, tool, plugin, identity):
        super().__init__(
            name=tool.name, description=tool.description, parameters=tool.parameters
        )
        self.original = tool
        self.plugin = plugin
        self.identity = identity
        self.active = bool(getattr(tool, "active", True))
        self.handler_module_path = getattr(tool, "handler_module_path", None)
        rule = TOOL_RULES.get(tool.name)
        module_parts = str(self.handler_module_path or "").split(".")
        self.capability = rule[0] if rule and rule[1] in module_parts else "unknown"

    async def call(self, context, **kwargs):
        event = context.context.event
        current = identity_from_event(event)
        error = self.plugin.policy.authorize(current, self.capability)
        actor = self.plugin.actor(current)
        if event.get_extra("qq_security_forward_read_only"):
            self.plugin.ledger.audit(actor, self.name, "denied")
            return "Operation denied: forwarded conversation turns are read-only."
        if not self.active or current != self.identity or error:
            self.plugin.ledger.audit(actor, self.name, "denied")
            return "Operation denied by the security policy."
        if self.capability == "admin_codex" and not self.plugin.is_computer_admin(
            event
        ):
            self.plugin.ledger.audit(actor, self.name, "denied")
            return "Operation denied: a verified private QQ administrator is required."
        try:
            if self.capability == "image":
                self.plugin.validate_references(event)
                if isinstance(kwargs.get("prompt"), str):
                    kwargs["prompt"] = self.plugin.policy.redact(kwargs["prompt"])
            config = self.plugin.policy.config
            reservation = (
                self.plugin.ledger.reserve(
                    actor,
                    daily=config.get("daily_image_limit", 20),
                    cooldown=config.get("image_cooldown_seconds", 60),
                    concurrent=config.get("image_concurrency", 2),
                )
                if self.capability == "image"
                else nullcontext()
            )
            with reservation, bot_scope(event):
                self.plugin.ledger.audit(actor, self.name, "started")
                handler = self.original.handler
                result = (
                    handler(event, **kwargs)
                    if handler
                    else self.original.call(context, **kwargs)
                )
                if inspect.isasyncgen(result):
                    last = None
                    async with asyncio.timeout(240):
                        async for item in result:
                            if isinstance(item, MessageChain):
                                await event.send(item)
                            elif item is not None:
                                last = item
                    result = last
                elif inspect.isawaitable(result):
                    timeout = (
                        self.plugin.admin_codex.timeout + 15
                        if self.capability == "admin_codex"
                        else 240
                    )
                    result = await asyncio.wait_for(result, timeout=timeout)
                self.plugin.ledger.audit(actor, self.name, "completed")
                if (
                    self.capability == "admin_codex"
                    and not self.plugin.is_computer_admin(event)
                ):
                    return "Operation denied: administrator access was revoked."
                if isinstance(result, str):
                    return self.plugin.policy.redact(
                        result,
                        private_admin=self.capability == "admin_codex"
                        and self.plugin.is_computer_admin(event),
                    )
                for part in getattr(result, "content", []) or []:
                    if isinstance(getattr(part, "text", None), str):
                        part.text = self.plugin.policy.redact(
                            part.text,
                            private_admin=self.capability == "admin_codex"
                            and self.plugin.is_computer_admin(event),
                        )
                return result
        except (PermissionError, ValueError, OSError, sqlite3.Error, TimeoutError):
            self.plugin.ledger.audit(actor, self.name, "blocked_or_failed")
            return "操作被安全策略或限额拦截，请在本机管理端检查设置。"
