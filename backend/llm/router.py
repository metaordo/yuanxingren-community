"""Route a task kind to a concrete LLMClient; support per-task overrides and failover."""
from __future__ import annotations
import logging
from typing import Callable
from .base import LLMClient, Message, ChatResult
from . import registry
from .budget_tracker import record_usage

log = logging.getLogger(__name__)

# In-memory mapping from task kind -> ordered list of model names to try.
# Community edition: single model for all task kinds.
_task_routes: dict[str, list[str]] = {
    "planning": ["deepseek-chat"],
    "codegen":  ["deepseek-chat"],
    "triage":   ["deepseek-chat"],
    "default":  ["deepseek-chat"],
}

# Stored instantiated clients keyed by model name
_clients: dict[str, LLMClient] = {}
# Stored per-model config (api keys etc.) keyed by model name
_configs: dict[str, dict] = {}


def configure(model_name: str, config: dict) -> None:
    """Set or replace the per-model config (e.g., api_key, base_url)."""
    _configs[model_name] = dict(config)
    _clients.pop(model_name, None)


def set_route(kind: str, model_names: list[str]) -> None:
    _task_routes[kind] = list(model_names)


def compose_chain_for_primary(kind: str, primary: str) -> list[str]:
    """Build the failover chain for `kind` given an admin-chosen primary.

    Order: [primary, primary.fallback_model (if any), *current task defaults].
    Deduped while preserving order. Used by both DB load and live PUT to
    keep in-memory and DB-loaded chains consistent.
    With a single-model community setup the chain is always [primary].
    """
    spec = registry.get(primary)
    builtin = _task_routes.get(kind) or _task_routes["default"]
    chain: list[str] = [primary]
    if spec and spec.fallback_model and spec.fallback_model != primary:
        chain.append(spec.fallback_model)
    for m in builtin:
        if m not in chain:
            chain.append(m)
    return chain


def get_primary_routes() -> dict[str, str]:
    """Return {task_kind: primary_model_name} for the persisted/configurable tasks."""
    return {k: (_task_routes.get(k) or [""])[0]
            for k in ("planning", "codegen", "triage")}


def load_routes_from_db() -> None:
    """Load persisted route overrides from SQLite into the in-memory map.

    Community edition: the RouteSetting table may not exist, so the DB
    read is wrapped in try/except and silently skipped on failure.
    """
    try:
        from sqlmodel import Session, select
        from ..db import engine
        from .models import RouteSetting
        with Session(engine) as s:
            for row in s.exec(select(RouteSetting)).all():
                if not row.model_name:
                    continue
                spec = registry.get(row.model_name)
                if spec is None:
                    log.warning("dropping stale route %s -> %s (unknown model)",
                                row.task_kind, row.model_name)
                    continue
                _task_routes[row.task_kind] = compose_chain_for_primary(
                    row.task_kind, row.model_name)
                log.info("route %s: chain = %s",
                          row.task_kind, _task_routes[row.task_kind])
    except Exception as e:  # noqa: BLE001
        log.warning("could not load persisted routes: %s", e)


def save_route_to_db(kind: str, model_name: str, user_id: int | None = None) -> None:
    """Persist a single task->model route to SQLite."""
    from datetime import datetime
    from sqlmodel import Session
    from ..db import engine
    from .models import RouteSetting
    with Session(engine) as s:
        row = s.get(RouteSetting, kind)
        if row:
            row.model_name = model_name
            row.updated_at = datetime.utcnow()
            row.updated_by = user_id
        else:
            row = RouteSetting(task_kind=kind, model_name=model_name,
                                updated_by=user_id)
        s.add(row)
        s.commit()


def _get_client(model_name: str) -> LLMClient:
    client = _clients.get(model_name)
    if client is not None:
        return client
    spec = registry.get(model_name)
    if not spec or not spec.factory:
        raise ValueError(f"unknown or non-instantiable model: {model_name}")
    cfg = _configs.get(model_name, {})
    client = spec.factory(cfg)
    _clients[model_name] = client
    return client


def call(kind: str, messages: list[Message], **kwargs) -> ChatResult:
    """Invoke the primary model for this task kind, falling back on failure."""
    candidates = _task_routes.get(kind) or _task_routes["default"]
    last_err: Exception | None = None
    for model_name in candidates:
        try:
            client = _get_client(model_name)
            spec = registry.get(model_name)
            call_kwargs = dict(kwargs)
            if spec and spec.min_max_tokens:
                requested = call_kwargs.get("max_tokens", 1024)
                if requested < spec.min_max_tokens:
                    log.info("model %s is a thinking model; raising max_tokens "
                              "%d -> %d", model_name, requested, spec.min_max_tokens)
                    call_kwargs["max_tokens"] = spec.min_max_tokens
            result = client.chat(messages, **call_kwargs)
            record_usage(model_name, result.usage.input_tokens, result.usage.output_tokens)
            return result
        except Exception as e:  # noqa: BLE001 — failover must be broad
            log.warning("model %s failed: %s; trying next", model_name, e)
            last_err = e
    raise RuntimeError(f"all candidates failed for task {kind!r}: {last_err}")


async def acall(kind: str, messages: list[Message], **kwargs) -> ChatResult:
    """Async wrapper around `call()` for use in asyncio.gather().

    Pushes the (synchronous, blocking) call onto the default thread pool —
    safe because each LLM call is largely IO/subprocess bound (claude CLI
    or HTTPS to upstream gateway), not CPU bound, and the underlying
    adapters and registry are thread-safe via per-model client caches.
    """
    import asyncio
    return await asyncio.to_thread(call, kind, messages, **kwargs)
