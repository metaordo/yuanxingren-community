"""LLM model registry: capabilities, pricing hints, instantiation."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable
from .base import LLMClient


@dataclass
class ModelSpec:
    name: str                  # canonical id, e.g. "claude-opus-4-7"
    provider: str              # e.g. "anthropic", "openai", "local"
    display: str               # human label
    context_window: int
    capabilities: set[str] = field(default_factory=set)
    # e.g. {"reasoning", "coding", "tool_use", "long_context", "multimodal"}
    default_for: set[str] = field(default_factory=set)
    # e.g. {"planning", "codegen", "triage"}
    # Factory that produces an LLMClient for this model from a config dict
    factory: Callable[[dict], LLMClient] | None = None
    # Thinking models (e.g. DeepSeek v4-pro) spend a large chunk of the
    # completion budget on `reasoning_content` before emitting any visible
    # answer. When set, the router clamps the caller's `max_tokens` up to
    # at least this value so the visible answer isn't truncated. Default
    # None preserves the caller's value unchanged for all other models.
    min_max_tokens: int | None = None
    # Same-family non-thinking sibling to try first when this model fails.
    # Thinking models occasionally time out or return empty `content` when
    # the upstream pool is hot; failing over to the flash variant (same key,
    # same base_url, same provider) is smoother than dropping to a foreign
    # model family. Router consults this before walking the built-in chain.
    fallback_model: str | None = None


_registry: dict[str, ModelSpec] = {}

# Thinking model -> same-family non-thinking sibling. Failover target when
# the thinking variant times out or returns empty content. Add a row when
# registering a new thinking model whose family also publishes a flash variant.
THINKING_TO_FLASH: dict[str, str] = {
    "deepseek-v4-pro": "deepseek-chat",
}


def register(spec: ModelSpec) -> None:
    _registry[spec.name] = spec


def get(name: str) -> ModelSpec | None:
    return _registry.get(name)


def all_specs() -> list[ModelSpec]:
    return list(_registry.values())


def register_custom(spec: ModelSpec) -> None:
    """Register a user-added custom model (e.g. local vLLM, enterprise gateway)."""
    _registry[spec.name] = spec


def load_user_models(session) -> None:
    """Load user-defined models from the DB into the runtime registry.

    Community edition only supports OpenAI-compatible endpoints.
    """
    from sqlmodel import select
    from .models import CustomModel
    from .credential_store import decrypt

    def _openai_factory(model: str, base_url: str, api_key_enc: str):
        def _factory(_cfg):
            from .adapters.openai_compat import make_client
            return make_client(model=model, base_url=base_url,
                                api_key=decrypt(api_key_enc))
        return _factory

    for cm in session.exec(select(CustomModel).where(CustomModel.is_active == True)).all():
        factory = _openai_factory(cm.name, cm.base_url, cm.api_key_encrypted)
        caps = set(c.strip() for c in cm.capabilities.split(",") if c.strip())
        # Thinking models burn most of their budget on reasoning_content
        # before emitting any visible text. Reserve at least 8192 tokens
        # so the actual JSON answer survives. Operators opt-in by adding
        # the "thinking" capability tag when registering the model.
        min_mt = 8192 if "thinking" in caps else None
        register_custom(ModelSpec(
            name=cm.name,
            provider=cm.provider,
            display=cm.display,
            context_window=cm.context_window,
            capabilities=caps,
            factory=factory,
            min_max_tokens=min_mt,
            fallback_model=THINKING_TO_FLASH.get(cm.name),
        ))


def register_defaults() -> None:
    """Register built-in model — OpenAI-compatible (DeepSeek default)."""
    def _openai_factory(model_name):
        def _make(cfg):
            from .adapters.openai_compat import OpenAICompatClient
            return OpenAICompatClient(model=model_name, **cfg)
        return _make

    register(ModelSpec(
        name="deepseek-chat", provider="openai_compat",
        display="DeepSeek Chat",
        context_window=128_000,
        capabilities={"coding", "tool_use"},
        default_for={"planning", "codegen", "triage"},
        factory=_openai_factory("deepseek-chat"),
    ))


register_defaults()
