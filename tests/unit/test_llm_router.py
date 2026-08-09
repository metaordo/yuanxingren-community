"""Tests for the LLM router: routes resolve to clients, failover works."""
from __future__ import annotations
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from backend.llm.base import ChatResult, Message, Usage
from backend.llm import router as llm_router, registry


class _FakeClient:
    """Minimal LLMClient stub for tests."""
    def __init__(self, name: str, fail: bool = False,
                 reply: str = "ok"):
        self.name = name
        self._fail = fail
        self._reply = reply
        self.calls = 0

    def chat(self, messages, **kwargs):
        self.calls += 1
        if self._fail:
            raise RuntimeError(f"{self.name} fails")
        return ChatResult(text=self._reply, usage=Usage(1, 1),
                           model=self.name, raw={})

    def stream(self, messages, **kwargs):
        if self._fail:
            raise RuntimeError(f"{self.name} fails")
        yield self._reply


def _register_fake(name: str, fail: bool = False, reply: str = "ok"):
    """Register a fake spec so router._get_client can resolve it."""
    fake = _FakeClient(name, fail=fail, reply=reply)
    spec = registry.ModelSpec(
        name=name, provider="fake", display=name,
        context_window=1024, capabilities={"reasoning"},
        factory=lambda _cfg: fake,
    )
    registry.register(spec)
    # Bust the cached client so the next get_client recreates from factory
    llm_router._clients.pop(name, None)
    return fake


def test_routes_to_primary_when_healthy():
    fake = _register_fake("test-primary", reply="primary")
    llm_router.set_route("test-task", ["test-primary"])
    result = llm_router.call("test-task", [Message(role="user", content="hi")])
    assert result.text == "primary"
    assert fake.calls == 1


def test_failover_to_secondary_on_primary_error():
    primary = _register_fake("test-bad", fail=True)
    secondary = _register_fake("test-good", reply="fallback")
    llm_router.set_route("test-task", ["test-bad", "test-good"])
    result = llm_router.call("test-task", [Message(role="user", content="hi")])
    assert result.text == "fallback"
    assert primary.calls == 1
    assert secondary.calls == 1


def test_unknown_task_falls_back_to_default_route():
    fake = _register_fake("default-target", reply="default")
    llm_router.set_route("default", ["default-target"])
    result = llm_router.call("brand-new-task-never-registered",
                              [Message(role="user", content="hi")])
    assert result.text == "default"


def test_all_failures_raises():
    _register_fake("only-bad", fail=True)
    llm_router.set_route("test-fail-task", ["only-bad"])
    with pytest.raises(RuntimeError):
        llm_router.call("test-fail-task", [Message(role="user", content="x")])


def test_compose_chain_inserts_fallback_model_then_builtin():
    """compose_chain_for_primary builds [primary, primary.fallback, *builtin]."""
    flash = _register_fake("fake-flash-model", reply="flash")
    # Thinking model declares flash sibling via fallback_model
    spec = registry.ModelSpec(
        name="fake-thinking-model", provider="fake", display="thinking",
        context_window=1024, capabilities={"reasoning", "thinking"},
        factory=lambda _cfg: _FakeClient("fake-thinking-model"),
        fallback_model="fake-flash-model",
    )
    registry.register(spec)
    llm_router._clients.pop("fake-thinking-model", None)

    # Pretend "test-compose" task already has a builtin default chain
    llm_router.set_route("test-compose", ["builtin-a", "builtin-b"])

    chain = llm_router.compose_chain_for_primary("test-compose",
                                                  "fake-thinking-model")
    assert chain == [
        "fake-thinking-model",     # admin choice first
        "fake-flash-model",         # same-family fallback second
        "builtin-a", "builtin-b",  # builtin defaults last
    ]


def test_compose_chain_no_fallback_preserves_builtin():
    """Non-thinking primary: chain is [primary, *builtin] minus duplicates."""
    _register_fake("plain-primary")
    llm_router.set_route("test-plain", ["plain-primary", "builtin-x"])

    chain = llm_router.compose_chain_for_primary("test-plain", "plain-primary")
    assert chain == ["plain-primary", "builtin-x"]


def test_compose_chain_dedup_when_fallback_already_in_builtin():
    """If primary.fallback is already in the builtin list, no duplicate added."""
    flash = _register_fake("dup-flash")
    spec = registry.ModelSpec(
        name="dup-thinking", provider="fake", display="thinking",
        context_window=1024, capabilities={"thinking"},
        factory=lambda _cfg: _FakeClient("dup-thinking"),
        fallback_model="dup-flash",
    )
    registry.register(spec)
    llm_router._clients.pop("dup-thinking", None)

    llm_router.set_route("test-dup", ["other", "dup-flash"])
    chain = llm_router.compose_chain_for_primary("test-dup", "dup-thinking")
    # dup-flash appears once (right after primary), not twice
    assert chain == ["dup-thinking", "dup-flash", "other"]
