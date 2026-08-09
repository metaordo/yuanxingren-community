"""Tests for the OpenAI-compatible adapter — covers vLLM, Ollama, 通义,
文心, 豆包, Kimi (they're all the same protocol). We mock the underlying
HTTP client so tests don't need network."""
from __future__ import annotations
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from backend.llm.base import Message


def _mock_openai_chat_response(text: str = "ok",
                                prompt_tokens: int = 5,
                                completion_tokens: int = 1):
    """Build the object shape OpenAI Python SDK returns from chat.completions.create."""
    choice = MagicMock()
    choice.message.content = text
    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens
    resp = MagicMock()
    resp.choices = [choice]
    resp.usage = usage
    resp.model_dump.return_value = {"id": "cmpl-test"}
    return resp


def test_openai_compat_uses_custom_base_url():
    """Verify base_url is propagated into the underlying OpenAI client."""
    from backend.llm.adapters.openai_compat import make_client
    with patch("backend.llm.adapters.openai.OpenAI") as MockOpenAI:
        make_client(model="qwen3-72b",
                    base_url="http://localhost:8000/v1",
                    api_key="test-key")
    args, kwargs = MockOpenAI.call_args
    assert kwargs["base_url"] == "http://localhost:8000/v1"
    assert kwargs["api_key"] == "test-key"


def test_openai_compat_chat_returns_chat_result():
    """End-to-end: chat() should turn the SDK response into a ChatResult."""
    from backend.llm.adapters.openai_compat import make_client
    with patch("backend.llm.adapters.openai.OpenAI") as MockOpenAI:
        instance = MockOpenAI.return_value
        instance.chat.completions.create.return_value = _mock_openai_chat_response(
            text="hello", prompt_tokens=10, completion_tokens=2,
        )
        client = make_client(model="qwen3-72b",
                              base_url="http://localhost:8000/v1",
                              api_key="EMPTY")
        result = client.chat([Message(role="user", content="hi")],
                              max_tokens=8, temperature=0.0)
    assert result.text == "hello"
    assert result.model == "qwen3-72b"
    assert result.usage.input_tokens == 10
    assert result.usage.output_tokens == 2


def test_openai_compat_passes_messages_correctly():
    """Verify the messages are formatted as OpenAI's chat array."""
    from backend.llm.adapters.openai_compat import make_client
    with patch("backend.llm.adapters.openai.OpenAI") as MockOpenAI:
        instance = MockOpenAI.return_value
        instance.chat.completions.create.return_value = _mock_openai_chat_response()
        client = make_client(model="m", base_url="http://x/v1", api_key="k")
        client.chat([
            Message(role="system", content="you are a tester"),
            Message(role="user", content="hi"),
        ], max_tokens=16, temperature=0.5)
    _, kwargs = instance.chat.completions.create.call_args
    assert kwargs["model"] == "m"
    assert kwargs["max_tokens"] == 16
    assert kwargs["temperature"] == 0.5
    assert kwargs["messages"] == [
        {"role": "system", "content": "you are a tester"},
        {"role": "user", "content": "hi"},
    ]


def test_openai_compat_streams_tokens():
    """stream() should yield content deltas until exhausted."""
    from backend.llm.adapters.openai_compat import make_client

    def _chunks():
        for piece in ["he", "llo", " world"]:
            chunk = MagicMock()
            delta = MagicMock()
            delta.content = piece
            choice = MagicMock()
            choice.delta = delta
            chunk.choices = [choice]
            yield chunk

    with patch("backend.llm.adapters.openai.OpenAI") as MockOpenAI:
        instance = MockOpenAI.return_value
        instance.chat.completions.create.return_value = _chunks()
        client = make_client(model="m", base_url="http://x/v1", api_key="k")
        out = list(client.stream([Message(role="user", content="hi")]))
    assert "".join(out) == "hello world"


@pytest.mark.parametrize("base_url,vendor", [
    ("https://dashscope.aliyuncs.com/compatible-mode/v1", "tongyi"),
    ("http://localhost:11434/v1", "ollama"),
    ("http://localhost:8000/v1", "vllm"),
    ("https://api.moonshot.cn/v1", "kimi"),
    ("https://api.deepseek.com/v1", "deepseek"),
    ("https://qianfan.baidubce.com/v2", "wenxin"),
    ("https://internal.gateway.example.com/v1", "enterprise"),
])
def test_openai_compat_works_across_vendors(base_url, vendor):
    """Same adapter, different base_url → all should construct fine."""
    from backend.llm.adapters.openai_compat import make_client
    with patch("backend.llm.adapters.openai.OpenAI") as MockOpenAI:
        client = make_client(model=f"model-{vendor}",
                              base_url=base_url,
                              api_key="sk-test")
        instance = MockOpenAI.return_value
        instance.chat.completions.create.return_value = _mock_openai_chat_response(
            text=f"ack-{vendor}",
        )
        result = client.chat([Message(role="user", content="ping")],
                              max_tokens=4)
    assert result.text == f"ack-{vendor}"
    # Verify the call site got the right base_url
    _, kwargs = MockOpenAI.call_args
    assert kwargs["base_url"] == base_url
