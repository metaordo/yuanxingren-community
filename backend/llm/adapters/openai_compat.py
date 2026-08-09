"""OpenAI-compatible adapter for self-hosted/proxied endpoints.

Reuses the OpenAI SDK with a custom base_url. Works with:
  - vLLM (--api-key required if set, OpenAI-compatible server)
  - Ollama (via ollama-openai compatibility layer)
  - Qwen on DashScope's OpenAI-compatible endpoint
  - 百度文心 / Moonshot Kimi / 智谱 GLM via their OpenAI-compatible mode
  - DeepSeek v4 (chat + v4-pro thinking)
  - Internal enterprise gateways that speak OpenAI's protocol

Thinking-model handling: DeepSeek v4-pro (and similar) emits an extra
`reasoning_content` field on the message that holds the chain-of-thought.
We surface it via `raw["reasoning_content"]` for transcript/debug while
returning only the user-facing `content` in `text`, so downstream JSON
parsers don't accidentally pick up reasoning prose.
"""
from __future__ import annotations
from typing import Iterator
from ..base import ChatResult, Message, Usage
from .openai import OpenAIClient


class OpenAICompatClient(OpenAIClient):
    """Identical wire protocol to OpenAI; differs by base_url and may
    surface thinking-model `reasoning_content`."""
    name = "openai_compat"

    def chat(self, messages: list[Message], *,
             max_tokens: int = 1024,
             temperature: float = 0.2,
             tools: list[dict] | None = None) -> ChatResult:
        kwargs: dict = {
            "model": self.model,
            "messages": self._to_openai(messages),
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools
        resp = self._client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        text = msg.content or ""
        reasoning = getattr(msg, "reasoning_content", None)
        u = getattr(resp, "usage", None)
        usage = Usage(
            input_tokens=getattr(u, "prompt_tokens", 0) or 0,
            output_tokens=getattr(u, "completion_tokens", 0) or 0,
        )
        raw = resp.model_dump()
        if reasoning:
            raw["reasoning_content"] = reasoning
        return ChatResult(text=text, usage=usage, model=self.model, raw=raw)


def make_client(model: str, base_url: str, api_key: str | None = None) -> OpenAICompatClient:
    return OpenAICompatClient(model=model, api_key=api_key or "EMPTY", base_url=base_url)
