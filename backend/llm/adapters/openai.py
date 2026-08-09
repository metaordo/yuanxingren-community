"""OpenAI-compatible adapter (also works for any OpenAI-style endpoint)."""
from __future__ import annotations
import os
from typing import Iterator
from openai import OpenAI
from ..base import ChatResult, LLMClient, Message, Usage


class OpenAIClient:
    name = "openai"

    def __init__(self, model: str, api_key: str | None = None,
                 base_url: str | None = None):
        self.model = model
        self._client = OpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            base_url=base_url or os.environ.get("OPENAI_BASE_URL"),
        )

    def _to_openai(self, messages: list[Message]) -> list[dict]:
        return [{"role": m.role, "content": m.content} for m in messages]

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
        text = resp.choices[0].message.content or ""
        u = getattr(resp, "usage", None)
        usage = Usage(
            input_tokens=getattr(u, "prompt_tokens", 0) or 0,
            output_tokens=getattr(u, "completion_tokens", 0) or 0,
        )
        return ChatResult(text=text, usage=usage, model=self.model, raw=resp.model_dump())

    def stream(self, messages: list[Message], *,
               max_tokens: int = 1024,
               temperature: float = 0.2) -> Iterator[str]:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=self._to_openai(messages),
            max_tokens=max_tokens,
            temperature=temperature,
            stream=True,
        )
        for chunk in resp:
            delta = chunk.choices[0].delta.content if chunk.choices else None
            if delta:
                yield delta


def make_client(**cfg) -> LLMClient:
    return OpenAIClient(**cfg)
