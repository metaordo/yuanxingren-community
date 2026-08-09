"""Unified LLM client protocol — all adapters implement this."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterator, Literal, Protocol, runtime_checkable


Role = Literal["system", "user", "assistant", "tool"]


@dataclass
class Message:
    role: Role
    content: str


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class ChatResult:
    text: str
    usage: Usage
    model: str
    raw: dict = field(default_factory=dict)


@runtime_checkable
class LLMClient(Protocol):
    name: str

    def chat(self, messages: list[Message], *,
             max_tokens: int = 1024,
             temperature: float = 0.2,
             tools: list[dict] | None = None) -> ChatResult: ...

    def stream(self, messages: list[Message], *,
               max_tokens: int = 1024,
               temperature: float = 0.2) -> Iterator[str]: ...
