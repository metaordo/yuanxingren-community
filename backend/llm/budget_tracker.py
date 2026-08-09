"""Tracks input/output tokens per model. Persists to SQLite later; in-memory for MVP."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock


@dataclass
class ModelUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0


_lock = Lock()
_stats: dict[str, ModelUsage] = defaultdict(ModelUsage)


def record_usage(model: str, input_tokens: int, output_tokens: int) -> None:
    with _lock:
        u = _stats[model]
        u.input_tokens += input_tokens
        u.output_tokens += output_tokens
        u.calls += 1


def snapshot() -> dict[str, ModelUsage]:
    with _lock:
        return {k: ModelUsage(v.input_tokens, v.output_tokens, v.calls) for k, v in _stats.items()}
