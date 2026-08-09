"""Cost calculation from token counts and per-model prices.

Display-only: missing price => 0, never raises. Prices are CNY per 1M tokens.
"""
from __future__ import annotations

from sqlmodel import Session, select

from ..llm.models import ModelPrice

# (price_in_per_mtok, price_out_per_mtok)
Prices = dict[str, tuple[float, float]]


def load_prices(session: Session) -> Prices:
    """One query -> {model_name: (price_in, price_out)} for in-memory lookup."""
    return {
        p.model_name: (p.price_in_per_mtok, p.price_out_per_mtok)
        for p in session.exec(select(ModelPrice)).all()
    }


def cost_cny(model: str | None, tokens_in: int, tokens_out: int, prices: Prices) -> float:
    """¥ cost for one model's token usage. Unknown model -> 0."""
    pin, pout = prices.get(model or "", (0.0, 0.0))
    return tokens_in / 1_000_000 * pin + tokens_out / 1_000_000 * pout
