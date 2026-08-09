"""0-Day detector: score a Finding's novelty by comparing against the
knowledge base. A high novelty score means the finding does not resemble
any known vulnerability class and may be a candidate 0-day.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass

from pentest_agent_sdk.contracts import Finding

log = logging.getLogger(__name__)


@dataclass
class NoveltyScore:
    value: float          # 0.0 (fully known) .. 1.0 (fully novel)
    similar_refs: list[str]
    rationale: str


def score(finding: Finding) -> NoveltyScore:
    """Retrieve similar knowledge base entries and score novelty.

    MVP heuristic: query KB with the finding's title + category. If top hit's
    similarity is above a threshold, treat as known; otherwise novel.
    """
    try:
        from knowledge_base import retriever
    except ImportError:
        return NoveltyScore(0.5, [], "knowledge base unavailable")

    query = f"{finding.title} {finding.category}"
    hits = retriever.search(query, top_k=5)
    if not hits:
        return NoveltyScore(
            value=0.9,
            similar_refs=[],
            rationale="no knowledge base matches; likely novel",
        )
    # Rough heuristic: rely on match count as proxy for recognition
    known_count = sum(1 for h in hits if finding.category.lower() in h.summary.lower())
    if known_count >= 2:
        return NoveltyScore(
            value=0.2,
            similar_refs=[h.id for h in hits[:3]],
            rationale=f"{known_count} KB entries match category {finding.category}",
        )
    return NoveltyScore(
        value=0.6,
        similar_refs=[h.id for h in hits[:3]],
        rationale="weak KB match; worth manual review",
    )
