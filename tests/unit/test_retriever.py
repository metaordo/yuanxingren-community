"""Unit tests for the BM25 retriever."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.schema.entry import KnowledgeEntry, EntryType
from knowledge_base.retriever import HybridRetriever


def _entry(idx: int, title: str, summary: str,
           category: str = "TCP", year: int = 2020) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=f"ref_{idx}", title=title, type=EntryType.paper,
        category=category, year=year, summary=summary,
    )


def test_bm25_recovers_term():
    r = HybridRetriever()
    r.index([
        _entry(1, "TCP sequence number prediction", "Morris 1985 sequence prediction attack"),
        _entry(2, "DNS cache poisoning", "Kaminsky DNS attack 2008", category="DNS"),
        _entry(3, "BGP hijacking", "Routing attack via BGP", category="BGP"),
    ])
    hits = r.search("sequence prediction")
    assert hits, "should return at least one hit"
    assert hits[0].id == "ref_1"


def test_metadata_filter():
    r = HybridRetriever()
    r.index([
        _entry(1, "TCP attack", "stuff", category="TCP"),
        _entry(2, "DNS attack", "stuff", category="DNS"),
    ])
    hits = r.search("attack", category="DNS")
    assert all(h.category == "DNS" for h in hits)


def test_year_filter():
    r = HybridRetriever()
    r.index([
        _entry(1, "TCP attack", "stuff", year=1985),
        _entry(2, "TCP attack modern", "stuff", year=2020),
    ])
    hits = r.search("attack", year_range=(2000, 2025))
    assert all(h.year and h.year >= 2000 for h in hits)
