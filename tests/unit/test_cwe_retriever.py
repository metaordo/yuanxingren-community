"""BM25 retriever over CWE corpus. Verifies English+CJK tokenization through
the underlying knowledge_base.retriever.BM25Index, plus the abstraction filter."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.cwe.schema import CweEntry
from knowledge_base.cwe.retriever import CweRetriever


def _seed():
    return [
        CweEntry(id="CWE-79", name="Cross-site Scripting XSS",
                 abstraction="Base", status="Stable",
                 description="Improper neutralization of input during web page generation",
                 extended_description="XSS allows attackers to inject script into pages viewed by other users 跨站脚本"),
        CweEntry(id="CWE-89", name="SQL Injection",
                 abstraction="Base", status="Stable",
                 description="Improper neutralization of special elements in SQL command",
                 extended_description="SQL injection lets attackers execute arbitrary SQL 注入"),
        CweEntry(id="CWE-707", name="Improper Neutralization",
                 abstraction="Pillar", status="Incomplete",
                 description="Generic neutralization weakness pillar covering injection"),
        CweEntry(id="CWE-74", name="Injection Class",
                 abstraction="Class", status="Incomplete",
                 description="Generic injection class node", parents=["CWE-707"]),
    ]


def test_english_search_hits_xss():
    r = CweRetriever()
    r.index(_seed())
    hits = r.search("cross site scripting")
    assert hits, "expected at least one hit"
    assert hits[0].id == "CWE-79"


def test_english_search_hits_sql_injection():
    r = CweRetriever()
    r.index(_seed())
    hits = r.search("sql command")
    assert hits[0].id == "CWE-89"


def test_chinese_bigram_search_finds_xss():
    r = CweRetriever()
    r.index(_seed())
    hits = r.search("跨站脚本")
    # CWE-79 should be in top-3 (CJK bigram tokenization is shared with the
    # main retriever — already tested at the BM25 level).
    ids_top3 = [h.id for h in hits[:3]]
    assert "CWE-79" in ids_top3


def test_abstraction_filter():
    r = CweRetriever()
    r.index(_seed())
    # Both CWE-79 and CWE-89 score on "injection" tokens, plus CWE-74 and CWE-707.
    # Filter to Pillars: only CWE-707 should remain.
    hits = r.search("injection", abstraction="Pillar")
    assert all(h.abstraction == "Pillar" for h in hits)
    assert "CWE-707" in {h.id for h in hits}


def test_parent_id_filter():
    r = CweRetriever()
    r.index(_seed())
    # Search "injection" but constrain to entries whose parents include CWE-707
    hits = r.search("injection", parent_id="CWE-707")
    assert all("CWE-707" in h.parents for h in hits)
    assert "CWE-74" in {h.id for h in hits}


def test_top_k_applies_after_filter():
    r = CweRetriever()
    r.index(_seed())
    hits = r.search("injection", top_k=1, abstraction="Pillar")
    assert len(hits) <= 1
