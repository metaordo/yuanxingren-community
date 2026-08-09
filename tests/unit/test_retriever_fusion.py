"""Unit tests for retriever fusion (RRF) — covers BM25 fallback and fusion."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.retriever import HybridRetriever, _rrf_fuse


def test_rrf_basic():
    # Both lists rank the same id high; RRF should bubble it to the top
    fused = _rrf_fuse(["a", "b", "c"], ["a", "x", "y"])
    assert fused[0] == "a"


def test_rrf_only_one_source():
    fused = _rrf_fuse(["a", "b", "c"], [])
    assert fused == ["a", "b", "c"]


def test_retriever_bm25_only_when_vector_unavailable(monkeypatch):
    r = HybridRetriever()
    # Force vector path to be unavailable
    r._vector_store = False
    from knowledge_base.schema.entry import KnowledgeEntry, EntryType
    r.index([
        KnowledgeEntry(id="ref_1", title="TCP sequence prediction",
                       type=EntryType.paper, category="TCP", year=1985,
                       summary="Morris 1985"),
        KnowledgeEntry(id="ref_2", title="DNS cache poisoning",
                       type=EntryType.paper, category="DNS", year=2008,
                       summary="Kaminsky 2008"),
    ])
    hits = r.search("Morris sequence")
    assert hits and hits[0].id == "ref_1"
