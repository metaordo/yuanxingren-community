"""Hybrid retrieval: BM25 keyword + semantic vector + metadata filtering.

MVP: pure-Python BM25 + optional Chroma for embeddings. Graceful fallback to
keyword-only mode when Chroma/sentence-transformers aren't installed.
"""
from __future__ import annotations
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from .schema.entry import KnowledgeEntry

log = logging.getLogger(__name__)

_WORD_RE = re.compile(r"\w+", re.UNICODE)
# Match runs of Han characters (CJK Unified Ideographs + extensions) so we can
# treat them specially: a Han sequence is broken into overlapping 2-grams which
# is a cheap but surprisingly effective tokenization for BM25 on Chinese text.
_HAN_RE = re.compile(r"[一-鿿㐀-䶿]+")


def _han_bigrams(text: str) -> list[str]:
    """Yield overlapping 2-character bigrams plus single chars for runs of CJK."""
    out: list[str] = []
    if len(text) == 1:
        return [text]
    for i in range(len(text) - 1):
        out.append(text[i:i + 2])
    # Also keep the single chars so a one-char query like '溯' still hits.
    out.extend(list(text))
    return out


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    # Word tokens (ASCII / mixed) preserve their canonical lowercased form.
    for m in _WORD_RE.findall(text):
        tokens.append(m.lower())
    # CJK runs: bigrams + single chars — both indexed and queried under the
    # same scheme, so a Chinese query word like "序列号" produces ["序列",
    # "列号", "序", "列", "号"] which is the same shape an indexed entry
    # containing the substring would emit.
    for m in _HAN_RE.findall(text):
        tokens.extend(_han_bigrams(m))
    return tokens


@dataclass
class BM25Index:
    """Simple in-memory BM25 index over entry summary+title."""
    k1: float = 1.5
    b: float = 0.75
    docs: list[list[str]] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)
    df: Counter = field(default_factory=Counter)
    avgdl: float = 0.0

    def build(self, entries: list[KnowledgeEntry]) -> None:
        self.docs = []
        self.ids = []
        self.df.clear()
        for e in entries:
            tokens = _tokenize(f"{e.title} {e.summary}")
            self.docs.append(tokens)
            self.ids.append(e.id)
            for term in set(tokens):
                self.df[term] += 1
        self.avgdl = (sum(len(d) for d in self.docs) / len(self.docs)) if self.docs else 0.0

    def search(self, query: str, top_k: int = 10) -> list[tuple[str, float]]:
        if not self.docs:
            return []
        q_tokens = _tokenize(query)
        n = len(self.docs)
        scores: list[tuple[str, float]] = []
        for i, doc in enumerate(self.docs):
            if not doc:
                continue
            tf = Counter(doc)
            dl = len(doc)
            score = 0.0
            for term in q_tokens:
                if term not in tf:
                    continue
                df = self.df.get(term, 0)
                if df == 0:
                    continue
                idf = math.log((n - df + 0.5) / (df + 0.5) + 1.0)
                tf_term = tf[term]
                denom = tf_term + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1))
                score += idf * (tf_term * (self.k1 + 1)) / denom
            if score > 0:
                scores.append((self.ids[i], score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]


class HybridRetriever:
    """BM25 + (optional) vector semantic search with metadata filtering.

    Fusion algorithm: Reciprocal Rank Fusion (RRF, Cormack et al. 2009),
    a simple-but-strong combiner that doesn't need per-engine score calibration.
    """

    def __init__(self, *, vector_persist_path: str | None = None):
        self.bm25 = BM25Index()
        self._entries: dict[str, KnowledgeEntry] = {}
        self._vector_store = None
        self._vector_persist_path = vector_persist_path

    def _ensure_vector_store(self):
        if self._vector_store is not None:
            return self._vector_store
        try:
            from .vectorstore import ChromaVectorStore
            self._vector_store = ChromaVectorStore(
                persist_path=self._vector_persist_path
            )
            log.info("Chroma vector store ready (size=%d)", self._vector_store.size())
        except ImportError:
            log.info("chromadb not installed; vector search disabled, falling back to BM25 only")
            self._vector_store = False  # mark as unavailable
        except Exception as e:  # noqa: BLE001
            log.warning("vector store init failed: %s; staying BM25-only", e)
            self._vector_store = False
        return self._vector_store

    def index(self, entries: list[KnowledgeEntry]) -> None:
        self._entries = {e.id: e for e in entries}
        self.bm25.build(entries)
        log.info("indexed %d entries (BM25)", len(entries))
        # Best-effort vector index population
        store = self._ensure_vector_store()
        if store and store is not False:
            try:
                ids = [e.id for e in entries]
                docs = [f"{e.title}\n{e.summary}" for e in entries]
                metas = [{
                    "category": e.category,
                    "year": e.year or 0,
                    "type": e.type.value,
                } for e in entries]
                store.upsert(ids, docs, metas)
                log.info("indexed %d entries (vector)", len(entries))
            except Exception as e:  # noqa: BLE001
                log.warning("vector index population failed: %s", e)

    def search(self, query: str, *,
               category: str | None = None,
               year_range: tuple[int, int] | None = None,
               entry_type: str | None = None,
               top_k: int = 10) -> list[KnowledgeEntry]:
        """Hybrid search with optional metadata filters.

        Strategy: get top-K from each available retriever, fuse with RRF,
        then apply post-filters (metadata is cheap to check after ranking).
        """
        bm25_hits = self.bm25.search(query, top_k=top_k * 4)
        vector_hits: list[tuple[str, float]] = []
        store = self._ensure_vector_store()
        if store and store is not False:
            try:
                where = {}
                if category:
                    where["category"] = category
                if entry_type:
                    where["type"] = entry_type
                vector_hits = store.query(query, top_k=top_k * 4,
                                           where=where or None)
            except Exception as e:  # noqa: BLE001
                log.warning("vector query failed: %s; using BM25 only", e)

        fused = _rrf_fuse([h[0] for h in bm25_hits],
                           [h[0] for h in vector_hits],
                           k=60)
        results: list[KnowledgeEntry] = []
        for entry_id in fused:
            e = self._entries.get(entry_id)
            if not e:
                continue
            if category and e.category != category:
                continue
            if entry_type and e.type.value != entry_type:
                continue
            if year_range and e.year is not None:
                lo, hi = year_range
                if not (lo <= e.year <= hi):
                    continue
            results.append(e)
            if len(results) >= top_k:
                break
        return results


def _rrf_fuse(*rank_lists: list[str], k: int = 60) -> list[str]:
    """Reciprocal Rank Fusion: combine N ranked id lists into a single ranking.

    Score(id) = sum over rank lists of 1 / (k + rank). Ties broken by score.
    """
    scores: dict[str, float] = {}
    for ranked in rank_lists:
        for rank, doc_id in enumerate(ranked):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank + 1)
    return [doc_id for doc_id, _ in
            sorted(scores.items(), key=lambda x: x[1], reverse=True)]


# Singleton retriever shared across the app
_default = HybridRetriever()


def index_all(entries: list[KnowledgeEntry]) -> None:
    _default.index(entries)


def search(query: str, **kwargs) -> list[KnowledgeEntry]:
    return _default.search(query, **kwargs)
