"""BM25 search over the CWE corpus.

Wraps `knowledge_base.retriever.BM25Index` (which already has CJK bigram +
ASCII word tokenization) by feeding it lightweight shim docs that duck-type
the `.id`/`.title`/`.summary` attributes BM25Index reads. Filters on
abstraction / status / parent_id are applied post-rank against the cached
`CweEntry` objects.
"""
from __future__ import annotations
from dataclasses import dataclass

from knowledge_base.retriever import BM25Index

from .schema import CweEntry


@dataclass
class _BM25Doc:
    """Minimal duck-type for BM25Index.build(); not exported."""
    id: str
    title: str
    summary: str


def _to_doc(e: CweEntry) -> _BM25Doc:
    """Combine description + extended_description into one searchable blob.

    The CWE name is used as the title (BM25Index already concatenates title
    and summary before tokenizing, so both are searched).
    """
    summary = " ".join(filter(None, [e.description, e.extended_description]))
    return _BM25Doc(id=e.id, title=e.name, summary=summary)


class CweRetriever:
    """BM25 search over CWE corpus (id + name + description + extended_description).

    Filters (abstraction, status, parent_id) are applied post-rank.
    """

    def __init__(self) -> None:
        self._bm25 = BM25Index()
        self._entries: dict[str, CweEntry] = {}

    def index(self, entries: list[CweEntry]) -> None:
        """Build the BM25 index and cache entries by id for hydration."""
        self._entries = {e.id: e for e in entries}
        self._bm25.build([_to_doc(e) for e in entries])

    def search(
        self,
        query: str,
        *,
        abstraction: str | None = None,
        status: str | None = None,
        parent_id: str | None = None,
        top_k: int = 20,
    ) -> list[CweEntry]:
        """BM25 search, returns CweEntry list ordered by score desc.

        Filters drop entries that don't match. top_k is applied AFTER filtering,
        so the underlying BM25 is queried for a generously larger candidate
        pool to avoid the filters starving the result list.
        """
        # Pull a wider candidate set so post-filtering still has signal.
        # Use the corpus size as the upper bound when filters are active.
        if abstraction or status or parent_id:
            candidate_k = max(top_k * 4, len(self._entries))
        else:
            candidate_k = top_k
        raw = self._bm25.search(query, top_k=candidate_k)
        results: list[CweEntry] = []
        for entry_id, _score in raw:
            e = self._entries.get(entry_id)
            if e is None:
                continue
            if abstraction is not None and e.abstraction != abstraction:
                continue
            if status is not None and e.status != status:
                continue
            if parent_id is not None and parent_id not in e.parents:
                continue
            results.append(e)
            if len(results) >= top_k:
                break
        return results


# Module-level singleton + functional facade matching knowledge_base.retriever
_default = CweRetriever()


def index_all(entries: list[CweEntry]) -> None:
    _default.index(entries)


def search(query: str, **kwargs) -> list[CweEntry]:
    return _default.search(query, **kwargs)
