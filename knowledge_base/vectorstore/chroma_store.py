"""Vector store backed by Chroma's embedded mode.

Gracefully degrades when chromadb or a sentence-transformers model isn't
available; in that case the retriever stays BM25-only and the rest of the
system keeps working.
"""
from __future__ import annotations
import logging
from typing import Iterable, Sequence

log = logging.getLogger(__name__)


class ChromaVectorStore:
    """Thin wrapper around chromadb's embedded client.

    Embeddings are computed by Chroma's default ONNX sentence-transformer
    (multilingual MiniLM). No external API calls.
    """
    def __init__(self, persist_path: str | None = None,
                 collection_name: str = "kb_entries"):
        try:
            import chromadb
        except ImportError as e:
            raise ImportError(
                "chromadb is not installed; vector search disabled"
            ) from e
        if persist_path:
            self._client = chromadb.PersistentClient(path=persist_path)
        else:
            self._client = chromadb.Client()
        self._collection = self._client.get_or_create_collection(collection_name)

    def upsert(self, ids: Sequence[str], documents: Sequence[str],
               metadatas: Sequence[dict]) -> None:
        if not ids:
            return
        self._collection.upsert(
            ids=list(ids),
            documents=list(documents),
            metadatas=list(metadatas),
        )

    def query(self, text: str, top_k: int = 10,
              where: dict | None = None) -> list[tuple[str, float]]:
        """Return (id, similarity_score) tuples. Higher score = closer."""
        kwargs: dict = {"query_texts": [text], "n_results": top_k}
        if where:
            kwargs["where"] = where
        result = self._collection.query(**kwargs)
        if not result or not result.get("ids"):
            return []
        ids = result["ids"][0]
        distances = result.get("distances", [[]])[0] or []
        # Chroma returns distance; convert to similarity for fusion
        pairs = []
        for i, doc_id in enumerate(ids):
            d = distances[i] if i < len(distances) else 1.0
            sim = 1.0 / (1.0 + max(d, 0.0))
            pairs.append((doc_id, sim))
        return pairs

    def size(self) -> int:
        return self._collection.count()
