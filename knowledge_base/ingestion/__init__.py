"""Ingest references.md into an in-memory store (later: persist to Chroma/Qdrant)."""
from __future__ import annotations
import logging
from pathlib import Path
from .references_parser import parse_file
from ..schema.entry import KnowledgeEntry

log = logging.getLogger(__name__)

# In-memory store for MVP; later replace with Chroma/Qdrant
_entries: dict[str, KnowledgeEntry] = {}


def ingest_references(path: Path) -> int:
    """Parse references.md and store entries. Returns count."""
    count = 0
    for entry in parse_file(path):
        _entries[entry.id] = entry
        count += 1
    log.info("ingested %d entries from %s", count, path)
    return count


def get_entry(entry_id: str) -> KnowledgeEntry | None:
    return _entries.get(entry_id)


def search_by_keyword(keyword: str, limit: int = 10) -> list[KnowledgeEntry]:
    """Simple keyword search in title/summary. Later: BM25 + vector."""
    kw = keyword.lower()
    matches = [e for e in _entries.values()
               if kw in e.title.lower() or kw in e.summary.lower()]
    return matches[:limit]


def all_entries() -> list[KnowledgeEntry]:
    return list(_entries.values())
