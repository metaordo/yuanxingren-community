"""Knowledge base HTTP API: search + admin ingestion."""
from __future__ import annotations
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Query
from ..auth.middleware import get_current_user, require_role
from ..auth.models import User, Role
from knowledge_base import retriever
from knowledge_base.ingestion import ingest_references, all_entries

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=500),
           category: str | None = None,
           entry_type: str | None = None,
           top_k: int = 10,
           _user: User = Depends(get_current_user)):
    hits = retriever.search(q, category=category,
                            entry_type=entry_type, top_k=top_k)
    return {
        "query": q,
        "count": len(hits),
        "hits": [{
            "id": h.id,
            "title": h.title,
            "type": h.type.value,
            "category": h.category,
            "year": h.year,
            "summary": h.summary[:300],
            "url": h.url,
        } for h in hits]
    }


@router.get("/list")
def list_entries(category: str | None = None,
                 entry_type: str | None = None,
                 _user: User = Depends(get_current_user)):
    """Browse the full knowledge index. Used by the directory view in the UI.

    Returns the whole set in one response (~200 KB for 403 entries) so the
    frontend can group / filter locally. Optional category / entry_type
    query params let callers narrow server-side when full set isn't needed.
    """
    entries = all_entries()
    if category:
        entries = [e for e in entries if e.category == category]
    if entry_type:
        entries = [e for e in entries if e.type.value == entry_type]
    return {
        "total": len(entries),
        "entries": [{
            "id": e.id,
            "title": e.title,
            "type": e.type.value,
            "category": e.category,
            "year": e.year,
            "venue": e.venue,
            "url": e.url,
            "summary": e.summary,
            "attack_surface": e.attack_surface,
            "mitigations": e.mitigations,
            "cves": e.cves,
        } for e in entries]
    }


@router.post("/ingest")
def ingest(path: str,
           _admin: User = Depends(require_role(Role.admin))):
    """Ingest a references.md file. Admin-only."""
    p = Path(path)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"file not found: {path}")
    count = ingest_references(p)
    # Rebuild BM25 index after ingestion
    retriever.index_all(all_entries())
    return {"ingested": count, "total": len(all_entries())}
