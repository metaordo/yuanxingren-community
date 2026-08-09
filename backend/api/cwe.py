"""CWE knowledge base HTTP API.

Five endpoints under prefix /api/cwe — see plan doc. Reads go through the
module singleton knowledge_base.cwe.storage.store; search goes through the
retriever singleton. /refresh re-runs the parser and rebuilds both.
"""
from __future__ import annotations
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from ..auth.middleware import get_current_user, require_role
from ..auth.models import User, Role

# Path adjustment — knowledge_base lives at repo root, not under backend/
import sys as _sys
_sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.cwe import retriever as cwe_retriever
from knowledge_base.cwe.storage import store as cwe_store
from knowledge_base.cwe.schema import CweEntry

router = APIRouter(prefix="/api/cwe", tags=["cwe"])


def _to_node(e: CweEntry) -> dict:
    """Lightweight node for tree/list endpoints. Excludes detail blob."""
    return {
        "id": e.id,
        "name": e.name,
        "abstraction": e.abstraction,
        "status": e.status,
        "has_children": bool(e.children),
        "parents": e.parents,
    }


def _to_full(e: CweEntry) -> dict:
    """Full entry for detail endpoint."""
    return {
        "id": e.id,
        "name": e.name,
        "abstraction": e.abstraction,
        "structure": e.structure,
        "status": e.status,
        "description": e.description,
        "extended_description": e.extended_description,
        "likelihood": e.likelihood,
        "parents": e.parents,
        "children": e.children,
        "peers": e.peers,
        "consequences": e.consequences,
        "mitigations": e.mitigations,
        "detection_methods": e.detection_methods,
        "demonstrative_examples": e.demonstrative_examples,
        "applicable_platforms": e.applicable_platforms,
        "capec_ids": e.capec_ids,
        "references": e.references,
    }


@router.get("/tree/roots")
def tree_roots(_user: User = Depends(get_current_user)):
    """All Pillar nodes — top of the CWE tree."""
    return {"roots": [_to_node(e) for e in cwe_store.get_pillars()]}


@router.get("/list")
def list_entries(abstraction: str | None = None,
                 parent_id: str | None = None,
                 status: str | None = None,
                 _user: User = Depends(get_current_user)):
    """Filtered list. parent_id is the lazy-load knob for tree expansion.
    Without filters returns the whole corpus (~969 nodes)."""
    if parent_id:
        entries = cwe_store.get_children(parent_id)
    elif abstraction:
        entries = cwe_store.list_by_abstraction(abstraction)
    else:
        entries = cwe_store.all()
    if status:
        entries = [e for e in entries if e.status == status]
    return {"total": len(entries), "entries": [_to_node(e) for e in entries]}


@router.get("/search")
def search(q: str = Query(..., min_length=1, max_length=500),
           abstraction: str | None = None,
           status: str | None = None,
           parent_id: str | None = None,
           top_k: int = 30,
           _user: User = Depends(get_current_user)):
    hits = cwe_retriever.search(q, abstraction=abstraction, status=status,
                                parent_id=parent_id, top_k=top_k)
    return {"query": q, "count": len(hits), "hits": [_to_node(h) for h in hits]}


@router.get("/{cwe_id}")
def detail(cwe_id: str, _user: User = Depends(get_current_user)):
    """Full payload by id. Accepts 'CWE-79' or '79'."""
    e = cwe_store.get(cwe_id)
    if not e:
        raise HTTPException(status_code=404, detail=f"CWE not found: {cwe_id}")
    return {"entry": _to_full(e)}


@router.post("/refresh", status_code=202)
def refresh(_admin: User = Depends(require_role(Role.admin))):
    """Re-parse XML and rebuild index. Admin-only.

    Reads PA_CWE_XML or defaults to data/cwe/cwec_latest.xml at the repo root.
    """
    from knowledge_base.cwe.parser import parse_cwec_xml
    xml_path = Path(os.environ.get("PA_CWE_XML")
                    or Path(__file__).resolve().parents[2] / "data" / "cwe" / "cwec_latest.xml")
    if not xml_path.exists():
        raise HTTPException(status_code=503, detail=f"CWE XML not available at {xml_path}")
    entries = parse_cwec_xml(xml_path)
    cwe_store.bulk_insert(entries, force=True)
    cwe_retriever.index_all(cwe_store.all())
    return {"refreshed": len(entries), "source": str(xml_path)}
