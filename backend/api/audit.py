"""Audit log HTTP API: admin-only."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from sqlmodel import Session
from ..audit import query as audit_query, AuditKind
from ..auth.middleware import require_role
from ..auth.models import User, Role
from ..db import get_session

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_events(kind: AuditKind | None = None,
                actor_id: int | None = None,
                limit: int = Query(100, le=1000),
                _admin: User = Depends(require_role(Role.admin)),
                session: Session = Depends(get_session)):
    events = audit_query(kind=kind, actor_id=actor_id,
                          limit=limit, session=session)
    return [{
        "id": e.id,
        "kind": e.kind.value,
        "actor_id": e.actor_id,
        "actor_username": e.actor_username,
        "object_kind": e.object_kind,
        "object_id": e.object_id,
        "ip": e.ip,
        "detail": e.detail,
        "created_at": e.created_at.isoformat(),
    } for e in events]
