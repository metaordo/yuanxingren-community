"""Audit log service: thin write helper + query API."""
from __future__ import annotations
import logging
from contextlib import contextmanager
from typing import Optional
from sqlmodel import Session, select, desc
from ..db import engine
from .models import AuditEvent, AuditKind

log = logging.getLogger(__name__)


@contextmanager
def _maybe_session(existing: Optional[Session]):
    """Use an existing session if provided, otherwise open a fresh one."""
    if existing is not None:
        yield existing
        return
    with Session(engine) as s:
        yield s


def record(kind: AuditKind, *,
           actor_id: int | None = None,
           actor_username: str | None = None,
           object_kind: str | None = None,
           object_id: str | None = None,
           ip: str | None = None,
           detail: dict | None = None,
           session: Session | None = None) -> None:
    """Insert an audit event. Never raises — audit must never block business logic."""
    try:
        event = AuditEvent(
            kind=kind,
            actor_id=actor_id,
            actor_username=actor_username,
            object_kind=object_kind,
            object_id=object_id,
            ip=ip,
            detail=detail or {},
        )
        with _maybe_session(session) as s:
            s.add(event)
            s.commit()
    except Exception as e:  # noqa: BLE001
        # Audit failures must not kill the request; log and move on.
        log.error("audit write failed for kind=%s: %s", kind, e)


def query(*, kind: AuditKind | None = None,
          actor_id: int | None = None,
          limit: int = 100,
          session: Session | None = None) -> list[AuditEvent]:
    """Return the most recent matching audit events."""
    with _maybe_session(session) as s:
        stmt = select(AuditEvent)
        if kind is not None:
            stmt = stmt.where(AuditEvent.kind == kind)
        if actor_id is not None:
            stmt = stmt.where(AuditEvent.actor_id == actor_id)
        stmt = stmt.order_by(desc(AuditEvent.created_at)).limit(limit)
        return list(s.exec(stmt).all())
