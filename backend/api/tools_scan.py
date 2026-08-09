"""Unified scan API: routes targets to the right engine (ZAP or Nmap)."""
from __future__ import annotations
import logging
import threading
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..auth.middleware import get_current_user
from ..auth.models import User, Role
from ..db import get_session
from ..targets.validator import validate_against_scope, AuthorizationError
from ..targets.parser import parse as parse_target
from ..targets.models import TargetType, Target
from ..targets.scope_manager import AuthScope
from ..audit import record as audit_record, AuditKind

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tools/scan", tags=["scan"])

# In-memory scan state (keyed by scan_id)
_scans: dict[int, dict] = {}
_scan_id_seq = 0


class ScanStartIn(BaseModel):
    target_id: int = Field(..., ge=1)
    options: dict = Field(default_factory=dict)


class ScanStartOut(BaseModel):
    scan_id: int
    target_type: str
    engine: str  # "zap" or "nmap"


class ScanFinalizeIn(BaseModel):
    scan_id: int = Field(..., ge=1)


class ScanFinalizeOut(BaseModel):
    scan_id: int
    result: dict | None


def _get_scope(session: Session, user_id: int) -> AuthScope | None:
    return session.exec(select(AuthScope).where(AuthScope.owner_id == user_id)).first()


def _validate_target(target: Target, user: User, session: Session) -> None:
    """Auth scope check for scan targets."""
    parsed = parse_target(target.value)
    scope = _get_scope(session, user.id)
    if user.role != Role.admin and scope:
        allow_hosts = scope.hosts if scope else []
        allow_cidrs = scope.cidrs if scope else []
        try:
            validate_against_scope(parsed, allow_hosts, allow_cidrs)
        except AuthorizationError as e:
            raise HTTPException(status_code=403,
                                detail=f"target out of authorized scope: {e}")


@router.post("", response_model=ScanStartOut)
def start_scan(data: ScanStartIn,
               user: User = Depends(get_current_user),
               session: Session = Depends(get_session)):
    """Unified scan entry point — routes to ZAP or Nmap by target type."""
    if user.role == Role.viewer:
        raise HTTPException(status_code=403, detail="viewers cannot launch scans")

    target = session.get(Target, data.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    if target.owner_id != user.id and user.role != Role.admin:
        raise HTTPException(status_code=403, detail="not your target")

    _validate_target(target, user, session)

    parsed = parse_target(target.value)

    # Route to engine
    if parsed.type == TargetType.url:
        engine = "zap"
    elif parsed.type in (TargetType.ip, TargetType.domain, TargetType.protocol):
        engine = "nmap"
    else:
        raise HTTPException(status_code=400,
                            detail=f"target type {parsed.type.value} not supported for scan")

    global _scan_id_seq  # noqa: PLW0603
    _scan_id_seq += 1
    scan_id = _scan_id_seq
    _scans[scan_id] = {
        "scan_id": scan_id,
        "target_id": target.id,
        "target_value": target.value,
        "target_type": parsed.type.value,
        "engine": engine,
        "status": "pending",
        "phases": {},
        "result": None,
        "error": None,
    }

    audit_record(AuditKind.tool_invoke,
                 actor_id=user.id, actor_username=user.username,
                 object_kind="scan", object_id=str(scan_id),
                 detail={"engine": engine, "target": target.value, "type": parsed.type.value},
                 session=session)

    # Launch scan in background thread
    threading.Thread(
        target=_run_scan, args=(scan_id, target, parsed, engine, data.options),
        daemon=True,
    ).start()

    return ScanStartOut(scan_id=scan_id, target_type=parsed.type.value, engine=engine)


def _run_scan(scan_id: int, target: Target, parsed, engine: str, options: dict) -> None:
    """Run the scan in background and update _scans state."""
    state = _scans.get(scan_id)
    if not state:
        return
    state["status"] = "running"

    try:
        if engine == "zap":
            result = _run_zap_scan(target, options)
        elif engine == "nmap":
            result = _run_nmap_scan(parsed.value, options)
        else:
            raise ValueError(f"unknown engine: {engine}")
        state["status"] = "done"
        state["result"] = result
    except Exception as e:
        log.exception("scan %d failed", scan_id)
        state["status"] = "error"
        state["error"] = str(e)


def _run_zap_scan(target: Target, options: dict) -> dict:
    """Delegate to existing ZAP adapter via its API internals.

    For full-featured ZAP scanning, use the existing /api/tools/zap endpoints
    directly. This stub exists so the unified scan API can route URL targets
    consistently while reusing the battle-tested ZAP integration.
    """
    # We reuse the ZAP endpoint logic by calling its functions directly
    from .tools_zap import _authorize_target_url, _get_zap_adapter

    # Build a minimal request context — the ZAP scan functions need a Request
    # object for audit logging, but we can call the adapter layer directly.
    raise NotImplementedError(
        "ZAP scan delegation via unified API is not yet implemented. "
        "Use the existing /api/tools/zap/scan endpoint for URL targets."
    )


def _run_nmap_scan(target_value: str, options: dict) -> dict:
    """Run Nmap 3-phase pipeline: port scan, NSE vuln, CVE lookup."""
    from ..tools.external_pentest.adapters.nmap import NmapAdapter
    adapter = NmapAdapter()
    adapter.setup({})

    # Phase 1+2: run nmap with phases (blocking, we're already in a bg thread)
    nmap_result = adapter.run_with_phases(target_value, options)

    # Phase 3: CVE lookup
    services = nmap_result.get("services", [])
    cve_results = []
    if services:
        try:
            from ..knowledge_base.cve.storage import CveStore
            from ..knowledge_base.cve.retriever import CveRetriever
            import os
            data_dir = os.environ.get("PA_DATA_DIR", os.path.join(
                os.path.dirname(__file__), "..", "..", "data"))
            db_path = os.path.join(data_dir, "cve_index.db")
            store = CveStore(db_path)
            retriever = CveRetriever(store)
            cve_results = retriever.search_batch(services)
        except Exception as e:
            log.warning("CVE lookup skipped: %s", e)

    return {
        "hosts": nmap_result.get("hosts", []),
        "services": services,
        "nse_vulns": nmap_result.get("phase2", {}).get("vulns", []),
        "cve_matches": cve_results,
    }


@router.get("/status")
def scan_status(scan_id: int,
                user: User = Depends(get_current_user),
                session: Session = Depends(get_session)):
    """Poll the status of a previously launched scan."""
    state = _scans.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="scan not found")
    return {
        "scan_id": state["scan_id"],
        "status": state["status"],
        "engine": state["engine"],
        "phases": state.get("phases", {}),
        "result": state.get("result"),
        "error": state.get("error"),
    }
