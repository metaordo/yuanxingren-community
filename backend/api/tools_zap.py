"""External tool invocation endpoints (currently ZAP-only).

Exposes a small surface so the frontend can launch and poll a real ZAP scan
against an authorized target without going through the LLM/orchestrator.

The orchestrator path remains the right thing for chat-driven workflows; this
module is the "button" path for deterministic UI-driven scans.
"""
from __future__ import annotations
import logging
import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..auth.middleware import get_current_user
from ..auth.models import User, Role
from ..audit.service import record as audit_record
from ..audit.models import AuditKind
from ..db import get_session
from ..targets.models import Target, TargetType
from ..targets.scope_manager import AuthScope
from ..targets import parser as target_parser
from ..targets import validator as target_validator
from ..plugins import get_tool
from ..tools.external_pentest.adapters.zap import ZapTransientError
from ..tools.zap_models import ZapScan

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tools/zap", tags=["tools-zap"])


# ---------- request/response schemas ----------

class ScanStartIn(BaseModel):
    target_id: int = Field(..., ge=1)
    wait_spider_secs: int = Field(0, ge=0, le=120,
                                   description="Block until spider finishes, capped here.")


class ScanStartOut(BaseModel):
    target_id: int
    target_url: str
    spider_id: str
    ascan_id: str
    spider_seconds_waited: float
    zap_version: str


class ScanStatusOut(BaseModel):
    target_url: str
    spider_status: str | None = None
    ascan_status: str | None = None
    spider_urls: int = 0
    num_alerts: int = 0
    alerts: list[dict] = []


# ---------- helpers ----------

def _get_zap_adapter():
    wrapper = get_tool("zap")
    if wrapper is None:
        raise HTTPException(status_code=503, detail="ZAP tool not registered")
    if not getattr(wrapper, "_configured", False):
        raise HTTPException(status_code=503,
                            detail="ZAP not configured (PA_ZAP_BASE_URL missing?)")
    if not wrapper.health_check().ok:
        raise HTTPException(status_code=503, detail="ZAP daemon not reachable")
    return wrapper._adapter


def _authorize_target_url(session: Session, user: User, target_id: int) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    if target.owner_id != user.id and user.role != Role.admin:
        raise HTTPException(status_code=403, detail="target not owned by you")
    if target.type != TargetType.url:
        raise HTTPException(status_code=400,
                            detail=f"ZAP only scans url targets (got {target.type})")
    scope = session.exec(select(AuthScope)
                          .where(AuthScope.owner_id == target.owner_id)).first()
    hosts = scope.hosts if scope else []
    cidrs = scope.cidrs if scope else []
    parsed = target_parser.parse(target.value)
    try:
        target_validator.validate_against_scope(parsed, hosts, cidrs)
    except Exception as e:
        raise HTTPException(status_code=403, detail=f"target out of authorized scope: {e}")
    return target


def _slim_alert(a: dict) -> dict:
    """Reduce a ZAP alert to UI-friendly fields."""
    evidence = a.get("evidence", "") or ""
    if len(evidence) > 240:
        evidence = evidence[:240] + "…"
    desc = a.get("description", "") or ""
    if len(desc) > 360:
        desc = desc[:360] + "…"
    return {
        "name": a.get("name", ""),
        "risk": a.get("risk", ""),
        "confidence": a.get("confidence", ""),
        "url": a.get("url", ""),
        "param": a.get("param", ""),
        "evidence": evidence,
        "description": desc,
        "cweid": a.get("cweid", ""),
        "wascid": a.get("wascid", ""),
        "solution": (a.get("solution") or "")[:240],
    }


# ---------- endpoints ----------

@router.post("/scan", response_model=ScanStartOut)
def start_scan(data: ScanStartIn,
               request: Request,
               user: User = Depends(get_current_user),
               session: Session = Depends(get_session)):
    """Kick off accessUrl → spider → ascan against an authorized URL target."""
    if user.role == Role.viewer:
        raise HTTPException(status_code=403, detail="viewer cannot launch scans")
    target = _authorize_target_url(session, user, data.target_id)
    adapter = _get_zap_adapter()

    url = target.value
    adapter.access_url(url)  # ensures root is in site tree (~1s)
    spider_id = adapter.start_spider(url)

    spider_wait = 0.0
    if data.wait_spider_secs > 0:
        t0 = time.time()
        deadline = t0 + data.wait_spider_secs
        while time.time() < deadline:
            if adapter.spider_status(spider_id) == "100":
                break
            time.sleep(1.0)
        spider_wait = time.time() - t0

    ascan_id = adapter.start_ascan(url)

    audit_record(
        AuditKind.tool_invoke,
        actor_id=user.id,
        actor_username=user.username,
        object_kind="target",
        object_id=str(target.id),
        ip=request.client.host if request.client else None,
        detail={"tool": "zap", "target_url": url,
                "spider_id": spider_id, "ascan_id": ascan_id},
    )
    return ScanStartOut(
        target_id=target.id,
        target_url=url,
        spider_id=spider_id,
        ascan_id=ascan_id,
        spider_seconds_waited=round(spider_wait, 1),
        zap_version=adapter.version(),
    )


@router.get("/scan/status", response_model=ScanStatusOut)
def scan_status(
    target_url: str = Query(..., min_length=1, max_length=2048),
    spider_id: str | None = Query(None, max_length=32),
    ascan_id: str | None = Query(None, max_length=32),
    include_alerts: bool = Query(True),
    alert_limit: int = Query(60, ge=1, le=2000),
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Poll spider + ascan progress and (optionally) the latest alerts.

    Degrades gracefully when the ZAP daemon is busy: a transient timeout on
    any sub-call returns 200 with whatever progress fields we managed to
    fetch (others as null / 0), so the frontend polling loop keeps running
    instead of treating one slow tick as a fatal error.

    The alerts endpoint (`/core/view/numberOfAlerts/?baseurl=...`) is the
    slowest under load — ZAP linearly scans the alerts table while spider
    keeps writing to it. We skip that call entirely until spider hits 100%.
    """
    _check_url_authorized(session, user, target_url)
    adapter = _get_zap_adapter()

    spider_status: str | None = None
    ascan_status: str | None = None
    num = 0
    alerts: list[dict] = []

    spider_urls = 0
    if spider_id:
        try:
            spider_status = adapter.spider_status(spider_id)
        except ZapTransientError as e:
            log.warning("zap spider_status transient failure: %s", e)
        try:
            spider_urls = adapter.spider_results_count(spider_id)
        except ZapTransientError as e:
            log.warning("zap spider_results transient failure: %s", e)
    if ascan_id:
        try:
            ascan_status = adapter.ascan_status(ascan_id)
        except ZapTransientError as e:
            log.warning("zap ascan_status transient failure: %s", e)

    # Only ask for alerts once spider is finished — otherwise the daemon
    # holds the alerts-table read open for tens of seconds and we 500 out.
    spider_done = spider_status == "100"
    if spider_done:
        try:
            num = adapter.number_of_alerts(target_url)
        except ZapTransientError as e:
            log.warning("zap number_of_alerts transient failure: %s", e)
            num = 0
        if include_alerts and num > 0:
            try:
                raw = adapter.get_alerts(target_url)
                alerts = [_slim_alert(a) for a in raw[:alert_limit]]
            except ZapTransientError as e:
                log.warning("zap get_alerts transient failure: %s", e)
                alerts = []

    return ScanStatusOut(target_url=target_url,
                          spider_status=spider_status,
                          ascan_status=ascan_status,
                          spider_urls=spider_urls,
                          num_alerts=num,
                          alerts=alerts)


def _check_url_authorized(session: Session, user: User, target_url: str) -> None:
    """Make sure the URL string the client sent is within the user's auth scope.

    Prevents a logged-in user from pointing the polling endpoint at an unrelated
    URL just by guessing it.
    """
    scope = session.exec(select(AuthScope).where(AuthScope.owner_id == user.id)).first()
    hosts = scope.hosts if scope else []
    cidrs = scope.cidrs if scope else []
    parsed = target_parser.parse(target_url)
    try:
        target_validator.validate_against_scope(parsed, hosts, cidrs)
    except Exception as e:
        raise HTTPException(status_code=403,
                            detail=f"url out of authorized scope: {e}")


# ---------- persist a completed scan ----------

class FinalizeIn(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048)
    target_id: int | None = None
    spider_id: str | None = Field(None, max_length=32)
    ascan_id: str | None = Field(None, max_length=32)


class FinalizeOut(BaseModel):
    scan_id: int
    num_alerts: int


_RISK_ORDER = ("High", "Medium", "Low", "Informational")


@router.post("/finalize", response_model=FinalizeOut)
def finalize_scan(data: FinalizeIn, request: Request,
                  user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)) -> FinalizeOut:
    """Persist a completed X-Scan's alert snapshot for later admin review.

    Called by the frontend once ascan hits 100%. Alerts are re-fetched
    server-side (never trusting client-submitted findings). Idempotent on
    (owner_id, ascan_id): a repeat call updates the existing row.
    """
    if user.role == Role.viewer:
        raise HTTPException(status_code=403, detail="viewer cannot launch scans")
    _check_url_authorized(session, user, data.target_url)
    adapter = _get_zap_adapter()

    try:
        raw = adapter.get_alerts(data.target_url)
    except ZapTransientError as e:
        raise HTTPException(status_code=503, detail=f"ZAP busy, retry: {e}")
    alerts = [_slim_alert(a) for a in raw]
    risk_summary: dict[str, int] = {}
    for a in alerts:
        risk = a.get("risk") or "Informational"
        risk_summary[risk] = risk_summary.get(risk, 0) + 1

    row = None
    if data.ascan_id:
        row = session.exec(
            select(ZapScan).where(ZapScan.owner_id == user.id,
                                  ZapScan.ascan_id == data.ascan_id)).first()
    if row is None:
        row = ZapScan(owner_id=user.id, target_id=data.target_id,
                      target_url=data.target_url,
                      spider_id=data.spider_id, ascan_id=data.ascan_id)
    row.status = "done"
    row.num_alerts = len(alerts)
    row.risk_summary = risk_summary
    row.alerts_json = alerts
    row.finished_at = datetime.utcnow()
    session.add(row)
    session.commit()
    session.refresh(row)

    audit_record(
        AuditKind.zap_scan,
        actor_id=user.id, actor_username=user.username,
        object_kind="zap_scan", object_id=str(row.id),
        ip=request.client.host if request.client else None,
        detail={"target_url": data.target_url, "num_alerts": len(alerts),
                "risk_summary": risk_summary},
        session=session)
    return FinalizeOut(scan_id=row.id, num_alerts=len(alerts))
