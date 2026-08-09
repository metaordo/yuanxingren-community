from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..auth.middleware import get_current_user
from ..auth.models import User, Role
from ..audit import record as audit_record, AuditKind
from ..db import get_session
from ..uploads.models import UploadedFile
from . import parser as target_parser
from . import validator as target_validator
from .models import Target, TargetType
from .scope_manager import AuthScope

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=2048)
    type_hint: str | None = None
    authorized: bool = False
    scope: dict = Field(default_factory=dict)
    auth: dict = Field(default_factory=dict)


class TargetOut(BaseModel):
    id: int
    type: TargetType
    value: str
    authorized: bool


def _get_scope(session: Session, user_id: int) -> AuthScope | None:
    return session.exec(select(AuthScope).where(AuthScope.owner_id == user_id)).first()


@router.post("", response_model=TargetOut)
def create_target(data: TargetIn,
                  request: Request,
                  user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)):
    if not data.authorized:
        raise HTTPException(status_code=400,
                            detail="you must confirm authorization for the target")
    try:
        parsed = target_parser.parse(data.value, hint=data.type_hint)
    except target_parser.ParseError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scope = _get_scope(session, user.id) if user.role != Role.admin else _get_scope(session, user.id)
    allow_hosts = scope.hosts if scope else []
    allow_cidrs = scope.cidrs if scope else []
    try:
        target_validator.validate_against_scope(parsed, allow_hosts, allow_cidrs)
    except target_validator.AuthorizationError as e:
        raise HTTPException(status_code=403, detail=f"out of authorized scope: {e}")

    t = Target(type=parsed.type, value=parsed.value,
               owner_id=user.id, authorized=True,
               scope=data.scope, auth=data.auth)
    session.add(t)
    session.commit()
    session.refresh(t)
    audit_record(AuditKind.target_create,
                 actor_id=user.id, actor_username=user.username,
                 object_kind="target", object_id=str(t.id),
                 ip=request.client.host if request.client else None,
                 detail={"type": t.type.value, "value": t.value},
                 session=session)
    return TargetOut(id=t.id, type=t.type, value=t.value, authorized=t.authorized)


@router.delete("/{target_id}")
def delete_target(target_id: int,
                  request: Request,
                  user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)):
    """Delete one of the caller's own targets.

    Only the row is removed; historical `AgentTask` / `AgentRun` rows keep
    their `target_id` (it's an index, not a FK) so audit trails stay intact.
    Underlying uploaded files are NOT touched — they can still be reused to
    re-create a target via /targets/from-upload.
    """
    t = session.get(Target, target_id)
    if t is None:
        raise HTTPException(status_code=404, detail="target not found")
    if t.owner_id != user.id and user.role != Role.admin:
        raise HTTPException(status_code=403, detail="not your target")
    snapshot = {"type": t.type.value, "value": t.value}
    session.delete(t)
    session.commit()
    audit_record(AuditKind.target_delete,
                 actor_id=user.id, actor_username=user.username,
                 object_kind="target", object_id=str(target_id),
                 ip=request.client.host if request.client else None,
                 detail=snapshot,
                 session=session)
    return {"ok": True, "id": target_id}


@router.get("")
def list_targets(user: User = Depends(get_current_user),
                  session: Session = Depends(get_session)):
    """List all authorized targets owned by the caller."""
    rows = session.exec(
        select(Target)
        .where(Target.owner_id == user.id)
        .order_by(Target.created_at.desc())  # type: ignore[union-attr]
    ).all()
    return [{
        "id": r.id,
        "type": r.type.value,
        "value": r.value,
        "authorized": r.authorized,
        "created_at": r.created_at.isoformat(),
    } for r in rows]


class AuthScopeIn(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    note: str | None = None


@router.put("/auth-scope")
def upsert_scope(data: AuthScopeIn,
                 request: Request,
                 user: User = Depends(get_current_user),
                 session: Session = Depends(get_session)):
    existing = _get_scope(session, user.id)
    if existing:
        existing.hosts = data.hosts
        existing.cidrs = data.cidrs
        existing.note = data.note
        session.add(existing)
    else:
        session.add(AuthScope(owner_id=user.id, hosts=data.hosts,
                              cidrs=data.cidrs, note=data.note))
    session.commit()
    audit_record(AuditKind.scope_update,
                 actor_id=user.id, actor_username=user.username,
                 ip=request.client.host if request.client else None,
                 detail={"hosts": data.hosts, "cidrs": data.cidrs,
                         "note": data.note},
                 session=session)
    return {"ok": True}


@router.get("/auth-scope")
def get_scope(user: User = Depends(get_current_user),
              session: Session = Depends(get_session)):
    sc = _get_scope(session, user.id)
    if not sc:
        return {"hosts": [], "cidrs": [], "note": None}
    return {"hosts": sc.hosts, "cidrs": sc.cidrs, "note": sc.note}


class TargetFromUploadIn(BaseModel):
    upload_id: int
    authorized: bool = False
    scope: dict = Field(default_factory=dict)
    auth: dict = Field(default_factory=dict)


@router.post("/from-upload", response_model=TargetOut)
def create_target_from_upload(data: TargetFromUploadIn,
                               request: Request,
                               user: User = Depends(get_current_user),
                               session: Session = Depends(get_session)):
    """Create a target referencing an uploaded file.

    Supported upload types → target types:
      source / archive / document → TargetType.source (whitebox audit material)
      binary                       → TargetType.binary
      pcap                         → TargetType.pcap

    Uploaded-file targets bypass the host/CIDR scope check because they are
    local artifacts the user already controls (no network egress involved).
    """
    if not data.authorized:
        raise HTTPException(status_code=400,
                            detail="you must confirm authorization for the target")
    uf = session.get(UploadedFile, data.upload_id)
    if not uf or uf.owner_id != user.id:
        raise HTTPException(status_code=404, detail="upload not found")
    type_map = {
        "source": TargetType.source,
        "archive": TargetType.source,
        "document": TargetType.source,
        "binary": TargetType.binary,
        "pcap": TargetType.pcap,
    }
    target_type = type_map.get(uf.file_type)
    if target_type is None:
        raise HTTPException(
            status_code=400,
            detail=f"upload type '{uf.file_type}' cannot be a target "
                    "(supported: source, archive, document, binary, pcap)")
    t = Target(type=target_type, value=uf.storage_path,
               owner_id=user.id, authorized=True,
               scope=data.scope, auth=data.auth,
               metadata_={"upload_id": uf.id, "filename": uf.filename,
                          "sha256": uf.sha256})
    session.add(t)
    session.commit()
    session.refresh(t)
    audit_record(AuditKind.target_create,
                 actor_id=user.id, actor_username=user.username,
                 object_kind="target", object_id=str(t.id),
                 ip=request.client.host if request.client else None,
                 detail={"type": t.type.value, "via_upload": uf.id,
                         "filename": uf.filename},
                 session=session)
    return TargetOut(id=t.id, type=t.type, value=t.value, authorized=t.authorized)
