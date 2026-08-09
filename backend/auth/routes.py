from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select
from . import service, jwt_handler, captcha
from .middleware import get_current_user, require_role
from .models import User, Role
from ..audit import record as audit_record, AuditKind
from ..db import get_session

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


class LoginInput(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)
    captcha_token: str = Field("", max_length=64)
    captcha_answer: str = Field("", max_length=8)


class ChangePasswordInput(BaseModel):
    old_password: str
    new_password: str


class CreateUserInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str
    role: Role = Role.operator


class UpdateUserInput(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    reset_password: str | None = None


class UserOut(BaseModel):
    id: int
    username: str
    role: Role
    is_active: bool = True
    must_change_password: bool


def _user_out(u: User) -> UserOut:
    return UserOut(id=u.id, username=u.username, role=u.role,
                   is_active=u.is_active,
                   must_change_password=u.must_change_password)


@router.get("/captcha")
def get_captcha():
    """Generate a new CAPTCHA image challenge."""
    cap = captcha.generate()
    return {"captcha_token": cap.token, "image_b64": cap.image_b64}


@router.post("/login")
def login(data: LoginInput, response: Response, request: Request,
          session: Session = Depends(get_session)):
    import os
    # Verify CAPTCHA before touching the password
    if not captcha.verify(data.captcha_token, data.captcha_answer):
        raise HTTPException(status_code=401, detail="验证码错误，请重试")
    ip = _client_ip(request)
    try:
        user = service.authenticate(session, data.username, data.password)
    except service.AuthError as e:
        audit_record(AuditKind.login_failure,
                     actor_username=data.username, ip=ip,
                     detail={"reason": str(e)}, session=session)
        raise HTTPException(status_code=401, detail=str(e))
    token = jwt_handler.issue(user.id, user.username, user.role.value)
    # Secure-cookie flag is driven by PA_COOKIE_SECURE so dev (http://) and
    # production (https://) both work without code changes.
    secure_cookie = os.environ.get("PA_COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
    response.set_cookie(
        "pa_token", token,
        httponly=True, samesite="strict",
        secure=secure_cookie,
        max_age=8 * 3600,
        path="/",
    )
    audit_record(AuditKind.login_success,
                 actor_id=user.id, actor_username=user.username, ip=ip,
                 session=session)
    return {"user": _user_out(user), "must_change_password": user.must_change_password}


@router.post("/logout")
def logout(response: Response, request: Request,
           user: User = Depends(get_current_user),
           session: Session = Depends(get_session)):
    response.delete_cookie("pa_token", path="/")
    audit_record(AuditKind.logout,
                 actor_id=user.id, actor_username=user.username,
                 ip=_client_ip(request), session=session)
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return _user_out(user)


@router.post("/change-password")
def change_password(data: ChangePasswordInput,
                    request: Request,
                    user: User = Depends(get_current_user),
                    session: Session = Depends(get_session)):
    try:
        service.change_password(session, user, data.old_password, data.new_password)
    except service.AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))
    audit_record(AuditKind.password_change,
                 actor_id=user.id, actor_username=user.username,
                 ip=_client_ip(request), session=session)
    return {"ok": True}



# @router.get("/users", response_model=list[UserOut])
# def list_users(_admin: User = Depends(require_role(Role.admin)),
#                session: Session = Depends(get_session)):
#     return [_user_out(u) for u in session.exec(select(User)).all()]


# @router.post("/users", response_model=UserOut)
# def create_user(data: CreateUserInput,
#                 request: Request,
#                 admin: User = Depends(require_role(Role.admin)),
#                 session: Session = Depends(get_session)):
#     try:
#         u = service.create_user(session, data.username, data.password, data.role)
#     except service.AuthError as e:
#         raise HTTPException(status_code=400, detail=str(e))
#     audit_record(AuditKind.user_create,
#                  actor_id=admin.id, actor_username=admin.username,
#                  object_kind="user", object_id=str(u.id),
#                  ip=_client_ip(request),
#                  detail={"username": u.username, "role": u.role.value},
#                  session=session)
#     return _user_out(u)


# @router.patch("/users/{user_id}", response_model=UserOut)
# def update_user(user_id: int, data: UpdateUserInput,
#                 request: Request,
#                 admin: User = Depends(require_role(Role.admin)),
#                 session: Session = Depends(get_session)):
#     u = session.get(User, user_id)
#     if not u:
#         raise HTTPException(status_code=404, detail="user not found")
#     if u.id == admin.id and data.is_active is False:
#         raise HTTPException(status_code=400, detail="cannot deactivate yourself")
#     changes: dict = {}
#     if data.role is not None:
#         changes["role"] = (u.role.value, data.role.value)
#         u.role = data.role
#     if data.is_active is not None:
#         changes["is_active"] = (u.is_active, data.is_active)
#         u.is_active = data.is_active
#     if data.reset_password:
#         from .password import hash_password, is_strong
#         if not is_strong(data.reset_password):
#             raise HTTPException(status_code=400, detail="password does not meet policy")
#         u.password_hash = hash_password(data.reset_password)
#         u.must_change_password = True
#         changes["password_reset"] = True
#     session.add(u)
#     session.commit()
#     session.refresh(u)
#     audit_record(AuditKind.user_update,
#                  actor_id=admin.id, actor_username=admin.username,
#                  object_kind="user", object_id=str(u.id),
#                  ip=_client_ip(request), detail={"changes": changes},
#                  session=session)
#     return _user_out(u)


# @router.delete("/users/{user_id}")
# def delete_user(user_id: int, request: Request,
#                 admin: User = Depends(require_role(Role.admin)),
#                 session: Session = Depends(get_session)):
#     if user_id == admin.id:
#         raise HTTPException(status_code=400, detail="cannot delete yourself")
#     u = session.get(User, user_id)
#     if not u:
#         raise HTTPException(status_code=404, detail="user not found")
#     username = u.username  # snapshot before the row is physically removed
#     # Hard delete: physically remove the user and cascade-clean all data they
#     # own (targets / scopes / uploads + disk / agent tasks+runs / compliance /
#     # custom models). Audit trail survives via actor_username snapshots.
#     counts = service.hard_delete_user(session, user_id)
#     audit_record(AuditKind.user_delete,
#                  actor_id=admin.id, actor_username=admin.username,
#                  object_kind="user", object_id=str(user_id),
#                  ip=_client_ip(request),
#                  detail={"username": username, "cascaded": counts},
#                  session=session)
#     return {"ok": True, "id": user_id, "deleted": counts}
