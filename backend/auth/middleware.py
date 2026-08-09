from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session
from . import jwt_handler
from .models import User, Role
from ..db import get_session


def _extract_token(request: Request) -> Optional[str]:
    # Prefer cookie (HttpOnly), fall back to Authorization header
    token = request.cookies.get("pa_token")
    if token:
        return token
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    return None


def get_current_user(request: Request,
                     session: Session = Depends(get_session)) -> User:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    try:
        payload = jwt_handler.verify(token)
    except Exception:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    user_id = int(payload.get("sub", 0))
    user = session.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user not found or inactive")
    return user


def require_role(*roles: Role):
    """Dependency factory enforcing role allowlist."""
    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="insufficient permission")
        return user
    return _dep
