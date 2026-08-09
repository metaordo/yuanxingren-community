import secrets
import string
from datetime import datetime, timedelta
from typing import Optional
from sqlmodel import Session, select
from .models import User, Role
from .password import hash_password, verify_password, is_strong

MAX_FAILED = 5
LOCK_MINUTES = 15


class AuthError(Exception):
    pass


def get_user(session: Session, username: str) -> Optional[User]:
    return session.exec(select(User).where(User.username == username)).first()


def create_user(session: Session, username: str, password: str, role: Role,
                must_change: bool = False) -> User:
    if get_user(session, username):
        raise AuthError("username already exists")
    if not is_strong(password):
        raise AuthError("password does not meet policy")
    u = User(username=username, password_hash=hash_password(password),
             role=role, must_change_password=must_change)
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def authenticate(session: Session, username: str, password: str) -> User:
    user = get_user(session, username)
    # Constant-time-ish: don't reveal whether username or password is wrong
    generic = AuthError("invalid credentials")
    if not user or not user.is_active:
        raise generic
    if user.locked_until and user.locked_until > datetime.utcnow():
        raise AuthError("account locked, try later")
    if not verify_password(password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= MAX_FAILED:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
            user.failed_attempts = 0
        session.add(user)
        session.commit()
        raise generic
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def change_password(session: Session, user: User, old: str, new: str) -> None:
    if not verify_password(old, user.password_hash):
        raise AuthError("invalid current password")
    if not is_strong(new):
        raise AuthError("new password does not meet policy")
    user.password_hash = hash_password(new)
    user.must_change_password = False
    session.add(user)
    session.commit()


def generate_initial_password() -> str:
    """Strong random password matching policy."""
    alphabet = string.ascii_letters + string.digits
    specials = "!@#$%^&*-_"
    # Guarantee policy: upper+lower+digit+special, length 16
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(specials),
    ]
    pwd += [secrets.choice(alphabet + specials) for _ in range(12)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def hard_delete_user(session: Session, user_id: int) -> dict:
    """Physically delete a user and cascade-clean every record they own.

    Returns per-table deletion counts (for audit detail). Audit-trail rows are
    intentionally left untouched: ``AuditEvent.actor_id`` has no FK and
    ``actor_username`` is snapshotted, so history survives the delete.
    ``RouteSetting`` rows are global system config — their ``updated_by`` stamp
    is nulled rather than deleted.
    """
    import os
    import shutil
    from pathlib import Path
    # Lazy imports: these tables live in sibling packages; importing at module
    # top would create import cycles (auth <- targets/agents/llm <- auth).
    from ..targets.models import Target
    from ..targets.scope_manager import AuthScope
    from ..uploads.models import UploadedFile
    from ..agents.models import AgentTask, AgentRun, ComplianceScan, UnknownReport
    from ..llm.models import CustomModel, RouteSetting

    counts: dict[str, int] = {}

    # Tasks first: capture their ids so AgentRun / UnknownReport (linked only by
    # task_id, no owner_id) can be cascaded.
    task_ids = [t.id for t in session.exec(
        select(AgentTask).where(AgentTask.owner_id == user_id)).all()]
    if task_ids:
        for run in session.exec(
                select(AgentRun).where(AgentRun.task_id.in_(task_ids))).all():
            session.delete(run)
            counts["agent_runs"] = counts.get("agent_runs", 0) + 1
        for rep in session.exec(
                select(UnknownReport).where(UnknownReport.task_id.in_(task_ids))).all():
            session.delete(rep)
            counts["unknown_reports"] = counts.get("unknown_reports", 0) + 1

    # owner_id-scoped tables
    for model, key in ((AgentTask, "agent_tasks"),
                       (ComplianceScan, "compliance_scans"),
                       (Target, "targets"),
                       (AuthScope, "auth_scopes"),
                       (UploadedFile, "uploaded_files")):
        rows = session.exec(select(model).where(model.owner_id == user_id)).all()
        for row in rows:
            session.delete(row)
        if rows:
            counts[key] = len(rows)

    # created_by-scoped
    customs = session.exec(
        select(CustomModel).where(CustomModel.created_by == user_id)).all()
    for c in customs:
        session.delete(c)
    if customs:
        counts["custom_models"] = len(customs)

    # Global config: keep the route, drop the user stamp.
    for rs in session.exec(
            select(RouteSetting).where(RouteSetting.updated_by == user_id)).all():
        rs.updated_by = None
        session.add(rs)

    user = session.get(User, user_id)
    if user:
        session.delete(user)

    session.commit()

    # Disk: wipe the user's entire upload tree (PA_DATA_DIR/uploads/<user_id>).
    data_dir = Path(os.environ.get("PA_DATA_DIR", "./data"))
    shutil.rmtree(data_dir / "uploads" / str(user_id), ignore_errors=True)

    return counts


def bootstrap_admin_if_needed(session: Session) -> Optional[tuple[str, str]]:
    """If no users exist, create an admin with a generated password. Returns (username, password) or None."""
    existing = session.exec(select(User)).first()
    if existing:
        return None
    pwd = generate_initial_password()
    u = User(username="admin",
             password_hash=hash_password(pwd),
             role=Role.admin,
             must_change_password=True)
    session.add(u)
    session.commit()
    return ("admin", pwd)
