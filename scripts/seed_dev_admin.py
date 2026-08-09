"""Development-only seed script: create a known admin account for testing.

WARNING: This bypasses the password policy. Use ONLY in dev/test environments.
A loud banner is printed every time it runs.

Usage:
    cd pentest-agent
    PA_DATA_DIR=./data python3 scripts/seed_dev_admin.py

Idempotent: if the username already exists, the password is RESET (so you
can run it again if you forget). To use a different username/password,
override PA_DEV_USERNAME / PA_DEV_PASSWORD env vars.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sqlmodel import Session, select
from backend.db import engine, init_db
from backend.auth.models import User, Role
from backend.auth.password import hash_password

DEV_USERNAME = os.environ.get("PA_DEV_USERNAME", "admin")
_PASSWORD = os.environ.get("PA_DEV_PASSWORD")
if not _PASSWORD:
    sys.exit("PA_DEV_PASSWORD env var is required — refusing to use a hardcoded default")
DEV_PASSWORD = _PASSWORD


def _banner() -> None:
    bar = "=" * 70
    print(f"\n{bar}", file=sys.stderr)
    print("  DEVELOPMENT SEED — DO NOT USE IN PRODUCTION", file=sys.stderr)
    print(f"  Creating admin account with KNOWN credentials:", file=sys.stderr)
    print(f"    username: {DEV_USERNAME}", file=sys.stderr)
    print(f"    password: {DEV_PASSWORD}", file=sys.stderr)
    print(f"  Password policy is bypassed for this seed.", file=sys.stderr)
    print(f"  Data dir: {os.environ.get('PA_DATA_DIR', './data')}", file=sys.stderr)
    print(f"{bar}\n", file=sys.stderr)


def main() -> int:
    _banner()
    init_db()
    with Session(engine) as session:
        existing = session.exec(
            select(User).where(User.username == DEV_USERNAME)
        ).first()
        if existing:
            existing.password_hash = hash_password(DEV_PASSWORD)
            existing.role = Role.admin
            existing.is_active = True
            existing.must_change_password = False
            existing.failed_attempts = 0
            existing.locked_until = None
            session.add(existing)
            session.commit()
            print(f"✓ Reset password for existing user '{DEV_USERNAME}' (id={existing.id})",
                  file=sys.stderr)
        else:
            u = User(
                username=DEV_USERNAME,
                password_hash=hash_password(DEV_PASSWORD),
                role=Role.admin,
                is_active=True,
                must_change_password=False,
            )
            session.add(u)
            session.commit()
            session.refresh(u)
            print(f"✓ Created user '{DEV_USERNAME}' (id={u.id}) with role admin",
                  file=sys.stderr)
    print("✓ Done. You can now log in to the web UI.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
