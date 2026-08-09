import os
import time
from datetime import timedelta
from typing import Optional
import jwt

_SECRET = os.environ.get("PA_JWT_SECRET")
_ALGO = "HS256"
_ACCESS_TTL = timedelta(hours=8)


def _secret() -> str:
    global _SECRET
    if not _SECRET:
        _SECRET = os.environ["PA_JWT_SECRET"]  # required — no default, no fallback
    return _SECRET


def issue(user_id: int, username: str, role: str, ttl: Optional[timedelta] = None) -> str:
    # Use time.time() (always UTC epoch) rather than datetime.utcnow(), which has
    # subtle timezone bugs on systems where naive datetimes are interpreted as
    # local time during .timestamp() conversion.
    now_ts = int(time.time())
    exp_ts = now_ts + int((ttl or _ACCESS_TTL).total_seconds())
    payload = {
        "sub": str(user_id),
        "usr": username,
        "rol": role,
        "iat": now_ts,
        "exp": exp_ts,
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGO)


def verify(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[_ALGO])
