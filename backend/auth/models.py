from datetime import datetime
from enum import Enum
from typing import Optional
from sqlmodel import SQLModel, Field


class Role(str, Enum):
    admin = "admin"
    operator = "operator"
    viewer = "viewer"


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=64)
    password_hash: str
    role: Role = Field(default=Role.operator)
    is_active: bool = Field(default=True)
    must_change_password: bool = Field(default=False)
    failed_attempts: int = Field(default=0)
    locked_until: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
