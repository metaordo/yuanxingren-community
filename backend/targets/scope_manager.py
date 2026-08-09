"""Per-user authorization scope (hosts and CIDRs) the operator has attested to."""
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class AuthScope(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(index=True)
    # Lists of glob patterns (e.g. "*.example.com") and CIDRs ("10.0.0.0/24")
    hosts: list = Field(default_factory=list, sa_column=Column(JSON))
    cidrs: list = Field(default_factory=list, sa_column=Column(JSON))
    note: Optional[str] = None  # e.g. SoW reference, ticket id
    created_at: datetime = Field(default_factory=datetime.utcnow)
