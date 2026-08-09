"""Black-box target schema and persistence models."""
from datetime import datetime
from enum import Enum
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class TargetType(str, Enum):
    url = "url"
    ip = "ip"          # single IP or CIDR
    domain = "domain"
    binary = "binary"  # uploaded binary file
    pcap = "pcap"      # uploaded packet capture
    source = "source"  # uploaded source code file or archive
    protocol = "protocol"  # custom protocol endpoint, e.g. tcp://host:port


class Target(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    type: TargetType
    value: str = Field(max_length=2048)
    owner_id: int = Field(index=True)  # creator user id
    authorized: bool = Field(default=False)
    authorization_doc: Optional[str] = None  # path to uploaded auth letter
    scope: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # scope example: {"allowed_paths": ["/api/*"], "forbidden_paths": ["/admin"], "rate_limit": 10}
    auth: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # auth example: {"type": "bearer", "credentials_ref": "vault:secrets/target_1"}
    metadata_: dict = Field(default_factory=dict, sa_column=Column("metadata", JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)
