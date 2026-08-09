"""X-Scan(ZAP)扫描结果持久化表。

ZAP 扫描本身是实时打 daemon、按 url 取 alerts,不落库。本表在扫描完成
(ascan 100%)时由 finalize 端点服务端重取 alerts 后落库,供管理员跨用户审阅。
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class ZapScan(SQLModel, table=True):
    """One completed X-Scan (ZAP) run, with its alert snapshot."""
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(index=True)
    target_id: Optional[int] = Field(default=None, index=True)  # 扫描按 url 发起,可空
    target_url: str = Field(max_length=2048)
    status: str = Field(default="done", max_length=16)
    num_alerts: int = Field(default=0)
    # 风险分布,如 {"High":1,"Medium":3,"Low":5,"Informational":2}
    risk_summary: dict = Field(default_factory=dict, sa_column=Column(JSON))
    alerts_json: list = Field(default_factory=list, sa_column=Column(JSON))
    spider_id: Optional[str] = Field(default=None, max_length=32)
    ascan_id: Optional[str] = Field(default=None, max_length=32)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    finished_at: Optional[datetime] = Field(default=None)
