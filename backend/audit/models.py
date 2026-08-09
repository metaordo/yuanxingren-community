"""Centralized audit log.

Records security-relevant events across the system in a single SQL table so
auditors can answer questions like:
  - Who logged in (or tried to log in) from when to when?
  - Which targets did user X access?
  - Which external tools were invoked against which targets?
  - Who changed user roles or permissions?

Each event has a `kind` (e.g. login_success, target_create), an optional
target user/object, and an arbitrary JSON detail blob. Records are append-only
from the application's perspective — direct deletion requires DB-level access.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class AuditKind(str, Enum):
    login_success = "login_success"
    login_failure = "login_failure"
    logout = "logout"
    password_change = "password_change"
    user_create = "user_create"
    user_update = "user_update"
    user_deactivate = "user_deactivate"
    user_delete = "user_delete"
    target_create = "target_create"
    target_delete = "target_delete"
    target_access = "target_access"
    scope_update = "scope_update"
    tool_invoke = "tool_invoke"
    poc_synthesize = "poc_synthesize"
    poc_sandbox_run = "poc_sandbox_run"
    disclosure_draft = "disclosure_draft"
    model_register = "model_register"
    route_update = "route_update"
    analysis_complete = "analysis_complete"   # multi-agent 分析完成
    compliance_scan = "compliance_scan"        # 合规检查完成
    zap_scan = "zap_scan"                      # X-Scan(ZAP)扫描完成


class AuditEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    kind: AuditKind = Field(index=True)
    actor_id: Optional[int] = Field(default=None, index=True)   # user who triggered
    actor_username: Optional[str] = Field(default=None, max_length=64)
    object_kind: Optional[str] = Field(default=None, max_length=32)
    object_id: Optional[str] = Field(default=None, max_length=128)
    ip: Optional[str] = Field(default=None, max_length=64)
    detail: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
