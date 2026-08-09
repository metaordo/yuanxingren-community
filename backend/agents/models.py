"""SQLModel tables for the multi-agent workflow runtime.

`AgentTask` is one user-submitted multi-agent run (a workflow).
`AgentRun` is one specific role's execution within that task — there are N rows
(one per spawned worker) per AgentTask.

These two tables let the frontend reconstruct the dashboard from history and
let admins audit per-run token cost / engine calls.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from sqlmodel import SQLModel, Field, Column, JSON


class TaskStatus(str, Enum):
    running = "running"
    done = "done"
    failed = "failed"
    partial = "partial"
    cancelled = "cancelled"


class RunStatus(str, Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"
    skipped = "skipped"


class AgentTask(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(index=True)
    target_id: Optional[int] = Field(default=None, index=True)
    upload_id: Optional[int] = Field(default=None, index=True)
    user_prompt: str = Field(default="", max_length=4000)
    status: TaskStatus = Field(default=TaskStatus.running, index=True)
    # supervisor's per-round picks: [{"round":0,"picked":[...],"rejected":[...],"rationale":"..."}]
    supervisor_decisions: list = Field(default_factory=list, sa_column=Column(JSON))
    final_report: str = Field(default="")
    # {"raw": int, "after_dedupe": int, "clusters": int}
    dedupe_stats: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error: Optional[str] = Field(default=None, max_length=2000)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    finished_at: Optional[datetime] = Field(default=None)


class ComplianceScan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(index=True)
    target_id: int = Field(index=True)
    status: str = Field(default="pending", index=True)   # pending|running|done|failed
    progress: int = Field(default=0)
    reuse_ratio: float = Field(default=0.0)
    self_ratio: float = Field(default=1.0)
    verdict: Optional[str] = Field(default=None, max_length=32)
    result_json: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error_msg: Optional[str] = Field(default=None, max_length=2000)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    finished_at: Optional[datetime] = Field(default=None)


class AgentRun(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True)
    role: str = Field(max_length=64, index=True)
    # files this agent was scoped to (relative paths inside the project)
    scope: list = Field(default_factory=list, sa_column=Column(JSON))
    status: RunStatus = Field(default=RunStatus.pending, index=True)
    llm_model: Optional[str] = Field(default=None, max_length=128)
    llm_task_kind: Optional[str] = Field(default=None, max_length=32)
    tokens_in: int = 0
    tokens_out: int = 0
    # [{"engine":"svf","args":{...},"finding_count":3,"ms":420}]
    engine_calls: list = Field(default_factory=list, sa_column=Column(JSON))
    # raw findings produced by this run, before verifier dedupe
    findings: list = Field(default_factory=list, sa_column=Column(JSON))
    transcript: str = Field(default="")
    error: Optional[str] = Field(default=None, max_length=2000)
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)


class AgentAuditScan(SQLModel, table=True):
    """One Agent-audit run: static + dynamic analysis via Cuscuta engine."""
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(index=True)
    target_id: int = Field(index=True)
    # project name registered in Cuscuta (derived from upload filename)
    cuscuta_project: Optional[str] = Field(default=None, max_length=256)
    # task_id returned by Cuscuta /pipeline
    cuscuta_task_id: Optional[str] = Field(default=None, max_length=128)
    status: str = Field(default="pending", index=True)  # pending|running|done|failed
    # sink_rules requested: ["rce","sqli","ssti","id"]
    sink_rules: list = Field(default_factory=list, sa_column=Column(JSON))
    # aggregated result snapshot once done
    result_json: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error_msg: Optional[str] = Field(default=None, max_length=2000)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    finished_at: Optional[datetime] = Field(default=None)


class UnknownReport(SQLModel, table=True):
    """One 0-day pipeline run against one verified finding.

    Created in workflow's post-verifier stage. Stored separately from
    AgentRun because the pipeline is not an LLM agent — it's a fixed
    sequence (score → poc → sandbox → disclosure) with multiple LLM and
    subprocess calls inside.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    task_id: int = Field(index=True)
    finding_idx: int                                   # position in verifier output
    finding_snapshot: dict = Field(default_factory=dict, sa_column=Column(JSON))
    # {"value": 0.0-1.0, "similar_refs": [...], "rationale": "..."}
    novelty: dict = Field(default_factory=dict, sa_column=Column(JSON))
    poc_source: Optional[str] = Field(default=None)
    poc_language: Optional[str] = Field(default="python", max_length=16)
    poc_notes: Optional[str] = Field(default=None, max_length=2000)
    sandbox_triggered: Optional[bool] = Field(default=None)
    sandbox_exit_code: Optional[int] = Field(default=None)
    sandbox_stdout: Optional[str] = Field(default=None)
    sandbox_stderr: Optional[str] = Field(default=None)
    sandbox_duration_seconds: Optional[float] = Field(default=None)
    disclosure_body: Optional[str] = Field(default=None)
    disclosure_cve_request: Optional[str] = Field(default=None)
    disclosure_embargo_until: Optional[datetime] = Field(default=None)
    error: Optional[str] = Field(default=None, max_length=2000)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
