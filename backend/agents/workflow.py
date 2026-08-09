"""Multi-agent workflow: orchestrates intake → preprocess → supervisor →
worker fan-out → verifier → reporter.

M2 implementation: native asyncio + a tiny coordinator instead of LangGraph
StateGraph. The reason is pragmatic — LangGraph 1.2's `Send()` API gives
us fan-out, but the per-event streaming we need (a separate token channel
per worker) is easier to express directly with asyncio.gather + an event
queue. We can promote this to StateGraph in M3 if/when we need persistent
checkpoints.

Public API:
  run_workflow(...) - sync wrapper, returns final result dict
  astream_workflow(...) - async iterator over (event_dict) for WS streaming
"""
from __future__ import annotations
import asyncio
import logging
import shutil
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Any

from sqlmodel import Session

from ..db import engine
from ..audit import record as audit_record, AuditKind
from ..uploads.models import UploadedFile
from .base import Agent, AgentOutput
from .models import AgentRun, AgentTask, RunStatus, TaskStatus, UnknownReport
from .roles import get_worker
from .supervisor import build_file_index, supervisor_pick, supervisor_second_round
from .verifier import verify, render_report, _SEVERITY_RANK
from ..llm.router import acall

log = logging.getLogger(__name__)


# ---- project staging ----

def _stage_project(upload: dict, data_dir: Path) -> tuple[Path, list[Path]]:
    """Materialize an uploaded file or archive into a temp directory.

    Returns (project_root, paths_to_clean). Caller must delete `paths_to_clean`
    when the workflow finishes.
    """
    src = data_dir / upload["storage_path"]
    if not src.exists():
        raise FileNotFoundError(f"upload missing on disk: {src}")
    workdir = Path(tempfile.mkdtemp(prefix=f"agent-task-{upload['id']}-"))
    try:
        if zipfile.is_zipfile(src):
            with zipfile.ZipFile(src) as zf:
                _safe_extract_zip(zf, workdir)
        elif tarfile.is_tarfile(src):
            with tarfile.open(src) as tf:
                _safe_extract_tar(tf, workdir)
        else:
            # single source file → put it in the workdir under its original name
            (workdir / upload["filename"]).write_bytes(src.read_bytes())
        return workdir, [workdir]
    except Exception:
        shutil.rmtree(workdir, ignore_errors=True)
        raise


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract ZIP, rejecting traversal entries."""
    dest_resolved = dest.resolve()
    for info in zf.infolist():
        member_path = (dest / info.filename).resolve()
        if not str(member_path).startswith(str(dest_resolved)):
            log.warning("skipping zip traversal entry: %s", info.filename)
            continue
        if info.is_dir():
            member_path.mkdir(parents=True, exist_ok=True)
        else:
            member_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, member_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    dest_resolved = dest.resolve()
    for m in tf.getmembers():
        member_path = (dest / m.name).resolve()
        if not str(member_path).startswith(str(dest_resolved)):
            log.warning("skipping tar traversal entry: %s", m.name)
            continue
        # extract via member path manipulation
        m.name = str(member_path.relative_to(dest_resolved))
        tf.extract(m, path=dest)


# ---- workflow runner ----

class WorkflowError(Exception):
    pass


def _resolve_upload(target, session: Session) -> dict:
    """Find the UploadedFile that backs a `source` Target.

    Returns a plain dict snapshot (id/storage_path/filename) so callers don't
    need to keep the SQLModel instance attached to a session.
    """
    from ..targets.models import Target as TargetModel
    if not getattr(target, "id", None):
        raise WorkflowError("multi_agent mode requires a saved target with id")
    t = session.get(TargetModel, int(target.id))
    if not t:
        raise WorkflowError(f"target {target.id} not found")
    meta = t.metadata_ or {}
    upload_id = meta.get("upload_id")
    if not isinstance(upload_id, int):
        raise WorkflowError(
            "target does not point to an uploaded file (multi_agent only "
            "supports source targets created via /targets/from-upload)")
    uf = session.get(UploadedFile, upload_id)
    if not uf:
        raise WorkflowError(f"upload {upload_id} not found")
    return {
        "id": uf.id,
        "filename": uf.filename,
        "storage_path": uf.storage_path,
        "size_bytes": uf.size_bytes,
    }


async def astream_workflow(*, user_prompt: str, target,
                            owner_id: int) -> AsyncIterator[dict]:
    """Async generator yielding workflow events as dicts.

    Event shapes (matches plan §5):
      - workflow_started, supervisor_decision, agent_started,
        agent_done, agent_failed, verifier_dedupe, workflow_done,
        workflow_error
    """
    import os
    data_dir = Path(os.environ.get("PA_DATA_DIR", "./data"))
    cleanup_paths: list[Path] = []
    task_id: int | None = None

    try:
        # 1. resolve upload + create AgentTask row
        with Session(engine) as session:
            upload = _resolve_upload(target, session)
            task = AgentTask(
                owner_id=owner_id,
                target_id=int(target.id),
                upload_id=upload["id"],
                user_prompt=user_prompt,
                status=TaskStatus.running,
            )
            session.add(task)
            session.commit()
            session.refresh(task)
            task_id = task.id

        # 2. intake / preprocess
        # Offload to a thread: unzip + tree-walk are blocking IO/CPU and would
        # otherwise stall the event loop, starving the WebSocket keepalive pong
        # (ping timeout -> 1011 disconnect on large projects). See acall().
        project_root, cleanup_paths = await asyncio.to_thread(_stage_project, upload, data_dir)
        file_index = await asyncio.to_thread(build_file_index, project_root)

        # 3. supervisor decides workers (blocking LLM call -> offload)
        decision = await asyncio.to_thread(supervisor_pick, file_index, user_prompt)
        with Session(engine) as session:
            t = session.get(AgentTask, task_id)
            t.supervisor_decisions = [decision]
            session.add(t)
            session.commit()

        yield {
            "event": "workflow_started",
            "task_id": task_id,
            "picked_roles": [p["role"] for p in decision["picked"]],
            "rejected_roles": [r["role"] for r in decision["rejected"]],
            "file_index_summary": {
                "total_files": len(file_index["files"]),
                "by_ext": file_index["by_ext"],
                "total_bytes": file_index["total_bytes"],
            },
        }
        yield {"event": "supervisor_decision", "round": 0,
               "picked": decision["picked"],
               "rejected": decision["rejected"],
               "rationale": decision["rationale"]}

        if not decision["picked"]:
            empty_report = "未匹配到任何 agent 角色 — 项目无可分析的源代码。"
            with Session(engine) as session:
                t = session.get(AgentTask, task_id)
                t.status = TaskStatus.done
                t.final_report = empty_report
                t.finished_at = datetime.utcnow()
                session.add(t)
                session.commit()
            yield {"event": "workflow_done", "task_id": task_id,
                   "report": empty_report,
                   "findings": [],
                   "stats": {"raw": 0, "after_dedupe": 0, "clusters": 0}}
            return

        # ---- Round 0: spawn first batch of workers ----
        round0_findings: list[dict] = []
        async for evt in _spawn_and_collect(
            task_id=task_id,
            project_root=project_root,
            user_prompt=user_prompt,
            picked=decision["picked"],
            findings_sink=round0_findings,
        ):
            yield evt

        # ---- Round 0 verifier (preview, used to inform second supervisor) ----
        preview = await asyncio.to_thread(verify, round0_findings)
        all_findings = list(round0_findings)
        all_picked_roles = [p["role"] for p in decision["picked"]]

        # ---- Round 1 (optional second supervisor spawn) ----
        try:
            second = await asyncio.to_thread(
                supervisor_second_round,
                file_index,
                preview.get("verified", []),
                all_picked_roles,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("second-round supervisor errored: %s", e)
            second = {"round": 1, "picked": [], "rejected": [],
                       "rationale": f"second-round error: {e}"}

        if second.get("picked"):
            # persist the new decision
            with Session(engine) as session:
                t = session.get(AgentTask, task_id)
                history = list(t.supervisor_decisions or [])
                history.append(second)
                t.supervisor_decisions = history
                session.add(t)
                session.commit()

            yield {"event": "supervisor_decision",
                   "round": 1,
                   "picked": second["picked"],
                   "rejected": second.get("rejected", []),
                   "rationale": second.get("rationale", "")}

            async for evt in _spawn_and_collect(
                task_id=task_id,
                project_root=project_root,
                user_prompt=user_prompt,
                picked=second["picked"],
                findings_sink=all_findings,
            ):
                yield evt
            all_picked_roles.extend(p["role"] for p in second["picked"])

        # 5. final verifier (L1+L2 dedupe; L3 LLM dedupe gated by env flag)
        import os as _os
        use_llm_dedupe = _os.environ.get("PA_LLM_DEDUPE", "0") == "1"
        v = await asyncio.to_thread(verify, all_findings, use_llm_dedupe=use_llm_dedupe)
        yield {
            "event": "verifier_dedupe",
            "stats": v["stats"],
            "clusters": v["clusters"],
        }

        # 5b. verifier-reviewer: LLM confidence judge with code context
        review_enabled = _os.environ.get("PA_VERIFIER_REVIEWER", "1") == "1"
        context_lines = int(_os.environ.get("PA_VERIFIER_CONTEXT_LINES", "10"))
        v["dismissed"] = []

        if review_enabled and v["verified"]:
            review_run_id = _create_review_agent_run(task_id)
            yield {"event": "agent_started", "run_id": review_run_id,
                   "role": "verifier-reviewer", "model": "(pending)",
                   "scope_files_count": 0}
            try:
                kept, dismissed, review_stats = await _run_verifier_reviewer(
                    v["verified"],
                    project_root=project_root,
                    context_lines=context_lines,
                )
                v["verified"] = kept
                v["dismissed"] = dismissed
                v["stats"]["reviewer"] = review_stats
                _finalize_review_agent_run(
                    review_run_id, review_stats, status="done",
                    output={"verdicts": review_stats.get("verdicts", []),
                            "dismissed": dismissed,
                            "kept_count": len(kept)}
                )
                yield {"event": "agent_done", "run_id": review_run_id,
                       "role": "verifier-reviewer",
                       "finding_count": len(kept),
                       "tokens_in": review_stats.get("tokens_in", 0),
                       "tokens_out": review_stats.get("tokens_out", 0),
                       "latency_ms": review_stats.get("latency_ms", 0),
                       "model": review_stats.get("model", "")}
            except Exception as e:  # noqa: BLE001
                log.warning("verifier-reviewer wrapper failed: %s", e)
                v["stats"]["reviewer"] = {
                    "status": "failed", "error": str(e),
                    "kept": len(v["verified"]), "lowered": 0,
                    "dismissed": 0, "reviewed": 0,
                }
                _finalize_review_agent_run(
                    review_run_id, {}, status="failed", error=str(e)
                )
                yield {"event": "agent_failed", "run_id": review_run_id,
                       "role": "verifier-reviewer", "error": str(e),
                       "latency_ms": 0}
        elif not review_enabled:
            v["stats"]["reviewer"] = {
                "status": "skipped", "reason": "env_disabled",
                "kept": len(v["verified"]), "lowered": 0,
                "dismissed": 0, "reviewed": 0,
            }
        elif not v["verified"]:
            v["stats"]["reviewer"] = {
                "status": "skipped", "reason": "no_findings",
                "kept": 0, "lowered": 0, "dismissed": 0, "reviewed": 0,
            }

        # Keep legacy event for progress-step compatibility
        yield {
            "event": "verifier_reviewer_done",
            "stats": v["stats"].get("reviewer", {}),
        }

        # 5b. 0-day pipeline (M4). Gated by env flag PA_ENABLE_0DAY=1 so the
        # extra cost/latency is opt-in. When enabled, runs novelty scoring +
        # PoC synth + sandbox + disclosure draft on every high+ finding.
        enable_0day = _os.environ.get("PA_ENABLE_0DAY", "0") == "1"
        unknown_reports: list[dict] = []
        if enable_0day:
            enable_sandbox = _os.environ.get("PA_ENABLE_SANDBOX", "1") == "1"
            enable_disclosure = _os.environ.get("PA_ENABLE_DISCLOSURE", "1") == "1"
            async for evt in _run_unknown_pipeline(
                task_id=task_id, target=target,
                verified=v["verified"],
                enable_sandbox=enable_sandbox,
                enable_disclosure=enable_disclosure,
            ):
                yield evt
            # collect persisted UnknownReports for the reporter
            with Session(engine) as session:
                from sqlmodel import select
                rows = session.exec(
                    select(UnknownReport).where(UnknownReport.task_id == task_id)
                ).all()
                unknown_reports = [{
                    "finding_idx": r.finding_idx,
                    "novelty": r.novelty,
                    "poc_source": r.poc_source,
                    "poc_language": r.poc_language,
                    "sandbox_triggered": r.sandbox_triggered,
                    "sandbox_exit_code": r.sandbox_exit_code,
                    "sandbox_stdout": r.sandbox_stdout,
                    "sandbox_stderr": r.sandbox_stderr,
                    "disclosure_body": r.disclosure_body,
                    "disclosure_embargo_until": (
                        r.disclosure_embargo_until.isoformat()
                        if r.disclosure_embargo_until else None),
                } for r in rows]

        # 6. reporter
        with Session(engine) as session:
            from sqlmodel import select
            runs = session.exec(
                select(AgentRun).where(AgentRun.task_id == task_id)
            ).all()
            from ..billing import cost_cny, load_prices
            _prices = load_prices(session)
            run_dicts = [{
                "role": r.role,
                "status": r.status.value if hasattr(r.status, "value") else r.status,
                "findings": r.findings,
                "model": r.llm_model,
                "tokens_in": r.tokens_in,
                "tokens_out": r.tokens_out,
                "cost_cny": cost_cny(r.llm_model, r.tokens_in, r.tokens_out, _prices),
                "latency_ms": int(((r.finished_at or r.started_at or datetime.utcnow())
                                     - (r.started_at or datetime.utcnow())).total_seconds() * 1000),
            } for r in runs] if runs else []
        report = await asyncio.to_thread(
            render_report,
            target=target,
            user_prompt=user_prompt,
            picked_roles=all_picked_roles,
            agent_runs=run_dicts,
            verified=v["verified"],
            dismissed=v.get("dismissed", []),
            stats=v["stats"],
            unknown_reports=unknown_reports,
        )

        # 7. finalize task row
        with Session(engine) as session:
            t = session.get(AgentTask, task_id)
            had_failure = any(r["status"] == "failed" for r in run_dicts)
            t.status = TaskStatus.partial if had_failure else TaskStatus.done
            t.final_report = report
            t.dedupe_stats = v["stats"]
            t.finished_at = datetime.utcnow()
            session.add(t)
            session.commit()
            from ..billing import cost_cny, load_prices
            _prices = load_prices(session)
            _cost = round(sum(cost_cny(r.get("model"), r["tokens_in"], r["tokens_out"], _prices)
                              for r in run_dicts), 4)
            audit_record(
                AuditKind.analysis_complete,
                actor_id=owner_id, object_kind="task", object_id=str(task_id),
                detail={
                    "target_id": int(target.id),
                    "status": t.status.value,
                    "finding_count": len(v["verified"]),
                    "agents": len(run_dicts),
                    "tokens_in": sum(r["tokens_in"] for r in run_dicts),
                    "tokens_out": sum(r["tokens_out"] for r in run_dicts),
                    "cost_cny": _cost,
                },
                session=session)

        yield {
            "event": "workflow_done",
            "task_id": task_id,
            "report": report,
            "findings": v["verified"],
            "stats": v["stats"],
            "unknown_reports": unknown_reports,
        }

    except WorkflowError as e:
        log.warning("workflow error: %s", e)
        if task_id:
            _mark_task_failed(task_id, str(e))
        yield {"event": "workflow_error", "task_id": task_id, "detail": str(e)}
    except Exception as e:  # noqa: BLE001
        log.exception("workflow crashed")
        if task_id:
            _mark_task_failed(task_id, f"crash: {e}")
        yield {"event": "workflow_error", "task_id": task_id,
               "detail": f"internal error: {e}"}
    finally:
        for p in cleanup_paths:
            shutil.rmtree(p, ignore_errors=True)


def _mark_task_failed(task_id: int, msg: str) -> None:
    try:
        with Session(engine) as session:
            t = session.get(AgentTask, task_id)
            if t is not None:
                t.status = TaskStatus.failed
                t.error = msg[:2000]
                t.finished_at = datetime.utcnow()
                session.add(t)
                session.commit()
                audit_record(
                    AuditKind.analysis_complete,
                    actor_id=t.owner_id, object_kind="task", object_id=str(task_id),
                    detail={"target_id": t.target_id, "status": "failed",
                            "error": msg[:200]},
                    session=session)
    except Exception:  # noqa: BLE001
        log.exception("could not mark task %s failed", task_id)


async def _spawn_and_collect(*, task_id: int, project_root: Path,
                               user_prompt: str,
                               picked: list[dict],
                               findings_sink: list[dict]) -> AsyncIterator[dict]:
    """Spawn one batch of workers concurrently and yield their events.

    Appends each worker's findings to `findings_sink` (out-parameter style).
    Used for both round-0 and round-1 supervisor decisions.
    """
    if not picked:
        return

    # Pre-create AgentRun rows so the WS knows run_ids before tasks finish
    worker_ctx: list[tuple[Agent, dict, int]] = []
    with Session(engine) as session:
        for entry in picked:
            worker = get_worker(entry["role"])
            if worker is None:
                log.warning("supervisor picked unknown role: %s", entry["role"])
                continue
            run_row = AgentRun(
                task_id=task_id,
                role=entry["role"],
                scope=entry["scope_files"],
                status=RunStatus.running,
                llm_task_kind=worker.spec.llm_task_kind,
                started_at=datetime.utcnow(),
            )
            session.add(run_row)
            session.commit()
            session.refresh(run_row)
            worker_ctx.append((worker, entry, run_row.id))

    # Announce all workers (frontend creates columns immediately)
    for worker, entry, run_id in worker_ctx:
        yield {
            "event": "agent_started",
            "run_id": run_id,
            "role": worker.role,
            "scope_files_count": len(entry["scope_files"]),
            "model": "(pending)",
        }

    async def _run_one(worker: Agent, entry: dict, run_id: int) -> tuple[int, AgentOutput]:
        out = await worker.run(
            project_root=project_root,
            scope_files=entry["scope_files"],
            user_prompt=user_prompt,
            hints=entry.get("hints") or {},
        )
        return run_id, out

    tasks_co = [_run_one(w, e, rid) for (w, e, rid) in worker_ctx]
    for completed in asyncio.as_completed(tasks_co):
        run_id, out = await completed
        with Session(engine) as session:
            row = session.get(AgentRun, run_id)
            if row is None:
                continue
            row.status = (RunStatus.failed if out.status == "failed"
                          else RunStatus.skipped if out.status == "skipped"
                          else RunStatus.done)
            row.findings = out.findings
            row.transcript = (out.transcript or "")[:32_000]
            row.tokens_in = out.tokens_in
            row.tokens_out = out.tokens_out
            row.llm_model = out.llm_model or None
            row.error = out.error
            row.finished_at = datetime.utcnow()
            session.add(row)
            session.commit()

        event_name = "agent_done" if out.status != "failed" else "agent_failed"
        evt = {
            "event": event_name,
            "run_id": run_id,
            "role": out.role,
            "status": out.status,
            "tokens_in": out.tokens_in,
            "tokens_out": out.tokens_out,
            "latency_ms": out.latency_ms,
            "model": out.llm_model,
            "finding_count": len(out.findings),
        }
        if out.error:
            evt["error"] = out.error
        yield evt
        if out.transcript:
            yield {
                "event": "agent_transcript",
                "run_id": run_id,
                "role": out.role,
                "transcript": out.transcript[:8000],
            }
        for f in out.findings:
            yield {
                "event": "agent_finding",
                "run_id": run_id,
                "role": out.role,
                "finding": f,
            }
        if out.status != "failed":
            findings_sink.extend(out.findings)



# ---- verifier-reviewer AgentRun DB helpers ----------------------------------

def _create_review_agent_run(task_id: int) -> int:
    """Create a 'verifier-reviewer' AgentRun row, return its id."""
    with Session(engine) as session:
        row = AgentRun(
            task_id=task_id,
            role="verifier-reviewer",
            scope=[],
            status=RunStatus.running,
            llm_task_kind="triage",
            started_at=datetime.utcnow(),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id


def _finalize_review_agent_run(
    run_id: int,
    review_stats: dict,
    *,
    status: str,
    output: dict | None = None,
    error: str | None = None,
) -> None:
    """Update the verifier-reviewer AgentRun row with final stats / output."""
    with Session(engine) as session:
        row = session.get(AgentRun, run_id)
        if row is None:
            return
        row.status = RunStatus.done if status == "done" else RunStatus.failed
        row.tokens_in = int(review_stats.get("tokens_in") or 0)
        row.tokens_out = int(review_stats.get("tokens_out") or 0)
        row.llm_model = review_stats.get("model") or row.llm_model
        if output is not None:
            row.findings = output
        if error:
            row.error = error[:2000]
        row.finished_at = datetime.utcnow()
        session.add(row)
        session.commit()


# ---- verifier-reviewer: LLM confidence judge (post-L1/L2 dedupe) ----------

import os as _os_module
_REVIEW_BATCH_SIZE = int(_os_module.environ.get("PA_VERIFIER_BATCH_SIZE", "10"))


async def _run_verifier_reviewer(
    verified: list[dict],
    *,
    project_root: Path | None,
    context_lines: int = 10,
) -> tuple[list[dict], list[dict], dict]:
    """Run verifier-reviewer LLM over verified findings.

    Returns (kept, dismissed, stats):
      - kept:      finding list (keep + lower), with review_verdict/review_note
      - dismissed: finding list dismissed by LLM, with review_reason
      - stats:     {"status": "ok"|"failed"|"skipped",
                    "reviewed": N (sent to LLM, i.e. medium+),
                    "kept": K, "lowered": L, "dismissed": D,
                    "tokens_in": int, "tokens_out": int, "latency_ms": int,
                    "model": str, "verdicts": [...], "error": str|None,
                    "avg_confidence": int|None, "low_confidence_count": int,
                    "second_pass_count": int, "second_pass_changed_count": int}

    Behavior:
      - Skip low/info findings — they pass through as kept unchanged
      - For medium+ findings, fetch function-level code context via
        verifier._read_function_context (None if project_root is None or file invalid)
      - Batch findings (max PA_VERIFIER_BATCH_SIZE/batch, default 10), call LLM
      - Structured output: JSON array with confidence + exploitability fields
      - Borderline second pass: high/critical with confidence < 60 get a second LLM call
      - On a single batch failure, that batch's findings default to keep;
        other batches proceed normally. If ALL batches fail, status='failed'.
      - Verdict validation: only keep/lower/dismiss accepted; others → keep
      - Missing verdicts (LLM omitted ids) → keep
      - Out-of-range ids → silently dropped
    """
    import json as _json
    from ..llm import Message
    from .verifier import _read_function_context

    _empty_stats: dict = {
        "status": "ok", "reviewed": 0, "kept": 0, "lowered": 0,
        "dismissed": 0, "tokens_in": 0, "tokens_out": 0, "latency_ms": 0,
        "model": "", "verdicts": [], "error": None,
        "avg_confidence": None, "low_confidence_count": 0,
        "second_pass_count": 0, "second_pass_changed_count": 0,
    }

    if not verified:
        return [], [], dict(_empty_stats)

    worker = get_worker("verifier-reviewer")
    if worker is None:
        log.warning("verifier-reviewer role not found, skipping LLM judge")
        s = dict(_empty_stats)
        s.update({"status": "skipped", "reason": "no_worker", "kept": len(verified)})
        return verified, [], s

    # Partition by severity: medium+ go to LLM, low/info pass through
    to_review_idx: list[int] = []
    for i, f in enumerate(verified):
        sev = (f.get("severity") or "low").lower()
        if _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK["medium"]:
            to_review_idx.append(i)

    if not to_review_idx:
        s = dict(_empty_stats)
        s.update({"kept": len(verified)})
        return list(verified), [], s

    # Split into batches (size from env var, default 10)
    batch_size = int(_os_module.environ.get("PA_VERIFIER_BATCH_SIZE", "10"))
    batches: list[list[int]] = []
    for i in range(0, len(to_review_idx), batch_size):
        batches.append(to_review_idx[i:i + batch_size])

    aggregate_verdicts: dict[int, dict] = {}
    total_tokens_in = 0
    total_tokens_out = 0
    total_latency_ms = 0
    model_used = ""
    any_batch_succeeded = False
    last_error: str | None = None
    all_raw_verdicts: list[dict] = []

    for batch_idx, batch in enumerate(batches):
        # Build compact finding list with function-level code context
        compact = []
        for local_id, finding_idx in enumerate(batch):
            f = verified[finding_idx]
            loc = f.get("file", "")
            if isinstance(f.get("line"), int):
                loc += f":{f['line']}"
            # Fetch function-level code context
            if project_root is not None:
                ctx = _read_function_context(
                    f.get("file", ""),
                    f.get("line") or 0,
                    str(project_root),
                    fallback_window=context_lines,
                )
                code_context = ctx if ctx else "(source file not available)"
            else:
                code_context = "(source file not available)"
            compact.append({
                "id": local_id,
                "title": f.get("title", ""),
                "severity": f.get("severity", "low"),
                "category": f.get("category", ""),
                "cwe": f.get("cwe"),
                "location": loc,
                "evidence": (f.get("evidence") or "")[:300],
                "rationale": (f.get("rationale") or "")[:300],
                "confidence": round(f.get("confidence", 0.5), 2),
                "corroborating_roles": f.get("corroborating_roles", []),
                "agent_count": f.get("agent_count", 1),
                "code_context": code_context,
            })

        user_msg = (
            f"Below are {len(compact)} candidate findings (batch {batch_idx + 1}/{len(batches)}) "
            f"after automated L1/L2 deduplication (or high/critical bypass).\n"
            f"Assess each one and return your verdicts as a JSON array.\n\n"
            f"Each element MUST have these fields:\n"
            f'  {{"id": <int>, "verdict": "keep"|"lower"|"dismiss", '
            f'"confidence": <0-100>, '
            f'"exploitability": "high"|"medium"|"low"|"unknown", '
            f'"reason": "<string>"}}\n\n'
            f"Findings:\n{_json.dumps(compact, ensure_ascii=False, indent=2)}"
        )
        messages = [
            Message(role="system", content=worker.spec.system_prompt),
            Message(role="user", content=user_msg),
        ]

        t0 = time.time()
        try:
            result = await acall(worker.spec.llm_task_kind, messages,
                                 max_tokens=worker.spec.max_tokens)
        except Exception as e:  # noqa: BLE001
            log.warning("verifier-reviewer batch %d failed: %s", batch_idx, e)
            last_error = str(e)
            continue  # batch fails → those findings default to keep
        batch_latency = int((time.time() - t0) * 1000)
        total_latency_ms += batch_latency

        usage = getattr(result, "usage", None)
        if usage is None:
            in_tk, out_tk = 0, 0
        elif isinstance(usage, dict):
            in_tk = int(usage.get("input_tokens") or 0)
            out_tk = int(usage.get("output_tokens") or 0)
        else:
            in_tk = int(getattr(usage, "input_tokens", 0) or 0)
            out_tk = int(getattr(usage, "output_tokens", 0) or 0)
        total_tokens_in += in_tk
        total_tokens_out += out_tk
        if not model_used:
            model_used = getattr(result, "model", "") or ""

        text = (result.text or "").strip()
        # Parse verdicts JSON
        try:
            import re as _re
            fence = _re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text)
            if fence:
                batch_verdicts = _json.loads(fence.group(1))
            else:
                start = text.find("[")
                if start == -1:
                    raise ValueError("no json array found")
                batch_verdicts = _json.loads(text[start:])
        except Exception as e:  # noqa: BLE001
            log.warning("verifier-reviewer batch %d JSON parse failed: %s",
                        batch_idx, e)
            last_error = f"json parse: {e}"
            continue

        any_batch_succeeded = True
        all_raw_verdicts.extend(batch_verdicts if isinstance(batch_verdicts, list)
                                 else [])

        # Map local id → finding_idx, validate verdicts
        for v in batch_verdicts:
            if not isinstance(v, dict) or "id" not in v:
                continue
            try:
                local_id = int(v["id"])
            except (TypeError, ValueError):
                continue
            if local_id < 0 or local_id >= len(batch):
                continue
            verdict_str = str(v.get("verdict", "keep")).lower()
            if verdict_str not in ("keep", "lower", "dismiss"):
                continue
            # Parse new structured fields
            try:
                conf_val = int(v.get("confidence") or 50)
                conf_val = max(0, min(100, conf_val))
            except (TypeError, ValueError):
                conf_val = 50
            exp_val = str(v.get("exploitability") or "unknown").lower()
            if exp_val not in ("high", "medium", "low", "unknown"):
                exp_val = "unknown"
            finding_idx = batch[local_id]
            aggregate_verdicts[finding_idx] = {
                "verdict": verdict_str,
                "reason": (str(v.get("reason") or ""))[:500],
                "confidence": conf_val,
                "exploitability": exp_val,
            }

    # All batches failed → return original verified, status='failed'
    if not any_batch_succeeded:
        return verified, [], {"status": "failed",
                               "reviewed": len(to_review_idx),
                               "kept": len(verified), "lowered": 0,
                               "dismissed": 0, "tokens_in": total_tokens_in,
                               "tokens_out": total_tokens_out,
                               "latency_ms": total_latency_ms,
                               "model": model_used,
                               "verdicts": all_raw_verdicts,
                               "error": last_error or "all batches failed",
                               "avg_confidence": None,
                               "low_confidence_count": 0,
                               "second_pass_count": 0,
                               "second_pass_changed_count": 0}

    # Apply verdicts
    kept: list[dict] = []
    dismissed: list[dict] = []
    n_kept = 0
    n_lowered = 0
    n_dismissed = 0

    for i, f in enumerate(verified):
        v = aggregate_verdicts.get(i)
        if v is None:
            # Not reviewed (low/info passthrough OR missing verdict OR
            # batch-failed → default keep, no annotation)
            kept.append(f)
            if i in to_review_idx:
                n_kept += 1  # missing verdict treated as keep
            continue
        verdict_str = v["verdict"]
        reason = v["reason"]
        rev_conf = v.get("confidence", 50)
        rev_exp = v.get("exploitability", "unknown")
        if verdict_str == "dismiss":
            f2 = dict(f)
            f2["review_reason"] = reason
            f2["review_confidence"] = rev_conf
            f2["review_exploitability"] = rev_exp
            dismissed.append(f2)
            n_dismissed += 1
            log.debug("verifier-reviewer dismissed: %s — %s",
                      f.get("title"), reason)
        elif verdict_str == "lower":
            f2 = dict(f)
            f2["confidence"] = max(0.1, round(f2.get("confidence", 0.5) - 0.2, 2))
            f2["review_verdict"] = "lower"
            f2["review_note"] = reason
            f2["review_reason"] = reason
            f2["review_confidence"] = rev_conf
            f2["review_exploitability"] = rev_exp
            kept.append(f2)
            n_lowered += 1
        else:  # keep
            f2 = dict(f)
            f2["review_verdict"] = "keep"
            f2["review_note"] = reason
            f2["review_reason"] = reason
            f2["review_confidence"] = rev_conf
            f2["review_exploitability"] = rev_exp
            kept.append(f2)
            n_kept += 1

    # Re-sort kept by severity + confidence
    kept.sort(key=lambda x: (-_SEVERITY_RANK.get(x.get("severity", "low"), 0),
                              -x.get("confidence", 0)))

    # ---- B3: Borderline second pass ----------------------------------------
    # high/critical findings with low reviewer confidence get a second LLM call
    borderline = [
        f for f in kept
        if f.get("severity") in ("high", "critical")
        and f.get("review_confidence", 100) < 60
        and f.get("review_verdict") is not None  # was actually reviewed
    ]
    second_pass_count = len(borderline)
    second_pass_changed_count = 0

    for bf in borderline:
        first_verdict = bf.get("review_verdict", "keep")
        first_conf = bf.get("review_confidence", 50)
        first_reason = bf.get("review_reason") or bf.get("review_note") or ""
        # Build wider context
        if project_root is not None:
            ctx2 = _read_function_context(
                bf.get("file", ""),
                bf.get("line") or 0,
                str(project_root),
                max_function_lines=400,
                fallback_window=context_lines,
            )
            code_ctx2 = ctx2 if ctx2 else "(source file not available)"
        else:
            code_ctx2 = "(source file not available)"

        loc2 = bf.get("file", "")
        if isinstance(bf.get("line"), int):
            loc2 += f":{bf['line']}"

        compact2 = [{
            "id": 0,
            "title": bf.get("title", ""),
            "severity": bf.get("severity", "high"),
            "category": bf.get("category", ""),
            "cwe": bf.get("cwe"),
            "location": loc2,
            "evidence": (bf.get("evidence") or "")[:400],
            "rationale": (bf.get("rationale") or "")[:400],
            "confidence": round(bf.get("confidence", 0.5), 2),
            "corroborating_roles": bf.get("corroborating_roles", []),
            "agent_count": bf.get("agent_count", 1),
            "code_context": code_ctx2,
        }]
        second_msg = (
            f"Reviewer 1 has already evaluated this finding. "
            f"Their judgment: {first_verdict} with confidence {first_conf}/100. "
            f"Reason: {first_reason}\n\n"
            f"You have wider context. Make the final call.\n\n"
            f"Return a JSON array with one element:\n"
            f'  [{{"id": 0, "verdict": "keep"|"lower"|"dismiss", '
            f'"confidence": <0-100>, '
            f'"exploitability": "high"|"medium"|"low"|"unknown", '
            f'"reason": "<string>"}}]\n\n'
            f"Finding:\n{_json.dumps(compact2, ensure_ascii=False, indent=2)}"
        )
        messages2 = [
            Message(role="system", content=worker.spec.system_prompt),
            Message(role="user", content=second_msg),
        ]
        t2 = time.time()
        try:
            result2 = await acall(worker.spec.llm_task_kind, messages2,
                                  max_tokens=worker.spec.max_tokens)
        except Exception as e2:  # noqa: BLE001
            log.warning("verifier-reviewer second-pass failed for '%s': %s",
                        bf.get("title"), e2)
            continue  # keep first-pass result

        total_latency_ms += int((time.time() - t2) * 1000)
        usage2 = getattr(result2, "usage", None)
        if usage2 is None:
            in2, out2 = 0, 0
        elif isinstance(usage2, dict):
            in2 = int(usage2.get("input_tokens") or 0)
            out2 = int(usage2.get("output_tokens") or 0)
        else:
            in2 = int(getattr(usage2, "input_tokens", 0) or 0)
            out2 = int(getattr(usage2, "output_tokens", 0) or 0)
        total_tokens_in += in2
        total_tokens_out += out2

        text2 = (result2.text or "").strip()
        try:
            import re as _re2
            fence2 = _re2.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text2)
            if fence2:
                v2_list = _json.loads(fence2.group(1))
            else:
                s2 = text2.find("[")
                if s2 == -1:
                    raise ValueError("no json array")
                v2_list = _json.loads(text2[s2:])
        except Exception as e2:  # noqa: BLE001
            log.warning("verifier-reviewer second-pass JSON parse failed: %s", e2)
            continue

        if not isinstance(v2_list, list) or not v2_list:
            continue
        v2 = v2_list[0]
        if not isinstance(v2, dict):
            continue
        new_verdict = str(v2.get("verdict", "keep")).lower()
        if new_verdict not in ("keep", "lower", "dismiss"):
            new_verdict = "keep"
        try:
            new_conf = int(v2.get("confidence") or 50)
            new_conf = max(0, min(100, new_conf))
        except (TypeError, ValueError):
            new_conf = 50
        new_exp = str(v2.get("exploitability") or "unknown").lower()
        if new_exp not in ("high", "medium", "low", "unknown"):
            new_exp = "unknown"
        new_reason = (str(v2.get("reason") or ""))[:500]

        if new_verdict != first_verdict:
            second_pass_changed_count += 1

        # Override first-pass result on the finding dict in-place
        bf["review_verdict"] = new_verdict
        bf["review_confidence"] = new_conf
        bf["review_exploitability"] = new_exp
        bf["review_reason"] = new_reason
        bf["review_note"] = new_reason
        bf["review_pass"] = 2

        # If second pass says dismiss, move from kept to dismissed
        if new_verdict == "dismiss":
            kept.remove(bf)
            dismissed.append(bf)
            n_dismissed += 1
            n_kept -= 1

    # ---- Compute confidence stats ------------------------------------------
    reviewed_findings = [
        f for i, f in enumerate(verified)
        if i in set(to_review_idx) and aggregate_verdicts.get(i) is not None
    ]
    # Also include second-pass findings
    all_conf_values = [
        f.get("review_confidence", 50)
        for f in (kept + dismissed)
        if f.get("review_confidence") is not None
    ]
    avg_confidence = round(sum(all_conf_values) / len(all_conf_values)) if all_conf_values else None
    low_confidence_count = sum(1 for c in all_conf_values if c < 60)

    return kept, dismissed, {
        "status": "ok",
        "reviewed": len(to_review_idx),
        "kept": n_kept,
        "lowered": n_lowered,
        "dismissed": n_dismissed,
        "tokens_in": total_tokens_in,
        "tokens_out": total_tokens_out,
        "latency_ms": total_latency_ms,
        "model": model_used,
        "verdicts": all_raw_verdicts,
        "error": None,
        "avg_confidence": avg_confidence,
        "low_confidence_count": low_confidence_count,
        "second_pass_count": second_pass_count,
        "second_pass_changed_count": second_pass_changed_count,
    }


# ---- 0-day pipeline (M4) -------------------------------------------------

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _dict_to_finding(d: dict, *, target_ref: str = "?", idx: int = 0):
    """Coerce a verifier-output dict into an SDK Finding object.

    The 0-day pipeline (engines/unknown_detector) takes Finding objects; the
    rest of the multi-agent workflow uses plain dicts. This is the single
    point of conversion.
    """
    from pentest_agent_sdk.contracts import Finding, Severity, Evidence
    sev_str = (d.get("severity") or "low").lower()
    sev = getattr(Severity, sev_str, Severity.low)
    evidence_str = d.get("evidence") or ""
    rationale = d.get("rationale") or ""
    evidences = []
    if evidence_str:
        evidences.append(Evidence(kind="code_snippet",
                                    summary=str(evidence_str)[:1000],
                                    confidence=float(d.get("confidence", 0.5))))
    if rationale:
        evidences.append(Evidence(kind="analysis", summary=str(rationale)[:1000]))
    return Finding(
        id=f"verified-{idx}",
        title=str(d.get("title") or "(untitled)"),
        severity=sev,
        category=str(d.get("category") or "unknown"),
        target_ref=target_ref,
        evidence=evidences,
        cwe=d.get("cwe"),
        raw=d,
    )


async def _run_unknown_pipeline(
    *, task_id: int, target, verified: list[dict],
    enable_sandbox: bool = True,
    enable_disclosure: bool = True,
) -> AsyncIterator[dict]:
    """For each high+ verified finding, run novelty → PoC → sandbox → disclosure.

    Each finding is processed in parallel (asyncio.gather, capped by the
    same LLM semaphore as workers). Yields WS events as each stage completes.
    Persists results to the UnknownReport table.

    Returns nothing — pulls are async-iterated by the caller.
    """
    high_findings = [(i, f) for i, f in enumerate(verified)
                       if _SEVERITY_RANK.get((f.get("severity") or "").lower(), 0)
                          >= _SEVERITY_RANK["high"]]
    if not high_findings:
        yield {"event": "unknown_pipeline_skipped",
               "reason": "no high+ severity findings"}
        return

    yield {"event": "unknown_pipeline_started",
           "candidate_count": len(high_findings)}

    target_ref = str(getattr(target, "id", "?"))

    async def _process_one(idx: int, fdict: dict) -> dict:
        from engines.unknown_detector import process as process_unknown
        finding = _dict_to_finding(fdict, target_ref=target_ref, idx=idx)
        return await asyncio.to_thread(
            process_unknown,
            finding,
            sandbox=enable_sandbox,
            draft_disclosure=enable_disclosure,
        )

    tasks_co = [_process_one(idx, f) for (idx, f) in high_findings]
    for completed in asyncio.as_completed(tasks_co):
        try:
            report = await completed
        except Exception as e:  # noqa: BLE001
            log.warning("unknown pipeline crashed on one finding: %s", e)
            yield {"event": "unknown_pipeline_error", "detail": str(e)}
            continue

        # find this finding's index in `verified` (raw object identity may
        # not match because of the dict→Finding round-trip; use raw dict)
        fdict = report.finding.raw or {}
        idx = next((i for i, f in enumerate(verified)
                     if f.get("title") == fdict.get("title")), -1)
        if idx == -1:
            idx = 0

        # persist
        with Session(engine) as session:
            ur = UnknownReport(
                task_id=task_id,
                finding_idx=idx,
                finding_snapshot=fdict,
                novelty={
                    "value": report.novelty.value,
                    "similar_refs": list(report.novelty.similar_refs),
                    "rationale": report.novelty.rationale,
                },
                poc_source=report.poc.source if report.poc else None,
                poc_language=report.poc.language if report.poc else None,
                poc_notes=(report.poc.notes if report.poc else None),
                sandbox_triggered=(report.sandbox.triggered
                                     if report.sandbox else None),
                sandbox_exit_code=(report.sandbox.exit_code
                                     if report.sandbox else None),
                sandbox_stdout=(report.sandbox.stdout
                                  if report.sandbox else None),
                sandbox_stderr=(report.sandbox.stderr
                                  if report.sandbox else None),
                sandbox_duration_seconds=(report.sandbox.duration_seconds
                                            if report.sandbox else None),
                disclosure_body=(report.disclosure.body
                                   if report.disclosure else None),
                disclosure_cve_request=(report.disclosure.cve_request_draft
                                          if report.disclosure else None),
                disclosure_embargo_until=(report.disclosure.embargo_until
                                            if report.disclosure else None),
            )
            session.add(ur)
            session.commit()
            session.refresh(ur)
            ur_id = ur.id

        yield {
            "event": "novelty_scored",
            "report_id": ur_id,
            "finding_idx": idx,
            "novelty": report.novelty.value,
            "rationale": report.novelty.rationale,
            "is_zero_day_candidate": (report.poc is not None),
        }
        if report.poc:
            yield {
                "event": "poc_synthesized",
                "report_id": ur_id,
                "finding_idx": idx,
                "language": report.poc.language,
                "source_preview": (report.poc.source or "")[:600],
            }
        if report.sandbox:
            yield {
                "event": "sandbox_result",
                "report_id": ur_id,
                "finding_idx": idx,
                "triggered": report.sandbox.triggered,
                "exit_code": report.sandbox.exit_code,
                "stdout_preview": (report.sandbox.stdout or "")[:300],
                "stderr_preview": (report.sandbox.stderr or "")[:300],
                "duration_seconds": report.sandbox.duration_seconds,
            }
        if report.disclosure:
            yield {
                "event": "disclosure_drafted",
                "report_id": ur_id,
                "finding_idx": idx,
                "embargo_until": report.disclosure.embargo_until.isoformat(),
                "body_preview": (report.disclosure.body or "")[:300],
            }

    yield {"event": "unknown_pipeline_done"}


def run_workflow(*, user_prompt: str, target, owner_id: int) -> dict:
    """Sync wrapper: collect all events, return final result.

    Used by tests and by the non-streaming POST /api/chat path.
    """
    async def _collect() -> dict:
        final: dict = {"events": [], "report": "", "findings": [], "stats": {}}
        async for evt in astream_workflow(user_prompt=user_prompt,
                                            target=target,
                                            owner_id=owner_id):
            final["events"].append(evt)
            if evt.get("event") == "workflow_done":
                final["report"] = evt.get("report", "")
                final["findings"] = evt.get("findings", [])
                final["stats"] = evt.get("stats", {})
            if evt.get("event") == "workflow_error":
                final["error"] = evt.get("detail", "")
        return final
    return asyncio.run(_collect())
