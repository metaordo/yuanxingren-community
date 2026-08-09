"""Regression: astream_workflow must not block the event loop.

Root cause of the "WebSocket connection failed" (keepalive ping timeout ->
1011) bug: orchestration-level blocking calls (_stage_project /
build_file_index / supervisor_pick / verify / render_report) ran synchronously
inside the async generator, starving the websockets keepalive pong. They are
now offloaded via asyncio.to_thread.

Deterministic check (condition-based, no wall-clock thresholds): the stubbed
blocking intake waits on a threading.Event that can ONLY be set by a coroutine
running on the event loop. If the call is offloaded, the loop stays free, the
coroutine runs and sets the event, and the thread proceeds. If the call blocks
the loop, the coroutine never runs and the thread times out -> assertion fails.
"""
from __future__ import annotations
import asyncio
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("PA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PA_JWT_SECRET", "x")
    # Create tables on the SAME engine the workflow module already bound via
    # `from ..db import engine` — don't reload backend.db, or workflow.engine
    # ends up pointing at a stale/torn-down DB when another test imported it
    # first (test-isolation trap that has nothing to do with the fix).
    from backend.db import init_db
    from backend.agents import workflow as wf
    from sqlmodel import SQLModel
    init_db()
    SQLModel.metadata.create_all(wf.engine)
    return wf.engine


@pytest.mark.asyncio
async def test_orchestration_does_not_block_event_loop(db, monkeypatch):
    from backend.agents import workflow as wf

    loop_ran = threading.Event()      # set by a coroutine on the loop
    thread_saw_loop_run = {"ok": False}

    monkeypatch.setattr(wf, "_resolve_upload",
                        lambda target, session: {"id": 1, "storage_path": "x", "filename": "x"})
    monkeypatch.setattr(wf, "_stage_project",
                        lambda upload, data_dir: (Path("/tmp"), []))

    def blocking_index(project_root):
        # Wait for the event loop to make progress. Only gets set if the loop
        # is free to run the poker coroutine concurrently -> proves offload.
        thread_saw_loop_run["ok"] = loop_ran.wait(timeout=3.0)
        return {"files": [], "by_ext": {}, "total_bytes": 0}
    monkeypatch.setattr(wf, "build_file_index", blocking_index)
    monkeypatch.setattr(wf, "supervisor_pick",
                        lambda file_index, user_prompt: {"picked": [], "rejected": [], "rationale": "x"})

    async def poker():
        # If the loop is free during the blocking call, this runs and unblocks
        # the worker thread. If the loop is starved, this never executes.
        await asyncio.sleep(0.05)
        loop_ran.set()

    class _T:
        id = 1

    poke_task = asyncio.create_task(poker())
    events = []
    async for evt in wf.astream_workflow(user_prompt="audit", target=_T(), owner_id=1):
        events.append(evt)
    await poke_task

    assert thread_saw_loop_run["ok"], "event loop was starved during intake (call not offloaded)"
    assert any(e["event"] == "workflow_done" for e in events)
