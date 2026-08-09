"""Tests for _run_verifier_reviewer in workflow.py."""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
from backend.agents.workflow import _run_verifier_reviewer


def _make_finding(sev, file, line, title="t", conf=0.5):
    return {
        "title": title, "severity": sev, "category": "injection",
        "file": file, "line": line, "evidence": "ev", "rationale": "rat",
        "role": "sqli-analyst", "confidence": conf, "cwe": "CWE-89",
    }


def _make_root_with(tmp_path: Path, content: str, path: str = "a.py") -> Path:
    (tmp_path / path).write_text(content)
    return tmp_path


def _llm_result(verdicts: list[dict]) -> MagicMock:
    res = MagicMock()
    res.text = json.dumps(verdicts)
    res.usage = {"input_tokens": 100, "output_tokens": 50}
    res.model = "claude-haiku-4-5-20251001"
    return res


@pytest.mark.asyncio
async def test_low_info_skipped_from_review(tmp_path):
    """low/info findings 不送 LLM,直接 kept。"""
    findings = [
        _make_finding("low", "a.py", 1),
        _make_finding("info", "a.py", 2),
    ]
    root = _make_root_with(tmp_path, "x\n")
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result([]))) as mock_call:
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    # LLM 不应被调用(无 medium+ 送审)
    mock_call.assert_not_called()
    assert len(kept) == 2
    assert dismissed == []
    assert stats["reviewed"] == 0
    assert stats["status"] == "ok"


@pytest.mark.asyncio
async def test_medium_high_critical_sent_to_review(tmp_path):
    findings = [
        _make_finding("medium", "a.py", 1),
        _make_finding("high", "a.py", 2),
        _make_finding("critical", "a.py", 3),
    ]
    root = _make_root_with(tmp_path, "x\n" * 10)
    verdicts = [
        {"id": 0, "verdict": "keep", "confidence": 90, "reason": "ok"},
        {"id": 1, "verdict": "keep", "confidence": 90, "reason": "ok"},
        {"id": 2, "verdict": "keep", "confidence": 90, "reason": "ok"},
    ]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))) as mock_call:
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    mock_call.assert_called_once()
    assert stats["reviewed"] == 3
    assert stats["kept"] == 3
    assert len(kept) == 3
    assert all(f["review_verdict"] == "keep" for f in kept)


@pytest.mark.asyncio
async def test_dismiss_moves_to_dismissed_list(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    root = _make_root_with(tmp_path, "x\n")
    verdicts = [{"id": 0, "verdict": "dismiss", "reason": "test fixture"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert kept == []
    assert len(dismissed) == 1
    assert dismissed[0]["review_reason"] == "test fixture"
    assert stats["dismissed"] == 1


@pytest.mark.asyncio
async def test_lower_decreases_confidence(tmp_path):
    findings = [_make_finding("high", "a.py", 1, conf=0.8)]
    root = _make_root_with(tmp_path, "x\n")
    verdicts = [{"id": 0, "verdict": "lower", "reason": "weak evidence"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert len(kept) == 1
    assert kept[0]["confidence"] == 0.6  # 0.8 - 0.2
    assert kept[0]["review_verdict"] == "lower"
    assert kept[0]["review_note"] == "weak evidence"
    assert stats["lowered"] == 1


@pytest.mark.asyncio
async def test_lower_confidence_lower_bound(tmp_path):
    findings = [_make_finding("high", "a.py", 1, conf=0.15)]
    root = _make_root_with(tmp_path, "x\n")
    verdicts = [{"id": 0, "verdict": "lower", "reason": "r"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, _, _ = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert kept[0]["confidence"] == 0.1


@pytest.mark.asyncio
async def test_code_context_included_in_prompt(tmp_path):
    findings = [_make_finding("high", "a.py", 3)]
    root = _make_root_with(tmp_path, "L1\nL2\nL3\nL4\nL5\n")
    captured = {}

    async def fake_acall(*args, **kwargs):
        # capture the user message
        for msg in args[1]:
            if msg.role == "user":
                captured["user_msg"] = msg.content
        return _llm_result([{"id": 0, "verdict": "keep", "confidence": 90, "reason": "ok"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        await _run_verifier_reviewer(findings, project_root=root, context_lines=2)
    # New format: code_context contains line-numbered source from
    # _read_function_context (function-level or ±N fallback)
    assert "L3" in captured["user_msg"]
    assert "code_context" in captured["user_msg"]


@pytest.mark.asyncio
async def test_llm_failure_returns_unchanged(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    root = _make_root_with(tmp_path, "x\n")
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(side_effect=RuntimeError("API 502"))):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert len(kept) == 1
    assert kept[0]["evidence"] == "ev"  # unchanged
    assert dismissed == []
    assert stats["status"] == "failed"
    assert "API 502" in stats["error"]


@pytest.mark.asyncio
async def test_invalid_json_returns_unchanged(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    root = _make_root_with(tmp_path, "x\n")
    bad = MagicMock()
    bad.text = "not a json"
    bad.usage = {"input_tokens": 10, "output_tokens": 5}
    bad.model = "m"
    with patch("backend.agents.workflow.acall", new=AsyncMock(return_value=bad)):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert len(kept) == 1
    assert dismissed == []
    assert stats["status"] == "failed"


@pytest.mark.asyncio
async def test_out_of_range_id_skipped(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    root = _make_root_with(tmp_path, "x\n")
    verdicts = [{"id": 99, "verdict": "dismiss", "reason": "x"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    # id=99 越界忽略,原 finding 按 keep 处理
    assert len(kept) == 1
    assert dismissed == []


@pytest.mark.asyncio
async def test_invalid_verdict_treated_as_keep(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    root = _make_root_with(tmp_path, "x\n")
    verdicts = [{"id": 0, "verdict": "unknown_verdict", "reason": "x"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert len(kept) == 1
    assert dismissed == []
    assert stats["kept"] == 1


@pytest.mark.asyncio
async def test_missing_verdict_treated_as_keep(tmp_path):
    findings = [
        _make_finding("high", "a.py", 1),
        _make_finding("high", "a.py", 2),
    ]
    root = _make_root_with(tmp_path, "x\n" * 5)
    # LLM 只返了第 0 条,漏了第 1 条
    verdicts = [{"id": 0, "verdict": "keep", "reason": "ok"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert len(kept) == 2  # 漏的也保留
    assert stats["kept"] == 2


@pytest.mark.asyncio
async def test_batch_split_when_over_batch_size(tmp_path):
    """Batch size is 10 (was 50 before precision upgrade)."""
    findings = [_make_finding("high", "a.py", i + 1) for i in range(60)]
    root = _make_root_with(tmp_path, "\n".join(f"L{i}" for i in range(1, 100)))
    call_count = {"n": 0}

    async def fake_acall(*args, **kwargs):
        call_count["n"] += 1
        # 解析 user msg 找有多少 finding
        user_msg = next(m.content for m in args[1] if m.role == "user")
        # 计数 finding entries via top-level "id": occurrences (each finding has 1)
        # but skip the JSON schema example "id" — count actual items.
        # Simpler: count the "title" key — each finding has one
        n_in_batch = user_msg.count('"title":')
        # confidence 90 → no borderline trigger
        verdicts = [{"id": i, "verdict": "keep", "confidence": 90, "reason": "ok"}
                    for i in range(n_in_batch)]
        return _llm_result(verdicts)

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert call_count["n"] == 6  # 60 findings / batch_size=10 = 6 batches
    assert len(kept) == 60
    assert stats["reviewed"] == 60


@pytest.mark.asyncio
async def test_one_batch_fails_others_succeed(tmp_path):
    findings = [_make_finding("high", "a.py", i + 1) for i in range(60)]
    root = _make_root_with(tmp_path, "\n".join(f"L{i}" for i in range(1, 100)))
    call_count = {"n": 0}

    async def fake_acall(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("batch 1 failed")
        user_msg = next(m.content for m in args[1] if m.role == "user")
        n = user_msg.count('"title":')
        return _llm_result([{"id": i, "verdict": "dismiss",
                              "confidence": 90, "reason": "x"}
                            for i in range(n)])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    # batch_size=10 → 6 batches. Batch 1 fails → 10 items default keep.
    # Batches 2-6 succeed → 50 items dismissed.
    assert len(kept) == 10
    assert len(dismissed) == 50


@pytest.mark.asyncio
async def test_empty_input_skipped(tmp_path):
    kept, dismissed, stats = await _run_verifier_reviewer(
        [], project_root=tmp_path, context_lines=2
    )
    assert kept == []
    assert dismissed == []
    assert stats["status"] == "ok"
    assert stats["reviewed"] == 0


@pytest.mark.asyncio
async def test_project_root_none_skips_context():
    """project_root=None 时 code_context 填占位但仍送审。"""
    findings = [_make_finding("high", "a.py", 1)]
    captured = {}

    async def fake_acall(*args, **kwargs):
        captured["user_msg"] = next(m.content for m in args[1] if m.role == "user")
        return _llm_result([{"id": 0, "verdict": "keep", "reason": "ok"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        await _run_verifier_reviewer(findings, project_root=None, context_lines=2)
    # code_context 应填占位字串
    assert "source file not available" in captured["user_msg"].lower() or \
           "not available" in captured["user_msg"].lower()


@pytest.mark.asyncio
async def test_file_not_found_continues_with_placeholder(tmp_path):
    findings = [_make_finding("high", "missing.py", 1)]
    root = _make_root_with(tmp_path, "x\n", path="other.py")  # missing.py 不存在
    captured = {}

    async def fake_acall(*args, **kwargs):
        captured["user_msg"] = next(m.content for m in args[1] if m.role == "user")
        return _llm_result([{"id": 0, "verdict": "keep", "reason": "ok"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        await _run_verifier_reviewer(findings, project_root=root, context_lines=2)
    assert "not available" in captured["user_msg"].lower()


# --- AgentRun wrapping helpers tests ---
from sqlmodel import SQLModel, Session as _Session, create_engine as _create_engine
from backend.agents.models import AgentTask, AgentRun, RunStatus, TaskStatus
from backend.agents.workflow import (
    _create_review_agent_run, _finalize_review_agent_run,
)


@pytest.fixture()
def mem_engine():
    """In-memory SQLite engine isolated per test."""
    eng = _create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture(autouse=False)
def patch_engine(mem_engine, monkeypatch):
    """Patch backend.agents.workflow.engine with the in-memory engine."""
    import backend.agents.workflow as wf_mod
    monkeypatch.setattr(wf_mod, "engine", mem_engine)


def _create_task(mem_engine) -> int:
    with _Session(mem_engine) as s:
        t = AgentTask(owner_id=1, user_prompt="test", status=TaskStatus.running)
        s.add(t)
        s.commit()
        s.refresh(t)
        return t.id


def test_create_review_agent_run_creates_row(mem_engine, patch_engine):
    task_id = _create_task(mem_engine)
    run_id = _create_review_agent_run(task_id)
    with _Session(mem_engine) as s:
        row = s.get(AgentRun, run_id)
    assert row.role == "verifier-reviewer"
    assert row.status == RunStatus.running
    assert row.task_id == task_id
    assert row.started_at is not None


def test_finalize_review_agent_run_done_sets_fields(mem_engine, patch_engine):
    task_id = _create_task(mem_engine)
    run_id = _create_review_agent_run(task_id)
    stats = {"tokens_in": 100, "tokens_out": 50, "model": "haiku",
             "kept": 5, "lowered": 1, "dismissed": 2, "reviewed": 8,
             "latency_ms": 1200, "status": "ok"}
    _finalize_review_agent_run(
        run_id, stats, status="done",
        output={"verdicts": [], "dismissed": [{"title": "x"}]}
    )
    with _Session(mem_engine) as s:
        row = s.get(AgentRun, run_id)
    assert row.status == RunStatus.done
    assert row.tokens_in == 100
    assert row.tokens_out == 50
    assert row.llm_model == "haiku"
    assert row.finished_at is not None
    assert row.findings == {"verdicts": [], "dismissed": [{"title": "x"}]}


def test_finalize_review_agent_run_failed_sets_error(mem_engine, patch_engine):
    task_id = _create_task(mem_engine)
    run_id = _create_review_agent_run(task_id)
    _finalize_review_agent_run(
        run_id, {}, status="failed", error="LLM down"
    )
    with _Session(mem_engine) as s:
        row = s.get(AgentRun, run_id)
    assert row.status == RunStatus.failed
    assert row.error == "LLM down"


@pytest.mark.asyncio
async def test_usage_attribute_object_handled(tmp_path):
    """Real Usage is a @dataclass with .input_tokens attrs (not a dict).
    Regression for production crash 'Usage object has no attribute get'."""
    from backend.llm.base import Usage
    findings = [_make_finding("high", "a.py", 1)]
    root = _make_root_with(tmp_path, "x\n")

    res = MagicMock()
    # confidence 90 → no borderline trigger → single call
    res.text = json.dumps([{"id": 0, "verdict": "keep",
                             "confidence": 90, "reason": "ok"}])
    res.usage = Usage(input_tokens=42, output_tokens=17)  # real dataclass
    res.model = "claude-haiku-4-5-20251001"

    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=res)):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=root, context_lines=2
        )
    assert len(kept) == 1
    assert stats["status"] == "ok"
    assert stats["tokens_in"] == 42
    assert stats["tokens_out"] == 17


# ====================================================================
# Precision-upgrade tests: function context + structured output +
# borderline second-pass + sort.
# ====================================================================

from backend.agents.verifier import _read_function_context


def test_function_context_python_ast_returns_full_function(tmp_path):
    src = (
        "import os\n"  # L1
        "\n"  # L2
        "def outer():\n"  # L3
        "    pass\n"  # L4
        "\n"  # L5
        "def target_func(x):\n"  # L6
        "    if x > 0:\n"  # L7
        "        return x * 2\n"  # L8 ← finding here
        "    return -1\n"  # L9
        "\n"  # L10
        "def other():\n"  # L11
        "    pass\n"  # L12
    )
    (tmp_path / "a.py").write_text(src)
    ctx = _read_function_context("a.py", 8, str(tmp_path))
    # Should include full target_func (L6..L9), and nothing from outer/other
    assert "def target_func(x):" in ctx
    assert "return x * 2" in ctx
    assert "return -1" in ctx
    assert "def outer" not in ctx
    assert "def other" not in ctx


def test_function_context_c_brace_matching_returns_full_function(tmp_path):
    src = (
        "#include <stdio.h>\n"  # L1
        "\n"  # L2
        "void other() { return; }\n"  # L3
        "\n"  # L4
        "int target(char *buf, int n) {\n"  # L5
        "    if (n > 0) {\n"  # L6
        "        strcpy(buf, \"x\");\n"  # L7 ← finding
        "    }\n"  # L8
        "    return 0;\n"  # L9
        "}\n"  # L10
        "\n"  # L11
        "void unrelated() { return; }\n"  # L12
    )
    (tmp_path / "a.c").write_text(src)
    ctx = _read_function_context("a.c", 7, str(tmp_path))
    # Must include the target line and surrounding declaration
    assert "strcpy(buf" in ctx
    assert "int target(char *buf" in ctx
    # Must NOT include unrelated functions
    assert "unrelated" not in ctx
    assert "void other()" not in ctx


def test_function_context_fallback_for_unknown_extension(tmp_path):
    src = "\n".join(f"line {i}" for i in range(1, 101))
    (tmp_path / "x.xyz").write_text(src)
    ctx = _read_function_context("x.xyz", 50, str(tmp_path), fallback_window=5)
    # Window fallback: should include lines around 50 but not 1 or 100
    assert "line 50" in ctx
    assert "line 45" in ctx
    assert "line 55" in ctx
    assert "line 1\n" not in ctx
    assert "line 100" not in ctx


def test_function_context_fallback_when_function_too_big(tmp_path):
    # Build a Python file where a single function spans > max_function_lines
    body_lines = "\n".join(f"    a = {i}" for i in range(1, 350))
    src = "def huge():\n" + body_lines + "\n"
    (tmp_path / "big.py").write_text(src)
    # Finding at line 200 — function spans L1..L350 = 350 lines > max=200
    ctx = _read_function_context("big.py", 200, str(tmp_path),
                                  max_function_lines=200,
                                  fallback_window=5)
    # Should NOT contain the entire function — fallback to ±5 window
    assert "a = 196" in ctx
    assert "a = 200" in ctx
    assert "a = 204" in ctx
    # 175 is outside ±5 window from line 200
    assert "a = 175" not in ctx


def test_function_context_path_traversal_blocked(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("readable secret\n")
    ctx = _read_function_context("../secret.txt", 1, str(tmp_path))
    assert ctx == ""


def test_function_context_absolute_path_blocked(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    outside = tmp_path.parent / "abs_secret.txt"
    outside.write_text("readable\n")
    ctx = _read_function_context(str(outside), 1, str(tmp_path))
    assert ctx == ""


def test_function_context_symlink_escape_blocked(tmp_path):
    inside = tmp_path / "linkme.py"
    outside = tmp_path.parent / "outside_target.txt"
    outside.write_text("x = 1\n")
    try:
        os.symlink(str(outside), str(inside))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported")
    ctx = _read_function_context("linkme.py", 1, str(tmp_path))
    assert ctx == ""


@pytest.mark.asyncio
async def test_structured_output_parses_confidence_and_exploitability(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    verdicts = [{"id": 0, "verdict": "keep", "confidence": 88,
                  "exploitability": "high", "reason": "clear path"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, _, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    assert kept[0]["review_confidence"] == 88
    assert kept[0]["review_exploitability"] == "high"
    assert kept[0]["review_verdict"] == "keep"


@pytest.mark.asyncio
async def test_missing_confidence_defaults_to_50(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    verdicts = [{"id": 0, "verdict": "keep", "reason": "ok"}]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        kept, _, _ = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    assert kept[0]["review_confidence"] == 50


@pytest.mark.asyncio
async def test_borderline_high_low_confidence_triggers_second_pass(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    call_log = []

    async def fake_acall(*args, **kwargs):
        call_log.append(kwargs)
        if len(call_log) == 1:
            # First pass: low confidence triggers borderline
            return _llm_result([{"id": 0, "verdict": "keep",
                                  "confidence": 40, "reason": "unclear"}])
        # Second pass: more decisive
        return _llm_result([{"id": 0, "verdict": "keep",
                              "confidence": 80, "reason": "after deeper look"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, _, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    assert len(call_log) == 2  # first + borderline second
    assert stats["second_pass_count"] == 1
    assert kept[0]["review_pass"] == 2
    assert kept[0]["review_confidence"] == 80


@pytest.mark.asyncio
async def test_borderline_high_high_confidence_does_not_trigger(tmp_path):
    findings = [_make_finding("high", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    call_log = []

    async def fake_acall(*args, **kwargs):
        call_log.append(1)
        return _llm_result([{"id": 0, "verdict": "keep",
                              "confidence": 90, "reason": "clear"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, _, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    assert len(call_log) == 1  # only first pass
    assert stats["second_pass_count"] == 0
    assert kept[0].get("review_pass") != 2


@pytest.mark.asyncio
async def test_borderline_medium_does_not_trigger_second_pass(tmp_path):
    findings = [_make_finding("medium", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    call_log = []

    async def fake_acall(*args, **kwargs):
        call_log.append(1)
        # Low confidence but only medium severity — not borderline
        return _llm_result([{"id": 0, "verdict": "keep",
                              "confidence": 30, "reason": "weak"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, _, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    assert len(call_log) == 1
    assert stats["second_pass_count"] == 0


@pytest.mark.asyncio
async def test_second_pass_can_change_verdict(tmp_path):
    findings = [_make_finding("critical", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    call_log = []

    async def fake_acall(*args, **kwargs):
        call_log.append(1)
        if len(call_log) == 1:
            return _llm_result([{"id": 0, "verdict": "keep",
                                  "confidence": 40, "reason": "uncertain"}])
        # Second pass dismisses
        return _llm_result([{"id": 0, "verdict": "dismiss",
                              "confidence": 85, "reason": "false positive"}])

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, dismissed, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    # First-pass kept it; second-pass dismissed → finding moves to dismissed
    assert len(kept) == 0
    assert len(dismissed) == 1
    assert dismissed[0]["review_reason"] == "false positive"
    assert stats["second_pass_changed_count"] == 1


@pytest.mark.asyncio
async def test_second_pass_failure_keeps_first_pass(tmp_path):
    findings = [_make_finding("critical", "a.py", 1)]
    (tmp_path / "a.py").write_text("x = 1\n")
    call_log = []

    async def fake_acall(*args, **kwargs):
        call_log.append(1)
        if len(call_log) == 1:
            return _llm_result([{"id": 0, "verdict": "keep",
                                  "confidence": 40, "reason": "uncertain"}])
        raise RuntimeError("second-pass API down")

    with patch("backend.agents.workflow.acall", new=fake_acall):
        kept, _, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    # First-pass kept; second-pass failed → preserve first-pass result
    assert len(kept) == 1
    assert kept[0]["review_confidence"] == 40
    assert kept[0]["review_verdict"] == "keep"


@pytest.mark.asyncio
async def test_stats_reports_avg_confidence(tmp_path):
    findings = [_make_finding("high", "a.py", i + 1) for i in range(3)]
    (tmp_path / "a.py").write_text("x = 1\n" * 5)
    verdicts = [
        {"id": 0, "verdict": "keep", "confidence": 90, "reason": "ok"},
        {"id": 1, "verdict": "keep", "confidence": 80, "reason": "ok"},
        {"id": 2, "verdict": "keep", "confidence": 70, "reason": "ok"},
    ]
    with patch("backend.agents.workflow.acall",
               new=AsyncMock(return_value=_llm_result(verdicts))):
        _, _, stats = await _run_verifier_reviewer(
            findings, project_root=tmp_path, context_lines=2
        )
    # All high-conf → no borderline. Average should be 80.
    assert stats["avg_confidence"] == 80
    assert stats["low_confidence_count"] == 0
