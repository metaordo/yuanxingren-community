"""Tests for high/critical bypass + _annotate_corroboration in verifier.py."""
import os
import tempfile
from pathlib import Path

import pytest

from backend.agents.verifier import (
    _annotate_corroboration,
    _norm_finding,
    _read_code_context,
    verify,
)


def _make(role, sev, file, line, conf=0.5, evidence="evid", title="t"):
    return {
        "title": title, "severity": sev, "category": "injection",
        "file": file, "line": line, "evidence": evidence,
        "rationale": "rat", "role": role, "confidence": conf, "cwe": "CWE-89",
    }


def test_annotate_single_finding_no_corroboration():
    fs = [_make("sqli-analyst", "high", "a.py", 10)]
    out = _annotate_corroboration(fs)
    assert len(out) == 1
    assert out[0]["corroborating_roles"] == ["sqli-analyst"]
    assert out[0]["agent_count"] == 1
    assert out[0]["confidence"] == 0.5  # no boost for single


def test_annotate_two_agents_same_site_boosts_confidence():
    fs = [
        _make("sqli-analyst", "high", "a.py", 42, conf=0.8),
        _make("code-auditor", "high", "a.py", 43, conf=0.7),
    ]
    out = _annotate_corroboration(fs)
    assert len(out) == 2  # 不合并,各自保留
    for f in out:
        assert set(f["corroborating_roles"]) == {"sqli-analyst", "code-auditor"}
        assert f["agent_count"] == 2
    # confidence boost +0.15
    confs = sorted(f["confidence"] for f in out)
    assert confs == [0.85, 0.95]


def test_annotate_preserves_original_evidence():
    fs = [
        _make("sqli-analyst", "high", "a.py", 42, evidence="SQL evidence"),
        _make("code-auditor", "high", "a.py", 43, evidence="taint flow"),
    ]
    out = _annotate_corroboration(fs)
    evidences = sorted(f["evidence"] for f in out)
    assert evidences == ["SQL evidence", "taint flow"]


def test_annotate_different_sites_no_corroboration():
    fs = [
        _make("sqli-analyst", "high", "a.py", 10),
        _make("sqli-analyst", "high", "b.py", 10),  # 不同文件
    ]
    out = _annotate_corroboration(fs)
    for f in out:
        assert f["agent_count"] == 1


def test_annotate_no_line_uses_none_bucket():
    fs = [
        _make("sqli-analyst", "high", "a.py", None),
        _make("code-auditor", "high", "a.py", None),
    ]
    out = _annotate_corroboration(fs)
    # 同文件 + 无行号 → 同桶
    for f in out:
        assert f["agent_count"] == 2


def test_annotate_empty_input():
    assert _annotate_corroboration([]) == []


def test_annotate_confidence_cap_at_099():
    """Two roles both with high confidence should still cap at 0.99, not exceed it."""
    fs = [
        _make("sqli-analyst", "high", "a.py", 42, conf=0.9),
        _make("code-auditor", "high", "a.py", 43, conf=0.9),
    ]
    out = _annotate_corroboration(fs)
    # 0.9 + 0.15 = 1.05 → capped at 0.99
    for f in out:
        assert f["confidence"] == 0.99


def _make_project(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create files under tmp_path/'project'; return that project root.

    Uses pytest's tmp_path fixture for automatic cleanup.
    """
    root = tmp_path / "project"
    root.mkdir(exist_ok=True)
    for path, content in files.items():
        p = root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_read_context_basic(tmp_path):
    root = _make_project(tmp_path, {"a.py": "\n".join(f"line_{i}" for i in range(1, 21))})
    ctx = _read_code_context(root, "a.py", 10, context=2)
    assert ctx is not None
    assert ">>>" in ctx  # target line marked
    assert "line_10" in ctx
    assert "line_8" in ctx and "line_12" in ctx
    assert "line_7" not in ctx  # outside ±2


def test_read_context_target_line_marked(tmp_path):
    root = _make_project(tmp_path, {"a.py": "a\nb\nc\nd\ne\n"})
    ctx = _read_code_context(root, "a.py", 3, context=1)
    assert ctx is not None
    lines = ctx.splitlines()
    # Find ">>> 3" prefix on target line
    assert any(l.lstrip().startswith(">>>") and "3" in l and "c" in l
               for l in lines)


def test_read_context_path_traversal_blocked(tmp_path):
    """Relative ../ traversal escaping project_root must return None."""
    root = _make_project(tmp_path, {"a.py": "x"})
    # Put a real file OUTSIDE project_root so we know None comes from the
    # security check, not from "file not found"
    outside = tmp_path / "secret.txt"
    outside.write_text("readable secret\n")
    # Try to traverse to it
    ctx = _read_code_context(root, "../secret.txt", 1)
    assert ctx is None


def test_read_context_absolute_path_blocked(tmp_path):
    """Absolute path outside project_root must return None even if file exists."""
    root = _make_project(tmp_path, {"a.py": "x"})
    outside = tmp_path / "secret.txt"
    outside.write_text("readable secret\n")
    ctx = _read_code_context(root, str(outside), 1)
    assert ctx is None


def test_read_context_file_not_found(tmp_path):
    root = _make_project(tmp_path, {"a.py": "x"})
    ctx = _read_code_context(root, "missing.py", 1)
    assert ctx is None


def test_read_context_line_none(tmp_path):
    root = _make_project(tmp_path, {"a.py": "x\ny\n"})
    ctx = _read_code_context(root, "a.py", None)
    assert ctx is None


def test_read_context_line_out_of_range(tmp_path):
    root = _make_project(tmp_path, {"a.py": "x\ny\n"})
    ctx = _read_code_context(root, "a.py", 999)
    assert ctx is None


def test_read_context_clips_at_file_boundaries(tmp_path):
    root = _make_project(tmp_path, {"a.py": "line1\nline2\nline3\n"})
    ctx = _read_code_context(root, "a.py", 1, context=10)
    # 不报错,返回从文件开头到末尾
    assert ctx is not None
    assert "line1" in ctx and "line3" in ctx


def test_verify_high_bypasses_l1():
    """High severity findings 不被 L1 合并:同 (cat,file,line//5) 两条都保留。"""
    raw = [
        _make("sqli-analyst", "high", "a.py", 42, evidence="evidence A"),
        _make("code-auditor", "high", "a.py", 43, evidence="evidence B"),
    ]
    v = verify(raw)
    # 不合并 → 两条都在
    assert len(v["verified"]) == 2
    evs = sorted(f["evidence"] for f in v["verified"])
    assert evs == ["evidence A", "evidence B"]
    # 都被标注 agent_count=2
    for f in v["verified"]:
        assert f["agent_count"] == 2


def test_verify_critical_bypasses_l1():
    raw = [_make("a", "critical", "x.py", 1), _make("b", "critical", "x.py", 1)]
    v = verify(raw)
    assert len(v["verified"]) == 2


def test_verify_medium_still_merged_by_l1():
    """Medium 仍走 L1:同位置合并成一条 representative。"""
    raw = [
        _make("sqli-analyst", "medium", "a.py", 42, conf=0.8),
        _make("code-auditor", "medium", "a.py", 43, conf=0.8),
    ]
    v = verify(raw)
    # L1 合并 → 1 条 representative
    assert len(v["verified"]) == 1
    assert v["verified"][0]["agent_count"] == 2


def test_verify_low_filtered_by_l1():
    """单 agent 报 low + 低 confidence → 被 L1 过滤。"""
    raw = [_make("sqli-analyst", "low", "a.py", 42, conf=0.3)]
    v = verify(raw)
    assert len(v["verified"]) == 0


def test_verify_stats_high_critical_bypassed():
    raw = [
        _make("a", "high", "x.py", 1),
        _make("b", "critical", "y.py", 2),
        _make("c", "medium", "z.py", 3, conf=0.8),
    ]
    v = verify(raw)
    assert v["stats"]["high_critical_bypassed"] == 2


def test_verify_mixed_severity_preserves_high_evidence():
    """混合 severity:high 的 evidence 完整保留,medium 被合并后只剩 representative。"""
    raw = [
        _make("sqli-analyst", "high", "a.py", 10, evidence="HIGH-A"),
        _make("code-auditor", "high", "a.py", 11, evidence="HIGH-B"),
        _make("xss-analyst", "medium", "b.py", 20, evidence="MED-A", conf=0.8),
        _make("web-recon", "medium", "b.py", 21, evidence="MED-B", conf=0.8),
    ]
    v = verify(raw)
    # 2 条 high(都保留) + 1 条 medium(合并)
    assert len(v["verified"]) == 3
    high_evs = sorted(f["evidence"] for f in v["verified"]
                      if f["severity"] == "high")
    assert high_evs == ["HIGH-A", "HIGH-B"]


def test_verify_sorts_by_severity_desc_then_confidence():
    """Final verified is sorted: critical > high > medium > low > info, then -confidence."""
    raw = [
        _make("a", "low", "a.py", 1, conf=0.9),
        _make("b", "critical", "b.py", 1, conf=0.5),
        _make("c", "high", "c.py", 1, conf=0.4),
        _make("d", "medium", "d.py", 1, conf=0.8),
        _make("e", "high", "e.py", 1, conf=0.7),
    ]
    # Distinct CWEs so L2 (same-CWE pattern merge) doesn't collapse medium+low
    for i, f in enumerate(raw):
        f["cwe"] = f"CWE-{100 + i}"
    v = verify(raw)
    sevs = [f["severity"] for f in v["verified"]]
    # critical first, then high (sorted by confidence desc), then medium, then low
    assert sevs == ["critical", "high", "high", "medium", "low"]
    # Among the two highs, conf 0.7 should come before conf 0.4
    highs = [f for f in v["verified"] if f["severity"] == "high"]
    assert highs[0]["confidence"] > highs[1]["confidence"]


def test_verify_empty_input_returns_new_schema():
    v = verify([])
    assert v["verified"] == []
    assert v["stats"]["high_critical_bypassed"] == 0
    assert v["stats"]["after_dedupe"] == 0
    # clusters shape must match the new dict shape, not list
    assert isinstance(v["clusters"], dict)
    assert v["clusters"]["l1"] == []


def test_read_context_symlink_escape_blocked(tmp_path):
    """A symlink inside project_root pointing OUTSIDE should be blocked."""
    # Create the project_root
    root = tmp_path / "project"
    root.mkdir()
    (root / "real.py").write_text("safe\ncontent\n")
    # Create a target file OUTSIDE project_root
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\ndata\n")
    # Symlink inside project_root pointing to the outside file
    try:
        (root / "escape.py").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported in this environment")
    # Sanity: reading the real file works
    ctx = _read_code_context(root, "real.py", 1, context=1)
    assert ctx is not None
    # The symlink should be blocked (resolved path escapes project_root)
    ctx = _read_code_context(root, "escape.py", 1, context=1)
    assert ctx is None
