"""Tests for render_report dismissed section + review_note rendering."""
from backend.agents.verifier import render_report


class _Tgt:
    id = 42


def _verified(extras=None):
    return [{
        "title": "SQL Injection",
        "severity": "high",
        "category": "injection",
        "cwe": "CWE-89",
        "file": "auth/login.py",
        "line": 42,
        "evidence": "SELECT * FROM u WHERE id=" + "x" * 50,
        "rationale": "Concatenated user input into SQL",
        "confidence": 0.85,
        "corroborating_roles": ["sqli-analyst"],
        "agent_count": 1,
        "role": "sqli-analyst",
        **(extras or {}),
    }]


def _base_args():
    return dict(
        target=_Tgt(), user_prompt="audit me", picked_roles=["sqli-analyst"],
        agent_runs=[], unknown_reports=None,
    )


def test_dismissed_section_rendered_when_nonempty():
    dismissed = [{
        "title": "XSS in tpl", "severity": "medium", "file": "tpl.html",
        "line": 88, "review_reason": "Django auto-escape applies",
    }]
    stats = {"raw": 5, "after_l1": 4, "after_l2": 4, "after_dedupe": 2,
             "high_critical_bypassed": 1,
             "reviewer": {"status": "ok", "reviewed": 2, "kept": 1,
                          "lowered": 0, "dismissed": 1}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=dismissed, stats=stats)
    assert "🚫" in md
    assert "verifier-reviewer 驳回" in md
    assert "<details>" in md
    assert "Django auto-escape" in md
    assert "XSS in tpl" in md


def test_dismissed_section_omitted_when_empty():
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 1,
                          "lowered": 0, "dismissed": 0}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=[], stats=stats)
    assert "🚫" not in md
    assert "verifier-reviewer 驳回" not in md


def test_review_note_inline_for_keep():
    v = _verified(extras={"review_verdict": "keep",
                          "review_note": "evidence strong"})
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 1,
                          "lowered": 0, "dismissed": 0}}
    md = render_report(**_base_args(), verified=v, dismissed=[], stats=stats)
    assert "🔍" in md
    assert "复查意见" in md
    assert "evidence strong" in md


def test_review_note_inline_for_lower():
    v = _verified(extras={"review_verdict": "lower",
                          "review_note": "weak signal",
                          "confidence": 0.55})
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 0,
                          "lowered": 1, "dismissed": 0}}
    md = render_report(**_base_args(), verified=v, dismissed=[], stats=stats)
    assert "🔍" in md
    assert "weak signal" in md
    assert "verifier-reviewer 降低" in md


def test_stats_line_shows_high_critical_bypass():
    stats = {"raw": 10, "after_l1": 5, "after_l2": 4, "after_dedupe": 6,
             "high_critical_bypassed": 2,
             "reviewer": {"status": "ok", "reviewed": 6, "kept": 5,
                          "lowered": 0, "dismissed": 1}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=[], stats=stats)
    assert "高危旁路" in md
    assert "2" in md


def test_stats_line_shows_reviewer_failed():
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "failed", "error": "API 502"}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=[], stats=stats)
    assert "未做复查" in md


def test_stats_line_shows_reviewer_skipped():
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "skipped", "reason": "env_disabled"}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=[], stats=stats)
    # skipped 不应出现"未做复查"(那是 failed 的表述)
    assert "未做复查" not in md


def test_review_note_not_shown_when_absent():
    """review_verdict 不存在 → 不渲染 🔍 行。"""
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "skipped"}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=[], stats=stats)
    assert "🔍" not in md
    assert "复查意见" not in md


def test_stats_line_no_broken_bold_nesting():
    """The stats line must not nest **bold** markers (broken markdown)."""
    stats = {"raw": 5, "after_l1": 4, "after_l2": 4, "after_dedupe": 2,
             "high_critical_bypassed": 1,
             "reviewer": {"status": "ok", "reviewed": 2, "kept": 1,
                          "lowered": 0, "dismissed": 1}}
    md = render_report(**_base_args(), verified=_verified(),
                       dismissed=[], stats=stats)
    # Find the stats line (contains '最终')
    stats_line = next(l for l in md.split("\n") if "最终" in l)
    # Count **; should be even and not produce nested-bold pattern
    # If outer wraps + inner **最终** both present, we'd see odd count or broken pattern.
    # Simpler check: line should NOT start with ** AND have ** inside
    assert not (stats_line.startswith("**") and stats_line.count("**") > 2 and stats_line.endswith("**"))


def test_dismissed_table_escapes_pipe_in_filename():
    """Filenames containing | must not break the dismissed table layout."""
    dismissed = [{
        "title": "evil", "severity": "low", "file": "a|b.py", "line": 1,
        "review_reason": "x",
    }]
    stats = {"raw": 1, "after_dedupe": 0,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 0,
                          "lowered": 0, "dismissed": 1}}
    md = render_report(**_base_args(), verified=[],
                       dismissed=dismissed, stats=stats)
    # The | in filename should be escaped (\|) in the table cell
    assert r"a\|b.py" in md or "a\\|b.py" in md  # tolerate raw-string vs escape


# =====================================================================
# Precision-upgrade tests: sorting + new metadata columns + new stats
# =====================================================================

def _finding(severity, conf=50, exp="unknown", title="t", **extra):
    return {
        "title": title, "severity": severity, "category": "x",
        "cwe": "CWE-1", "file": "a.py", "line": 1, "evidence": "ev",
        "confidence": 0.5, "rationale": "r",
        "corroborating_roles": ["x"], "agent_count": 1,
        "review_verdict": "keep", "review_confidence": conf,
        "review_exploitability": exp, "review_note": "ok",
        **extra,
    }


def test_findings_sorted_by_severity_then_confidence():
    """Sort: severity DESC, then review_confidence DESC, then exploitability DESC."""
    verified = [
        _finding("medium", conf=99, title="medium-99"),
        _finding("critical", conf=50, title="crit-50"),
        _finding("high", conf=85, title="high-85"),
        _finding("high", conf=95, title="high-95"),
        _finding("low", conf=99, title="low-99"),
    ]
    stats = {"raw": 5, "after_dedupe": 5,
             "reviewer": {"status": "ok", "reviewed": 5, "kept": 5,
                          "lowered": 0, "dismissed": 0,
                          "avg_confidence": 86, "low_confidence_count": 1}}
    md = render_report(**_base_args(), verified=verified,
                       dismissed=[], stats=stats)
    # Extract order of titles
    titles_order = []
    for line in md.split("\n"):
        for t in ["crit-50", "high-95", "high-85", "medium-99", "low-99"]:
            if t in line and t not in titles_order:
                titles_order.append(t)
                break
    assert titles_order == ["crit-50", "high-95", "high-85", "medium-99", "low-99"]


def test_dismissed_findings_also_sorted():
    dismissed = [
        {"title": "low-dismiss", "severity": "low", "file": "a", "line": 1,
         "review_reason": "x", "review_confidence": 90},
        {"title": "crit-dismiss", "severity": "critical", "file": "b", "line": 1,
         "review_reason": "y", "review_confidence": 70},
        {"title": "high-dismiss", "severity": "high", "file": "c", "line": 1,
         "review_reason": "z", "review_confidence": 80},
    ]
    stats = {"raw": 3, "after_dedupe": 0,
             "reviewer": {"status": "ok", "reviewed": 3, "kept": 0,
                          "lowered": 0, "dismissed": 3}}
    md = render_report(**_base_args(), verified=[],
                       dismissed=dismissed, stats=stats)
    # In the dismissed table, critical should appear first
    crit_pos = md.find("crit-dismiss")
    high_pos = md.find("high-dismiss")
    low_pos = md.find("low-dismiss")
    assert crit_pos < high_pos < low_pos


def test_inline_metadata_shows_confidence_and_exploitability():
    verified = [_finding("high", conf=72, exp="medium", title="my-finding")]
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 1,
                          "lowered": 0, "dismissed": 0,
                          "avg_confidence": 72, "low_confidence_count": 0}}
    md = render_report(**_base_args(), verified=verified,
                       dismissed=[], stats=stats)
    assert "72" in md  # confidence shown
    # exploitability label present somewhere
    assert "medium" in md.lower()


def test_inline_metadata_shows_second_pass_tag():
    verified = [_finding("high", conf=80, title="reviewed-twice",
                         review_pass=2)]
    stats = {"raw": 1, "after_dedupe": 1,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 1,
                          "lowered": 0, "dismissed": 0,
                          "avg_confidence": 80, "low_confidence_count": 0,
                          "second_pass_count": 1, "second_pass_changed_count": 0}}
    md = render_report(**_base_args(), verified=verified,
                       dismissed=[], stats=stats)
    assert "🔁" in md or "二次复核" in md


def test_stats_block_includes_avg_confidence_line():
    verified = [_finding("high", conf=82)]
    stats = {"raw": 1, "high_critical_bypassed": 1,
             "after_l1": 0, "after_l2": 0, "after_dedupe": 1,
             "reviewer": {"status": "ok", "reviewed": 1, "kept": 1,
                          "lowered": 0, "dismissed": 0,
                          "avg_confidence": 82, "low_confidence_count": 0,
                          "second_pass_count": 0,
                          "second_pass_changed_count": 0}}
    md = render_report(**_base_args(), verified=verified,
                       dismissed=[], stats=stats)
    assert "82" in md
    assert "平均置信度" in md or "average confidence" in md.lower()
