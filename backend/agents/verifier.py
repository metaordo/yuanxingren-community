"""Verifier and Reporter — terminal nodes that consume worker outputs.

Three-layer dedupe (M3 upgrade):
  L1. Exact site cluster: (category, file, line // 5)
  L2. Same-CWE pattern merge: same (target, cwe) across different files
      → presented as one finding with all hit locations listed
  L3. LLM tie-breaker (optional, top severities only): pairs that survived
      L1+L2 but might still be duplicates get sent to the LLM in batches.

Layer 3 is gated behind `use_llm_dedupe=True` so cheap runs skip it.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _norm_finding(f: dict) -> dict:
    """Coerce a finding dict to the canonical shape used downstream."""
    sev = (f.get("severity") or "low").lower()
    if sev not in _SEVERITY_RANK:
        sev = "low"
    return {
        "title": str(f.get("title") or "(untitled)"),
        "severity": sev,
        "category": str(f.get("category") or "unknown"),
        "cwe": _norm_cwe(f.get("cwe")),
        "file": str(f.get("file") or ""),
        "line": f.get("line"),
        "line_end": f.get("line_end"),
        "evidence": str(f.get("evidence") or "")[:1000],
        "confidence": float(f.get("confidence") or 0.5),
        "rationale": str(f.get("rationale") or "")[:1000],
        "role": str(f.get("role") or "?"),
    }


def _norm_cwe(raw: Any) -> str | None:
    """Normalize CWE to 'CWE-NNN' string or None."""
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if not s:
        return None
    s = s.replace("CWE-", "").strip()
    if not s.isdigit():
        # tolerate "CWE-120, CWE-787" etc — take the first number
        m = re.search(r"\d+", s)
        if not m:
            return None
        s = m.group(0)
    return f"CWE-{s}"


def verify(raw_findings: list[dict], *, use_llm_dedupe: bool = False) -> dict:
    """Cluster findings across three layers; produce verified set.

    NEW BEHAVIOR (2026-05-31):
      - severity in {high, critical} bypasses L1/L2/L3; each finding is
        preserved with original evidence and goes through _annotate_corroboration
        only (cross-agent marking without merging).
      - severity in {medium, low, info} goes through L1 → L2 → L3 (optional)
        as before.
      - Final verified[] = annotated high/critical + L1/L2/L3 output (medium tail).

    Output:
      {
        "verified": list[dict],
        "clusters": {"l1": [...], "l2": [...], "l3_pairs": [...]},
        "stats": {"raw":N, "high_critical_bypassed":H, "after_l1":M1,
                  "after_l2":M2, "after_l3":M3,
                  "after_dedupe":(H+M3), "clusters":K},
      }

    NOTE: clusters["l1"] now only contains clustering decisions for medium/low/info
    findings. High/critical findings bypass L1 and are not represented in
    clusters["l1"]. Use stats["high_critical_bypassed"] to see the count of
    bypassed findings.
    """
    if not raw_findings:
        return {"verified": [],
                "clusters": {"l1": [], "l2": [], "l3_pairs": []},
                "stats": {"raw": 0, "high_critical_bypassed": 0,
                          "after_l1": 0, "after_l2": 0, "after_l3": 0,
                          "after_dedupe": 0, "clusters": 0}}

    norm = [_norm_finding(f) for f in raw_findings]

    # Split by severity: high/critical bypass L1/L2/L3
    high_crit = [f for f in norm
                 if _SEVERITY_RANK[f["severity"]] >= _SEVERITY_RANK["high"]]
    rest = [f for f in norm
            if _SEVERITY_RANK[f["severity"]] < _SEVERITY_RANK["high"]]

    # High/critical: annotate only, no merge
    high_crit_annotated = _annotate_corroboration(high_crit) if high_crit else []

    # Rest: original L1 → L2 → L3 pipeline
    # _cluster_l1([]) and _cluster_l2([]) both handle empty input correctly
    l1_clusters = _cluster_l1(rest)
    after_l1 = [c["representative"] for c in l1_clusters if c["kept"]]
    after_l2, l2_clusters = _cluster_l2(after_l1)

    after_l3 = after_l2
    l3_pairs: list[dict] = []
    if use_llm_dedupe and len(after_l2) > 1:
        try:
            after_l3, l3_pairs = _llm_dedupe(after_l2)
        except Exception as e:  # noqa: BLE001
            log.warning("L3 LLM dedupe failed: %s", e)

    # Merge: high/critical (annotated) + L1/L2/L3 output (medium/low/info tail)
    verified = high_crit_annotated + after_l3
    verified.sort(key=lambda f: (-_SEVERITY_RANK[f["severity"]],
                                 -f.get("confidence", 0)))

    return {
        "verified": verified,
        "clusters": {
            "l1": l1_clusters,
            "l2": l2_clusters,
            "l3_pairs": l3_pairs,
        },
        "stats": {
            "raw": len(norm),
            "high_critical_bypassed": len(high_crit),
            "after_l1": len(after_l1),
            "after_l2": len(after_l2),
            "after_l3": len(after_l3),
            "after_dedupe": len(verified),
            "clusters": len(l1_clusters),
        },
    }


# ---- corroboration annotation (used for high/critical bypass path) -------

def _annotate_corroboration(findings: list[dict]) -> list[dict]:
    """Annotate cross-agent corroboration at same (category, file, line//5) site.

    Expects already-normalized findings; the caller must `_norm_finding` first.

    Unlike _cluster_l1, this does NOT merge or drop findings — every input is
    preserved with its original evidence/rationale. Only adds:
      - corroborating_roles: sorted list of distinct roles at the same bucket
      - agent_count: len(corroborating_roles)
      - confidence: +0.15 boost if agent_count >= 2 (capped at 0.99)

    Used for high/critical findings that bypass L1/L2/L3 dedupe.
    """
    norm = findings
    bucket: dict[tuple, set[str]] = defaultdict(set)
    for f in norm:
        line_bucket = (f["line"] // 5) if isinstance(f["line"], int) else None
        key = (f["category"], f["file"], line_bucket)
        bucket[key].add(f["role"])

    out: list[dict] = []
    for f in norm:
        line_bucket = (f["line"] // 5) if isinstance(f["line"], int) else None
        key = (f["category"], f["file"], line_bucket)
        roles_at_site = sorted(bucket[key])
        f2 = dict(f)
        f2["corroborating_roles"] = roles_at_site
        f2["agent_count"] = len(roles_at_site)
        if len(roles_at_site) >= 2:
            f2["confidence"] = round(min(0.99, f2.get("confidence", 0.5) + 0.15), 2)
        out.append(f2)
    return out


# ---- L1: exact site cluster ----------------------------------------------

def _cluster_l1(norm: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for f in norm:
        line_bucket = (f["line"] // 5) if isinstance(f["line"], int) else None
        key = (f["category"], f["file"], line_bucket)
        groups[key].append(f)

    out = []
    for key, group in groups.items():
        roles_seen = sorted({g["role"] for g in group})
        rep = max(group, key=lambda g: (_SEVERITY_RANK[g["severity"]],
                                          g.get("confidence", 0)))
        rep = dict(rep)
        rep["corroborating_roles"] = roles_seen
        rep["agent_count"] = len(roles_seen)
        if len(roles_seen) >= 2:
            rep["confidence"] = round(min(0.99, rep.get("confidence", 0.5) + 0.15), 2)
        keep = (
            _SEVERITY_RANK[rep["severity"]] >= _SEVERITY_RANK["high"]
            or len(roles_seen) >= 2
            or rep.get("confidence", 0) >= 0.7
        )
        out.append({
            "key": list(key),
            "roles": roles_seen,
            "kept": keep,
            "size": len(group),
            "representative": rep,
        })
    return out


# ---- L2: same-CWE pattern merge across files -----------------------------

def _cluster_l2(after_l1: list[dict]) -> tuple[list[dict], list[dict]]:
    """Merge same-CWE findings across different files into one pattern."""
    if not after_l1:
        return [], []
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    no_cwe: list[dict] = []
    for f in after_l1:
        cwe = f.get("cwe")
        if cwe:
            by_cwe[cwe].append(f)
        else:
            no_cwe.append(f)

    merged: list[dict] = []
    diagnostics: list[dict] = []

    for cwe, group in by_cwe.items():
        if len(group) <= 1:
            merged.extend(group)
            continue
        # 2+ findings sharing the same CWE → merge into one "pattern" finding
        rep = max(group, key=lambda g: (_SEVERITY_RANK[g["severity"]],
                                          g.get("confidence", 0)))
        rep = dict(rep)
        locations = []
        all_roles = set()
        for g in group:
            loc = g.get("file", "")
            if isinstance(g.get("line"), int):
                loc += f":{g['line']}"
            locations.append(loc)
            all_roles.update(g.get("corroborating_roles") or [g.get("role")])
        rep["locations"] = locations
        rep["pattern_hits"] = len(group)
        rep["title"] = f"{rep['title']} (×{len(group)} sites)"
        rep["corroborating_roles"] = sorted(all_roles)
        rep["agent_count"] = len(all_roles)
        # boost confidence slightly — same CWE across multiple locations
        rep["confidence"] = min(0.99, rep.get("confidence", 0.5) + 0.05)
        merged.append(rep)
        diagnostics.append({
            "cwe": cwe,
            "merged_count": len(group),
            "locations": locations,
        })

    merged.extend(no_cwe)
    return merged, diagnostics


# ---- L3: LLM tie-breaker -------------------------------------------------

_L3_SYSTEM = """\
You compare pairs of security findings and decide if they describe the
same underlying vulnerability. Be conservative — say "different" unless
the evidence is clearly about the same code site or pattern.

For each pair output exactly one of: "same" or "different".
Output a JSON array of {"a":int, "b":int, "verdict":"same"|"different"}.
Output ONLY the JSON. No prose, no fences.
"""


def _llm_dedupe(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """LLM-mediated final dedupe. Only runs on top-severity items to save cost.

    Strategy: pick at most top 10 findings by severity+confidence, generate
    all pairwise comparisons (≤ 45 pairs), send in one batch.
    """
    if len(findings) <= 1:
        return findings, []

    # Only LLM-judge the high+ items (cost control)
    ranked = sorted(findings,
                      key=lambda f: (-_SEVERITY_RANK[f["severity"]],
                                       -f.get("confidence", 0)))
    top = [f for f in ranked
            if _SEVERITY_RANK[f["severity"]] >= _SEVERITY_RANK["high"]][:10]
    if len(top) <= 1:
        return findings, []

    pairs = []
    for i in range(len(top)):
        for j in range(i + 1, len(top)):
            pairs.append((i, j))
    if not pairs:
        return findings, []

    # Build the LLM prompt
    desc = []
    for idx, f in enumerate(top):
        loc = f.get("file", "")
        if isinstance(f.get("line"), int):
            loc += f":{f['line']}"
        desc.append({
            "id": idx,
            "title": f.get("title"),
            "category": f.get("category"),
            "cwe": f.get("cwe"),
            "location": loc,
            "evidence": (f.get("evidence") or "")[:200],
        })

    from ..llm import Message
    from ..llm.router import call as llm_call
    user = (
        f"Findings:\n{json.dumps(desc, ensure_ascii=False, indent=2)}\n\n"
        f"Pairs to judge: {pairs}\n\nRespond with the JSON array only."
    )
    res = llm_call("triage",
                    [Message(role="system", content=_L3_SYSTEM),
                     Message(role="user", content=user)],
                    max_tokens=1024)
    text = (res.text or "").strip()
    verdicts = _parse_json_array(text)

    # Union-find on "same" verdicts
    parent = list(range(len(top)))
    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for v in verdicts:
        if isinstance(v, dict) and v.get("verdict") == "same":
            try:
                a = int(v["a"]); b = int(v["b"])
                if 0 <= a < len(top) and 0 <= b < len(top):
                    union(a, b)
            except (KeyError, TypeError, ValueError):
                continue

    # Build the deduped top set
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(top)):
        groups[find(i)].append(i)

    keep_top: list[dict] = []
    merge_log: list[dict] = []
    keep_indices = set()
    for root, members in groups.items():
        if len(members) > 1:
            rep = max((top[i] for i in members),
                       key=lambda f: (_SEVERITY_RANK[f["severity"]],
                                        f.get("confidence", 0)))
            rep = dict(rep)
            all_roles = set(rep.get("corroborating_roles") or [rep.get("role")])
            for i in members:
                all_roles.update(top[i].get("corroborating_roles")
                                  or [top[i].get("role")])
            rep["corroborating_roles"] = sorted(all_roles)
            rep["agent_count"] = len(all_roles)
            merge_log.append({"merged_indices": members,
                               "kept_title": rep["title"]})
            keep_top.append(rep)
        else:
            keep_top.append(top[members[0]])
        for i in members:
            keep_indices.add(i)

    # Untouched (non-top) findings come through unchanged
    untouched = [f for f in findings if f not in top]
    return keep_top + untouched, merge_log


def _read_code_context(
    project_root: Path,
    file_path: str,
    line: int | None,
    *,
    context: int = 10,
) -> str | None:
    """Read ±context lines around `line` from project_root/file_path.

    Path traversal防护: resolved path must be inside project_root.
    Returns None on any failure (missing file, invalid line, IO error,
    path escape).

    Format: "  39| code\n>>> 40| target line\n  41| code"
    """
    if not isinstance(line, int) or line < 1:
        return None
    try:
        root_resolved = project_root.resolve()
        target = (project_root / file_path).resolve()
        if not target.is_relative_to(root_resolved):
            return None
        if not target.is_file():
            return None
        text = target.read_text(errors="replace")
    except (OSError, ValueError):
        return None
    lines = text.splitlines()
    if line > len(lines):
        return None
    start = max(1, line - context)
    end = min(len(lines), line + context)
    out: list[str] = []
    for i in range(start, end + 1):
        prefix = ">>> " if i == line else "    "
        out.append(f"{prefix}{i:4d}| {lines[i - 1]}")
    return "\n".join(out)


_BRACE_EXTS = {
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".rs", ".go", ".java", ".js", ".jsx", ".ts", ".tsx",
}


def _read_function_context(
    file_path: str,
    line: int,
    project_root: str,
    max_function_lines: int = 200,
    fallback_window: int = 50,
) -> str:
    """Read enclosing function's source with cat -n style line numbers.

    Falls back to ±fallback_window if function not detected or too big.
    Returns "" on path-safety failure or empty/out-of-range file.
    """
    import ast
    import os

    # 1. Path safety
    try:
        root_real = os.path.realpath(str(project_root))
        target_real = os.path.realpath(os.path.join(str(project_root), file_path))
        if os.path.commonpath([root_real, target_real]) != root_real:
            return ""
    except (ValueError, OSError):
        return ""

    if not os.path.isfile(target_real):
        return ""

    try:
        raw = open(target_real, errors="replace").read()
    except OSError:
        return ""

    all_lines = raw.splitlines()
    if not all_lines or line < 1 or line > len(all_lines):
        return ""

    ext = os.path.splitext(file_path)[1].lower()

    func_start: int | None = None
    func_end: int | None = None

    # 2. Python: AST parse
    if ext == ".py":
        try:
            tree = ast.parse(raw)
        except SyntaxError:
            tree = None
        if tree is not None:
            best: ast.AST | None = None
            best_size = 10**9
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                         ast.ClassDef)):
                    continue
                s = node.lineno
                e = getattr(node, "end_lineno", None)
                if e is None:
                    continue
                if s <= line <= e:
                    size = e - s + 1
                    if size < best_size:
                        best_size = size
                        best = node
            if best is not None:
                func_start = best.lineno
                func_end = getattr(best, "end_lineno")

    # 3. Brace-matching languages
    elif ext in _BRACE_EXTS:
        # Scan upward from `line` to find the opening brace of the enclosing function
        open_brace_lineno: int | None = None
        depth = 0
        in_line_comment = False
        in_block_comment = False

        # Walk upward to find an unmatched {
        for ln in range(line - 1, -1, -1):  # 0-indexed
            src = all_lines[ln]
            # Scan the line right-to-left to count braces (simplified)
            i = len(src) - 1
            while i >= 0:
                ch = src[i]
                # Skip line comments (can't detect from right easily; skip whole line)
                if src[:i + 1].rstrip().endswith("//"):
                    break
                if ch == '}':
                    depth += 1
                elif ch == '{':
                    if depth == 0:
                        open_brace_lineno = ln  # 0-indexed
                        break
                    depth -= 1
                i -= 1
            if open_brace_lineno is not None:
                break

        if open_brace_lineno is not None:
            # Walk back to find declaration start (non-blank line before the brace)
            decl_start = open_brace_lineno
            for ln in range(open_brace_lineno - 1, max(-1, open_brace_lineno - 10), -1):
                stripped = all_lines[ln].strip()
                if stripped and not stripped.startswith("//") and not stripped.startswith("*"):
                    decl_start = ln
                else:
                    break

            # Walk forward from open_brace to find matching close brace
            depth2 = 0
            close_lineno: int | None = None
            in_block = False
            for ln in range(open_brace_lineno, len(all_lines)):
                src = all_lines[ln]
                i2 = 0
                while i2 < len(src):
                    ch = src[i2]
                    # Block comment start
                    if not in_block and src[i2:i2+2] == "/*":
                        in_block = True
                        i2 += 2
                        continue
                    if in_block:
                        if src[i2:i2+2] == "*/":
                            in_block = False
                            i2 += 2
                        else:
                            i2 += 1
                        continue
                    # Line comment
                    if src[i2:i2+2] == "//":
                        break
                    if ch == '{':
                        depth2 += 1
                    elif ch == '}':
                        depth2 -= 1
                        if depth2 == 0:
                            close_lineno = ln
                            break
                    i2 += 1
                if close_lineno is not None:
                    break

            if close_lineno is not None:
                func_start = decl_start + 1   # convert to 1-indexed
                func_end = close_lineno + 1    # convert to 1-indexed

    # 4. Fallback: use ±fallback_window
    def _fallback() -> str:
        s = max(1, line - fallback_window)
        e = min(len(all_lines), line + fallback_window)
        return _format_lines(all_lines, s, e)

    if func_start is None or func_end is None:
        return _fallback()

    # Too big → fallback
    if func_end - func_start + 1 > max_function_lines:
        return _fallback()

    # 5. Empty file / line out of range already handled above
    s = max(1, func_start)
    e = min(len(all_lines), func_end)
    return _format_lines(all_lines, s, e)


def _format_lines(all_lines: list[str], start: int, end: int) -> str:
    """Format lines[start-1:end] with cat -n style numbering."""
    out: list[str] = []
    for i in range(start, end + 1):
        out.append(f"{i:5d} | {all_lines[i - 1]}")
    return "\n".join(out)


def _parse_json_array(text: str) -> list:
    if not text:
        return []
    fence = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("[")
    if start == -1:
        return []
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return []
    return []


# ---- Reporter ------------------------------------------------------------

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
EXP_RANK = {"high": 3, "medium": 2, "low": 1, "unknown": 0}


def _sort_findings(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda f: (
        SEV_RANK.get(f.get("severity", "info"), 0),
        int(f.get("review_confidence", 0) or 0),
        EXP_RANK.get(f.get("review_exploitability", "unknown"), 0),
    ), reverse=True)


def render_report(*, target: Any, user_prompt: str,
                  picked_roles: list[str],
                  agent_runs: list[dict],
                  verified: list[dict],
                  stats: dict,
                  dismissed: list[dict] | None = None,
                  unknown_reports: list[dict] | None = None) -> str:
    """Render the final markdown report."""
    dismissed = dismissed or []
    reviewer = (stats or {}).get("reviewer") or {}
    rev_status = reviewer.get("status", "skipped")

    lines: list[str] = []
    target_label = getattr(target, "id", "unknown")
    lines.append(f"# Multi-Agent Audit Report — Target #{target_label}")
    lines.append("")
    lines.append(f"**用户目标**:{user_prompt[:300]}")
    lines.append("")
    lines.append(f"**派出 agent**:{', '.join(picked_roles) if picked_roles else '(none)'}")

    # Stats block — tree layout makes the high-crit-bypass + dedupe-then-merge
    # paths legible (a one-liner hides that 73 high-crit + 21 deduped = 94
    # going into reviewer).
    raw = int(stats.get("raw", 0))
    bypass_h = int(stats.get("high_critical_bypassed", 0))
    after_l1 = int(stats.get("after_l1", 0))
    after_l2 = int(stats.get("after_l2", 0))
    others_raw = max(raw - bypass_h, 0)
    pre_review = bypass_h + after_l2  # 进入 L4 (或最终,若无 reviewer) 的总量
    reviewed = int(reviewer.get("reviewed", 0))
    kept_count = len(verified)
    dism_count = len(dismissed)
    passthrough = max(pre_review - reviewed, 0)  # low/info 直通

    lines.append("**统计**:")
    lines.append(f"- 原始发现:**{raw}** 条 = 高危 {bypass_h} + 其他 {others_raw}")
    if bypass_h:
        lines.append(f"  - 🔴 高危旁路(直接送复查):**{bypass_h}** 条")
    if others_raw:
        lines.append(
            f"  - 🟡 其他规则去重:{others_raw} → L1 {after_l1} → L2 **{after_l2}** 条"
        )
    if rev_status == "ok":
        lines.append(
            f"- 进入复查总量:**{pre_review}** 条 "
            f"(高危 {bypass_h} + 去重后其他 {after_l2})"
        )
        lines.append(
            f"  - 🔍 L4 LLM 复查 medium+:**{reviewed}** 条 → "
            f"保留 {reviewed - dism_count} + 驳回 {dism_count}"
        )
        if passthrough:
            lines.append(f"  - low/info 直通:{passthrough} 条")
        # New: avg confidence + second-pass metrics
        if reviewed > 0:
            avg_conf = reviewer.get("avg_confidence")
            low_conf = reviewer.get("low_confidence_count", 0)
            second_pass = reviewer.get("second_pass_count", 0)
            second_changed = reviewer.get("second_pass_changed_count", 0)
            if avg_conf is not None:
                lines.append(
                    f"  - 平均置信度:{avg_conf}/100,"
                    f"低置信度(<60):{low_conf} 条,"
                    f"二次复核:{second_pass} 条 → 改判:{second_changed} 条"
                )
        lines.append(
            f"- ✅ **最终**:{kept_count} 条"
            + (f" + {dism_count} 条被 verifier-reviewer 驳回" if dism_count else "")
        )
    elif rev_status == "failed":
        lines.append(
            f"- ⚠️ **最终**:{kept_count} 条(verifier-reviewer 不可用,未做复查)"
        )
    else:
        lines.append(f"- **最终**:{kept_count} 条")
    lines.append("")

    lines.append("## Agent 执行摘要")
    if agent_runs:
        lines.append("| Role | 状态 | 发现数 | 耗时 | tokens | 成本 |")
        lines.append("|---|---|---|---|---|---|")
        _total_cost = 0.0
        for r in agent_runs:
            tk = f"{r.get('tokens_in',0)}/{r.get('tokens_out',0)}"
            c = r.get("cost_cny", 0) or 0
            _total_cost += c
            cost_str = f"¥{c:.4f}" if c > 0 else "—"
            lines.append(f"| {r.get('role','?')} | {r.get('status','?')} | "
                          f"{len(r.get('findings') or [])} | "
                          f"{r.get('latency_ms',0)}ms | {tk} | {cost_str} |")
        if _total_cost > 0:
            lines.append(f"| **合计** | | | | | **¥{_total_cost:.4f}** |")
    else:
        lines.append("(无 agent 运行)")
    lines.append("")

    lines.append("## 已确认漏洞")
    sorted_verified = _sort_findings(verified)
    if not sorted_verified:
        lines.append("_未发现已确认的漏洞。_")
    else:
        for i, f in enumerate(sorted_verified, 1):
            sev = f.get("severity", "?").upper()
            roles = ", ".join(f.get("corroborating_roles")
                                or [f.get("role", "?")])
            cwe = f.get("cwe") or ""  # already normalized to "CWE-NNN"
            location = ""
            if f.get("locations"):
                location = ", ".join(f["locations"][:8])
                if len(f["locations"]) > 8:
                    location += f"… (+{len(f['locations'])-8} more)"
            else:
                location = f.get("file", "?")
                if isinstance(f.get("line"), int):
                    location += f":{f['line']}"
                    if isinstance(f.get("line_end"), int) and f["line_end"] != f["line"]:
                        location += f"-{f['line_end']}"
            lines.append(f"### {i}. [{sev}] {f.get('title','(untitled)')} {cwe}")
            lines.append(f"- **位置**:`{location}`")
            lines.append(f"- **类别**:{f.get('category','?')}")
            conf_suffix = ""
            if f.get("review_verdict") == "lower":
                conf_suffix = " (verifier-reviewer 降低)"
            lines.append(f"- **置信度**:{f.get('confidence', 0):.2f}{conf_suffix}")
            lines.append(f"- **协同确认**:{roles} ({f.get('agent_count',1)} agent)")
            # New: reviewer confidence + exploitability + second-pass tag
            rev_conf = f.get("review_confidence")
            rev_exp = f.get("review_exploitability")
            second_pass_tag = " 🔁 二次复核" if f.get("review_pass") == 2 else ""
            if rev_conf is not None or rev_exp is not None:
                conf_str = f"置信度 {rev_conf}/100" if rev_conf is not None else ""
                exp_str = f"可利用性: {rev_exp}" if rev_exp is not None else ""
                meta_parts = [p for p in [conf_str, exp_str] if p]
                meta_line = " | ".join(meta_parts) + second_pass_tag
                lines.append(f"- **复查元数据**:{meta_line}")
            elif second_pass_tag:
                lines.append(f"- **复查元数据**:{second_pass_tag.strip()}")
            if f.get("evidence"):
                lines.append(f"- **证据**:`{f['evidence'][:300]}`")
            if f.get("rationale"):
                lines.append(f"- **分析**:{f['rationale'][:500]}")
            if f.get("review_verdict"):
                rv = f["review_verdict"]
                rn = f.get("review_note") or ""
                lines.append(f"- **🔍 复查意见**:{rv} — {rn}")
            lines.append("")

    # ---- Dismissed section (verifier-reviewer rejects) ----
    sorted_dismissed = _sort_findings(dismissed)
    if sorted_dismissed:
        lines.append(f"## 🚫 verifier-reviewer 驳回 ({len(sorted_dismissed)} 条)")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>展开查看驳回详情</summary>")
        lines.append("")
        lines.append("| # | 标题 | 位置 | 严重度 | 驳回理由 |")
        lines.append("|---|---|---|---|---|")
        for i, d in enumerate(sorted_dismissed, 1):
            loc = d.get("file", "?")
            if isinstance(d.get("line"), int):
                loc += f":{d['line']}"
            loc = loc.replace("|", "\\|")
            reason = (d.get("review_reason") or "")[:200].replace("|", "\\|")
            title = (d.get("title") or "(untitled)").replace("|", "\\|")
            lines.append(f"| {i} | {title} | `{loc}` | "
                         f"{d.get('severity','?')} | {reason} |")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # ---- 0-day pipeline section (M4) ----
    if unknown_reports:
        lines.append("## 0-Day 候选(深度挖掘 + PoC + 沙箱)")
        lines.append("")
        for r in unknown_reports:
            idx = r.get("finding_idx", -1)
            nov = r.get("novelty") or {}
            nov_val = float(nov.get("value", 0))
            tag = "🔴 高新颖度" if nov_val >= 0.7 else "🟡 中度" if nov_val >= 0.4 else "🟢 已知模式"
            ref_finding = verified[idx] if 0 <= idx < len(verified) else None
            label = (ref_finding or {}).get("title", "(unknown)") if ref_finding else "(unknown)"
            lines.append(f"### {tag} · finding #{idx + 1}: {label}")
            lines.append(f"- **novelty score**: {nov_val:.2f}")
            lines.append(f"- **rationale**: {nov.get('rationale', '')[:300]}")
            if r.get("poc_source"):
                lines.append(f"- **PoC**(`{r.get('poc_language', 'python')}`):")
                lines.append("```" + str(r.get("poc_language") or "python"))
                lines.append((r["poc_source"] or "")[:2000])
                lines.append("```")
            if r.get("sandbox_triggered") is not None:
                triggered = r["sandbox_triggered"]
                rc = r.get("sandbox_exit_code", "?")
                lines.append(
                    f"- **沙箱执行**: {'✓ triggered' if triggered else '✗ not triggered'} "
                    f"(exit={rc})"
                )
                if r.get("sandbox_stderr"):
                    lines.append(f"  - stderr: `{(r['sandbox_stderr'] or '')[:200]}`")
            if r.get("disclosure_body"):
                lines.append("- **披露草稿**(摘要):")
                lines.append("```")
                lines.append((r["disclosure_body"] or "")[:600])
                lines.append("```")
                if r.get("disclosure_embargo_until"):
                    lines.append(f"  - 禁运期至 {r['disclosure_embargo_until']}")
            lines.append("")

    return "\n".join(lines)
