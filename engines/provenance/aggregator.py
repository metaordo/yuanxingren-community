"""match 列表 → 五档量化报告。纯计算,无 IO、无网络。"""
from __future__ import annotations

import os

from .models import ProvenanceMatch, ComplianceReport

# 五档分界(env 可配)
_B1 = float(os.environ.get("PA_REUSE_B1", "0.10"))
_B2 = float(os.environ.get("PA_REUSE_B2", "0.30"))
_B3 = float(os.environ.get("PA_REUSE_B3", "0.60"))
_B4 = float(os.environ.get("PA_REUSE_B4", "0.85"))

_GENERATED_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                    "composer.lock", "Cargo.lock", "go.sum"}
_GENERATED_SUFFIXES = (".min.js", ".min.css", ".pb.go", "_pb2.py",
                       ".pb.cc", ".pb.h", ".g.dart")


def is_generated_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in _GENERATED_NAMES:
        return True
    return any(path.endswith(sfx) for sfx in _GENERATED_SUFFIXES)


def classify_verdict(reuse_ratio: float) -> str:
    if reuse_ratio < _B1:
        return "高度自研"
    if reuse_ratio < _B2:
        return "以自研为主"
    if reuse_ratio < _B3:
        return "混合"
    if reuse_ratio < _B4:
        return "以复用为主"
    return "高度复用"


def build_report(*, matches: list[ProvenanceMatch],
                 total_effective_lines: int,
                 skipped: list[str]) -> ComplianceReport:
    reused_lines = sum(m.matched_lines for m in matches)
    if total_effective_lines > 0:
        reuse_ratio = min(1.0, reused_lines / total_effective_lines)
    else:
        reuse_ratio = 0.0
    self_ratio = 1.0 - reuse_ratio

    # 按 source_project 聚合
    agg: dict[str, dict] = {}
    for m in matches:
        bucket = agg.setdefault(m.source_project, {
            "project": m.source_project, "version": m.source_version,
            "lines": 0, "files": set()})
        bucket["lines"] += m.matched_lines
        bucket["files"].add(m.your_file)
        if not bucket["version"] and m.source_version:
            bucket["version"] = m.source_version
    by_project = [
        {"project": b["project"], "version": b["version"],
         "ratio": min(1.0, b["lines"] / total_effective_lines) if total_effective_lines else 0.0,
         "file_count": len(b["files"])}
        for b in sorted(agg.values(), key=lambda x: x["lines"], reverse=True)
    ]

    return ComplianceReport(
        reuse_ratio=reuse_ratio, self_ratio=self_ratio,
        verdict=classify_verdict(reuse_ratio),
        total_effective_lines=total_effective_lines,
        reused_lines=reused_lines,
        by_project=by_project, matches=matches, skipped=skipped)
