"""真实打 api.osskb.org 的端到端 smoke(不进 CI)。
用法:PYTHONPATH=.:sdk/python python3 tests/manual/smoke_provenance.py <源码目录>
"""
import sys
from pathlib import Path

from engines.provenance.scanoss_provider import ScanossProvider
from engines.provenance.aggregator import build_report


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(f"[*] 扫描 {root} …")
    matches, eff, skipped = ScanossProvider().scan_project(root)
    rep = build_report(matches=matches, total_effective_lines=eff, skipped=skipped)
    print(f"[*] 有效行 {eff} / 复用行 {rep.reused_lines}")
    print(f"[*] 复用率 {rep.reuse_ratio:.1%} → {rep.verdict}")
    for p in rep.by_project:
        print(f"    - {p['project']} {p['version']}: {p['ratio']:.1%} ({p['file_count']} files)")
    print(f"[*] 跳过 {len(skipped)} 文件")


if __name__ == "__main__":
    main()
