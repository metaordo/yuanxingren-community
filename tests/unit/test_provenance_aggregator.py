from engines.provenance.aggregator import classify_verdict, build_report, is_generated_file
from engines.provenance.models import ProvenanceMatch


def test_classify_verdict_five_buckets():
    assert classify_verdict(0.05) == "高度自研"
    assert classify_verdict(0.20) == "以自研为主"
    assert classify_verdict(0.45) == "混合"
    assert classify_verdict(0.70) == "以复用为主"
    assert classify_verdict(0.90) == "高度复用"


def test_classify_verdict_boundaries_inclusive_lower():
    # 边界归上档:0.10→以自研为主, 0.30→混合, 0.60→以复用为主, 0.85→高度复用
    assert classify_verdict(0.10) == "以自研为主"
    assert classify_verdict(0.30) == "混合"
    assert classify_verdict(0.60) == "以复用为主"
    assert classify_verdict(0.85) == "高度复用"


def test_is_generated_file():
    assert is_generated_file("a/package-lock.json")
    assert is_generated_file("dist/app.min.js")
    assert is_generated_file("api/foo.pb.go")
    assert is_generated_file("proto/foo_pb2.py")
    assert not is_generated_file("src/tcp.c")


def test_build_report_line_based_ratio():
    # 项目有效行 1000;匹配 300 行 → 复用率 0.30 → 混合
    matches = [
        ProvenanceMatch(your_file="src/tcp.c", lines="1-200", match_type="snippet",
                        matched_lines=200, source_project="lwip", source_version="2.1.3",
                        source_file="core/tcp.c", similarity=95, license="BSD-3-Clause"),
        ProvenanceMatch(your_file="src/util.c", lines="1-100", match_type="snippet",
                        matched_lines=100, source_project="lwip", source_version="2.1.3",
                        source_file="core/util.c", similarity=88),
    ]
    rep = build_report(matches=matches, total_effective_lines=1000, skipped=[])
    assert rep.reused_lines == 300
    assert abs(rep.reuse_ratio - 0.30) < 1e-6
    assert abs(rep.self_ratio - 0.70) < 1e-6
    assert rep.verdict == "混合"
    # by_project 聚合:lwip 占 300/1000 = 0.30,2 个文件
    assert len(rep.by_project) == 1
    assert rep.by_project[0]["project"] == "lwip"
    assert rep.by_project[0]["file_count"] == 2
    assert abs(rep.by_project[0]["ratio"] - 0.30) < 1e-6


def test_build_report_empty_matches_zero_reuse():
    rep = build_report(matches=[], total_effective_lines=500, skipped=[])
    assert rep.reuse_ratio == 0.0
    assert rep.self_ratio == 1.0
    assert rep.verdict == "高度自研"


def test_build_report_zero_effective_lines_safe():
    # 空项目不能除零
    rep = build_report(matches=[], total_effective_lines=0, skipped=[])
    assert rep.reuse_ratio == 0.0
    assert rep.verdict == "高度自研"
