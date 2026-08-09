from pathlib import Path
from unittest.mock import patch

import pytest

from engines.provenance.provider import ProvenanceError
from engines.provenance.scanoss_provider import ScanossProvider, _parse_scan_result


def test_parse_scan_result_snippet_and_file():
    raw = {
        "src/tcp.c": [{
            "id": "snippet", "lines": "40-92", "oss_lines": "10-62",
            "matched": "95%", "purl": ["pkg:github/lwip/lwip"],
            "vendor": "lwip", "component": "lwip", "version": "2.1.3",
            "file": "core/tcp.c", "licenses": [{"name": "BSD-3-Clause"}],
        }],
        "src/full.c": [{
            "id": "file", "lines": "1-200", "matched": "100%",
            "purl": ["pkg:github/openssl/openssl"], "component": "openssl",
            "version": "3.0.2", "file": "crypto/aes.c", "licenses": [],
        }],
        "src/orig.c": [{"id": "none"}],   # 无匹配,跳过
    }
    matches = _parse_scan_result(raw, {"src/full.c": 200, "src/tcp.c": 53})
    assert len(matches) == 2
    snip = next(m for m in matches if m.your_file == "src/tcp.c")
    assert snip.match_type == "snippet"
    assert snip.matched_lines == 53      # snippet 仍走 _line_count("40-92") = 53
    assert snip.similarity == 95
    assert snip.source_project == "lwip"
    assert snip.source_version == "2.1.3"
    assert snip.license == "BSD-3-Clause"
    full = next(m for m in matches if m.your_file == "src/full.c")
    assert full.match_type == "file"
    assert full.matched_lines == 200     # file 类型走 line_map["src/full.c"] = 200
    assert full.similarity == 100


def test_scan_project_partial_degrades_not_fail(tmp_path: Path, monkeypatch):
    # 一批失败但覆盖足够(2/3 行)→ 不整单失败,返回部分结果,失败文件计入 skipped。
    import engines.provenance.scanoss_provider as sp
    monkeypatch.setattr(sp, "_CHUNK_MAX_FILES", 1)   # 每文件一批 → 3 批
    monkeypatch.setattr(sp, "_CHUNK_DELAY_S", 0.0)
    for name in ("a.c", "b.c", "c.c"):
        (tmp_path / name).write_text("int f(){return 1;}\n" * 5)
    fake_a = {"a.c": [{"id": "snippet", "lines": "1-3", "matched": "90%",
                       "component": "foo", "version": "1.0", "file": "x.c", "licenses": []}]}
    with patch("engines.provenance.scanoss_provider.ScanossApi") as MockApi:
        # a 命中、b 空、c 限流失败 → 覆盖 2/3 ≥ 0.6
        MockApi.return_value.scan.side_effect = [fake_a, {}, Exception("503 service limits")]
        matches, eff, skipped = ScanossProvider().scan_project(tmp_path)
    assert len(matches) == 1
    assert "c.c" in skipped
    assert eff > 0


def test_scan_project_low_coverage_raises(tmp_path: Path, monkeypatch):
    # 多数批次限流失败(覆盖 1/3 < 0.6)→ 诚实失败,不给假结论。
    import engines.provenance.scanoss_provider as sp
    monkeypatch.setattr(sp, "_CHUNK_MAX_FILES", 1)
    monkeypatch.setattr(sp, "_CHUNK_DELAY_S", 0.0)
    for name in ("a.c", "b.c", "c.c"):
        (tmp_path / name).write_text("int f(){return 1;}\n" * 5)
    with patch("engines.provenance.scanoss_provider.ScanossApi") as MockApi:
        MockApi.return_value.scan.side_effect = [{}, Exception("503"), Exception("503")]
        with pytest.raises(ProvenanceError):
            ScanossProvider().scan_project(tmp_path)


def test_scan_project_api_exception_raises(tmp_path: Path):
    # 唯一一批就异常 → 覆盖 0 → 抛 ProvenanceError(诚实文案)。
    (tmp_path / "a.c").write_text("int a(){return 1;}\n" * 5)
    with patch("engines.provenance.scanoss_provider.ScanossApi") as MockApi:
        MockApi.return_value.scan.side_effect = Exception("503 service limits")
        with pytest.raises(ProvenanceError):
            ScanossProvider().scan_project(tmp_path)


def test_scan_project_none_chunk_skipped_gracefully(tmp_path: Path):
    # 单个 chunk 返回 None(坏 JSON)不再整单失败,跳过该批,返回已得结果。
    (tmp_path / "a.c").write_text("int a(){return 1;}\n" * 5)
    with patch("engines.provenance.scanoss_provider.ScanossApi") as MockApi:
        MockApi.return_value.scan.return_value = None
        matches, eff, skipped = ScanossProvider().scan_project(tmp_path)
    assert matches == []
    assert eff > 0


def test_scan_project_success(tmp_path: Path):
    (tmp_path / "a.c").write_text("int a(){return 1;}\n" * 5)
    fake = {"a.c": [{"id": "snippet", "lines": "1-3", "matched": "90%",
                     "component": "foo", "version": "1.0", "file": "x.c",
                     "licenses": [{"name": "MIT"}]}]}
    with patch("engines.provenance.scanoss_provider.ScanossApi") as MockApi:
        MockApi.return_value.scan.return_value = fake
        matches, eff, skipped = ScanossProvider().scan_project(tmp_path)
    assert len(matches) == 1
    assert matches[0].matched_lines == 3
    assert eff > 0


def test_parse_file_match_uses_line_map():
    raw = {"big.c": [{"id": "file", "lines": "all", "matched": "100%",
                      "component": "lwip", "version": "x", "file": "big.c", "licenses": []}]}
    matches = _parse_scan_result(raw, {"big.c": 150})
    assert len(matches) == 1
    assert matches[0].match_type == "file"
    assert matches[0].matched_lines == 150   # 用 line_map,而不是 0


def test_split_wfp_files_groups_by_file_decl():
    from engines.provenance.scanoss_provider import _split_wfp_files
    wfp = "file=aaa,10,a.c\n4=hash1\n8=hash2\nfile=bbb,20,b.c\n5=hash3\n"
    blocks = _split_wfp_files(wfp)
    assert len(blocks) == 2
    assert blocks[0].startswith("file=aaa")
    assert blocks[1].startswith("file=bbb")


def test_chunk_wfp_respects_file_count_limit():
    from engines.provenance.scanoss_provider import _chunk_wfp, _CHUNK_MAX_FILES
    # 构造 (max_files + 5) 个小文件块 → 应拆成 ≥2 个 chunk
    n = _CHUNK_MAX_FILES + 5
    wfp = "".join(f"file=h{i},10,f{i}.c\n4=x{i}\n" for i in range(n))
    chunks = _chunk_wfp(wfp)
    assert len(chunks) >= 2
    # 每个 chunk 的文件块数不超过上限
    for ch in chunks:
        assert ch.count("file=") <= _CHUNK_MAX_FILES
    # 总文件块数守恒
    assert sum(ch.count("file=") for ch in chunks) == n
