import textwrap
from pathlib import Path

import pytest

from engines.provenance.fingerprint import generate_wfp, count_effective_lines


def test_count_effective_lines_strips_blank_and_comments():
    code = textwrap.dedent('''\
        // header comment
        int main() {

            return 0;  // inline
        }
        ''')
    # 有效行:int main(), return 0;, } → 3(剥离空行、纯注释行)
    assert count_effective_lines(code) == 3


def test_generate_wfp_nonempty_and_has_file_decl(tmp_path: Path):
    f = tmp_path / "tcp.c"
    f.write_text("int connect_tcp(int fd) {\n    return bind(fd);\n}\n" * 10)
    wfp = generate_wfp(str(f), "src/tcp.c")
    assert wfp                       # 非空
    assert "file=" in wfp            # WFP 含文件声明行
    assert "src/tcp.c" in wfp        # 记录了相对路径


def test_generate_wfp_for_tree_skips_generated(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text("int a() { return 1; }\n" * 5)
    (tmp_path / "package-lock.json").write_text('{"x":1}\n' * 100)
    from engines.provenance.fingerprint import build_project_wfp
    wfp, effective_lines, skipped, line_map = build_project_wfp(tmp_path)
    assert "src/a.c" in wfp
    assert "package-lock.json" not in wfp     # 生成文件被剥离
    assert "package-lock.json" in skipped
    assert effective_lines > 0
    assert line_map.get("src/a.c", 0) > 0
    assert "package-lock.json" not in line_map
