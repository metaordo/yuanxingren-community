"""Tests for the real (non-mock) SVF wrapper pattern scan.

These exercise the tier-2 fallback (no SVF/clang required) against the
Juliet-style CVE fixtures.
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from pentest_agent_sdk.contracts import Severity, Target
from engines.whitebox.svf_wrapper import SVFWrapper


FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "cve_samples"


def _scan(filename: str):
    eng = SVFWrapper()
    eng.setup({})
    target = Target(id=f"fx-{filename}", type="binary",
                     value=str(FIXTURES / filename))
    return eng.run(target, {})


def test_detects_strcpy_taint():
    findings = _scan("CWE120_strcpy.c")
    cats = {f.category for f in findings}
    assert "BufferOverflow" in cats, f"expected BufferOverflow, got {cats}"
    # CWE tag should be carried through
    bo = next(f for f in findings if f.category == "BufferOverflow")
    assert bo.cwe == "CWE-120"
    # Evidence chain should include the taint path
    kinds = {e.kind for e in bo.evidence}
    assert "taint_path" in kinds


def test_detects_system_command_injection():
    findings = _scan("CWE78_system.c")
    cats = {f.category for f in findings}
    assert "CommandInjection" in cats, f"expected CommandInjection, got {cats}"


def test_detects_sqli():
    findings = _scan("CWE89_sqli.c")
    cats = {f.category for f in findings}
    assert "SQLi" in cats, f"expected SQLi, got {cats}"


def test_does_not_false_positive_on_clean_code(tmp_path):
    """A file that calls strcpy on a STRING LITERAL (no taint) should not fire."""
    clean = tmp_path / "clean.c"
    clean.write_text(
        "#include <string.h>\n"
        "int main(void) {\n"
        "    char d[16];\n"
        "    strcpy(d, \"hello\");\n"
        "    return 0;\n"
        "}\n"
    )
    eng = SVFWrapper()
    eng.setup({})
    findings = eng.run(Target(id="clean", type="binary", value=str(clean)), {})
    # Should not flag — there's no taint source (argv/scanf/etc.) nearby
    assert all(f.category != "BufferOverflow" for f in findings), \
        f"unexpected BO finding on clean code: {findings}"


def test_health_check_reports_degraded_when_clang_missing():
    eng = SVFWrapper()
    eng.clang = None
    eng.svf_saber = None
    h = eng.health_check()
    # Pattern fallback still works → ok=True, but message notes missing tools
    assert h.ok is True
    assert "degraded" in h.message.lower()


def test_saber_output_parsing():
    """Verify the saber output parser handles real-looking lines."""
    output = (
        "Bug Report:\n"
        "memory partial leak occurred at function foo\n"
        "double free in function bar\n"
        "use-after-free at function baz\n"
        "uninitialized memory read in qux\n"
        "random unrelated line\n"
    )
    target = Target(id="t", type="binary", value="/dev/null")
    findings = SVFWrapper._parse_saber(output, target)
    cats = {f.category for f in findings}
    assert cats == {"MemoryLeak", "DoubleFree", "UseAfterFree", "UninitializedMemory"}
    # Severity should be elevated for double-free and UAF
    by_cat = {f.category: f for f in findings}
    assert by_cat["DoubleFree"].severity == Severity.high
    assert by_cat["UseAfterFree"].severity == Severity.high
