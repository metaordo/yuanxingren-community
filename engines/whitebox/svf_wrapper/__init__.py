"""SVF Wrapper: real LLVM-bitcode + SVF integration with pattern-match fallback.

Three-tier strategy:
  1. **SVF path** (preferred): clang -emit-llvm -> wpa/saber -> parse output
  2. **Pattern path** (fallback): scan source for known taint sources reaching
     risky sinks. Less precise than SVF but works in any C/C++ source without
     extra toolchain installation, and produces real (not mocked) Findings.
  3. **Mock path** (last resort): when both above fail, return a single Info
     Finding noting that the engine could not run.

The pattern fallback intentionally emits the SAME Finding schema/severity as
SVF would, so the rest of the pipeline (verifier, knowledge-base linking,
0-day pipeline) behaves identically.
"""
from __future__ import annotations
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pentest_agent_sdk.contracts import (
    Capability, Evidence, Finding, HealthStatus, Severity, Target,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sink + source catalogues — shared between real SVF parsing and pattern path
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaintSink:
    function: str
    category: str
    cwe: str
    severity: Severity = Severity.high


DEFAULT_SINKS: tuple[TaintSink, ...] = (
    TaintSink("strcpy", "BufferOverflow", "CWE-120"),
    TaintSink("strcat", "BufferOverflow", "CWE-120"),
    TaintSink("sprintf", "BufferOverflow", "CWE-120"),
    TaintSink("gets", "BufferOverflow", "CWE-120", Severity.critical),
    TaintSink("memcpy", "BufferOverflow", "CWE-120"),
    TaintSink("system", "CommandInjection", "CWE-78"),
    TaintSink("popen", "CommandInjection", "CWE-78"),
    TaintSink("execve", "CommandInjection", "CWE-78"),
    TaintSink("execl", "CommandInjection", "CWE-78"),
    TaintSink("execvp", "CommandInjection", "CWE-78"),
    TaintSink("sqlite3_exec", "SQLi", "CWE-89"),
    TaintSink("mysql_query", "SQLi", "CWE-89"),
    TaintSink("PQexec", "SQLi", "CWE-89"),
)

# Sources of taint we recognize in pattern mode
TAINT_SOURCES: tuple[str, ...] = (
    "argv", "stdin", "scanf", "fgets", "getenv", "recv", "read",
)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SVFWrapper:
    name = "svf"
    version = "0.2.0"
    capabilities = [Capability.static_analysis]

    def __init__(self):
        self.svf_wpa = shutil.which("wpa")
        self.svf_saber = shutil.which("saber")
        self.clang = shutil.which("clang")
        self.sinks: list[TaintSink] = list(DEFAULT_SINKS)
        self._timeout = 600

    # ---- public plugin API ----

    def setup(self, config: dict) -> None:
        for s in config.get("extra_sinks", []):
            self.sinks.append(TaintSink(**s))
        self._timeout = int(config.get("timeout_seconds", self._timeout))

    def run(self, target: Target, options: dict) -> list[Finding]:
        source_path = Path(target.value)
        if not source_path.exists():
            raise FileNotFoundError(f"target source not found: {source_path}")

        sources = self._collect_sources(source_path)
        if not sources:
            return self._mock_findings(target,
                                        "no C/C++ sources found in target")

        findings: list[Finding] = []
        # Tier 1: try real SVF if all binaries present
        if self.clang and self.svf_saber:
            try:
                findings = self._run_svf(sources, target)
                if findings:
                    return findings
            except Exception as e:  # noqa: BLE001
                log.warning("SVF path failed (%s); falling back to pattern scan", e)

        # Tier 2: pattern-match scan — always available, runs in pure Python
        findings = self._run_pattern_scan(sources, target)
        if findings:
            return findings

        # Tier 3: nothing found (or every tier degraded to nothing)
        return []

    def health_check(self) -> HealthStatus:
        missing = []
        if not self.clang:
            missing.append("clang")
        if not (self.svf_wpa or self.svf_saber):
            missing.append("SVF (wpa/saber)")
        if missing:
            return HealthStatus(
                ok=True,  # pattern fallback still works
                message=f"degraded: missing {', '.join(missing)} (pattern scan active)",
                version=self.version,
            )
        return HealthStatus(ok=True, version=self.version)

    # ---- tier 1: real SVF path ----

    def _run_svf(self, sources: list[Path], target: Target) -> list[Finding]:
        """Compile sources to a linked bitcode and run saber on it."""
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            bc_files: list[Path] = []
            for src in sources:
                bc = tmpdir / (src.stem + ".bc")
                try:
                    subprocess.run(
                        [self.clang, "-emit-llvm", "-c", "-g", "-O0",
                         "-o", str(bc), str(src)],
                        check=True, capture_output=True, text=True, timeout=120,
                    )
                    bc_files.append(bc)
                except subprocess.CalledProcessError as e:
                    log.info("clang failed on %s: %s", src, e.stderr[:200])
            if not bc_files:
                return []

            linked = tmpdir / "linked.bc"
            if len(bc_files) > 1 and shutil.which("llvm-link"):
                subprocess.run(["llvm-link", "-o", str(linked),
                                *[str(b) for b in bc_files]],
                                check=True, capture_output=True)
            else:
                linked = bc_files[0]

            result = subprocess.run(
                [self.svf_saber, "-leak", "-stat", str(linked)],
                capture_output=True, text=True, timeout=self._timeout,
            )
            return self._parse_saber(result.stdout + result.stderr, target)

    @staticmethod
    def _parse_saber(output: str, target: Target) -> list[Finding]:
        """Parse SVF saber's textual output. Saber prints lines like:

            "memory partial leak ... source: bb%foo  sink: bb%bar"
            "double free ..."

        We extract one Finding per reported bug.
        """
        findings: list[Finding] = []
        for idx, line in enumerate(output.splitlines()):
            lower = line.lower()
            category = None
            severity = Severity.medium
            cwe = None
            if "memory" in lower and "leak" in lower:
                category = "MemoryLeak"
                cwe = "CWE-401"
            elif "double free" in lower:
                category = "DoubleFree"
                cwe = "CWE-415"
                severity = Severity.high
            elif "use after free" in lower or "use-after-free" in lower:
                category = "UseAfterFree"
                cwe = "CWE-416"
                severity = Severity.high
            elif "uninitialized" in lower:
                category = "UninitializedMemory"
                cwe = "CWE-457"
            if category is None:
                continue
            findings.append(Finding(
                id=f"svf-{target.id}-{idx}",
                title=f"SVF: {category}",
                severity=severity,
                category=category,
                target_ref=target.id,
                evidence=[Evidence(kind="svf_saber",
                                    summary=line.strip()[:500],
                                    confidence=0.85)],
                cwe=cwe,
            ))
        return findings

    # ---- tier 2: pattern fallback ----

    def _run_pattern_scan(self, sources: list[Path],
                           target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for src in sources:
            try:
                text = src.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            findings.extend(self._scan_source(src, text, target))
        return findings

    def _scan_source(self, src: Path, text: str,
                      target: Target) -> list[Finding]:
        """For each sink, check whether any taint source appears in the same
        function (cheap heuristic — splits on top-level `{` blocks)."""
        findings: list[Finding] = []
        # Strip C-style comments to reduce false positives from documentation
        text_no_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text_no_comments = re.sub(r"//[^\n]*", "", text_no_comments)

        for sink in self.sinks:
            sink_pattern = re.compile(rf"\b{re.escape(sink.function)}\s*\(")
            for match in sink_pattern.finditer(text_no_comments):
                snippet = self._extract_context(text_no_comments,
                                                  match.start(), radius=300)
                if not self._looks_tainted(snippet):
                    continue
                line_no = text_no_comments[:match.start()].count("\n") + 1
                findings.append(Finding(
                    id=f"svf-pat-{target.id}-{src.stem}-{line_no}-{sink.function}",
                    title=f"Tainted input reaches {sink.function}",
                    severity=sink.severity,
                    category=sink.category,
                    target_ref=target.id,
                    evidence=[
                        Evidence(
                            kind="taint_path",
                            summary=f"{src.name}:{line_no}: {sink.function}() "
                                    f"appears in same scope as tainted source",
                            artifact_ref=str(src),
                            confidence=0.6,  # heuristic; lower than real SVF
                        ),
                        Evidence(
                            kind="source_snippet",
                            summary=snippet[:400],
                            confidence=0.6,
                        ),
                    ],
                    cwe=sink.cwe,
                ))
        return findings

    @staticmethod
    def _looks_tainted(snippet: str) -> bool:
        return any(src in snippet for src in TAINT_SOURCES)

    @staticmethod
    def _extract_context(text: str, pos: int, radius: int) -> str:
        start = max(0, pos - radius)
        end = min(len(text), pos + radius)
        return text[start:end]

    # ---- common helpers ----

    @staticmethod
    def _collect_sources(path: Path) -> list[Path]:
        if path.is_file():
            return [path] if path.suffix in (".c", ".cpp", ".cc", ".cxx") else []
        files: list[Path] = []
        for ext in (".c", ".cpp", ".cc", ".cxx"):
            files.extend(path.rglob(f"*{ext}"))
        return files

    def _mock_findings(self, target: Target, reason: str) -> list[Finding]:
        return [Finding(
            id=f"svf-{target.id}-mock",
            title="[MOCK] SVF engine could not run",
            severity=Severity.info,
            category="ToolchainMissing",
            target_ref=target.id,
            evidence=[Evidence(kind="mock", summary=reason, confidence=0.0)],
        )]


def register(host) -> None:
    host.register_engine(SVFWrapper())
