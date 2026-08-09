"""StateAFL / AFL++ integration: stateful protocol fuzzing.

Tiered strategy (parallels SVF wrapper):
  1. **AFL++ path** (preferred): real afl-fuzz against an instrumented harness
  2. **Subprocess-fuzzer fallback**: light random/dictionary mutation of seed
     inputs fed to the target binary via stdin/argv, watching for crashes
  3. **Mock**: when neither can run

The fallback fuzzer is deliberately simple — it's not coverage-guided — but
gives real (non-mocked) Findings when fuzzing a small target like the Juliet
strcpy fixture compiled to a binary.
"""
from __future__ import annotations
import logging
import os
import random
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from pentest_agent_sdk.contracts import (
    Capability, Evidence, Finding, HealthStatus, Severity, Target,
)

log = logging.getLogger(__name__)


class StateAFLEngine:
    name = "stateafl"
    version = "0.2.0"
    capabilities = [Capability.fuzzing]

    def __init__(self):
        self.aflpp = shutil.which("afl-fuzz")
        self.afl_cc = shutil.which("afl-clang-fast") or shutil.which("afl-gcc")
        self._timeout_per_input_ms = 1000
        self._fuzz_duration_s = 30
        self._max_iterations = 200

    # ---- public plugin API ----

    def setup(self, config: dict) -> None:
        self._timeout_per_input_ms = int(config.get("timeout_per_input", 1000))
        self._fuzz_duration_s = int(config.get("fuzz_duration", 30))
        self._max_iterations = int(config.get("max_iterations", 200))

    def run(self, target: Target, options: dict) -> list[Finding]:
        if target.type not in ("binary", "protocol", "pcap"):
            raise ValueError(f"StateAFL does not accept target type {target.type!r}")

        binary_path = self._target_binary(target, options)

        # Tier 1: real AFL++
        if self.aflpp and binary_path and binary_path.exists():
            try:
                return self._run_aflpp(binary_path, options, target)
            except Exception as e:  # noqa: BLE001
                log.warning("AFL++ path failed (%s); falling back to subprocess fuzzer", e)

        # Tier 2: subprocess fuzzer
        if binary_path and binary_path.exists():
            try:
                return self._run_subprocess_fuzzer(binary_path, options, target)
            except Exception as e:  # noqa: BLE001
                log.warning("subprocess fuzzer failed: %s", e)

        return self._mock_findings(target)

    def health_check(self) -> HealthStatus:
        if not self.aflpp:
            return HealthStatus(
                ok=True,
                message="degraded: AFL++ not installed (subprocess fuzzer active)",
                version=self.version,
            )
        return HealthStatus(ok=True, version=self.version)

    # ---- target binary resolution ----

    def _target_binary(self, target: Target, options: dict) -> Path | None:
        """Resolve which binary to fuzz. Caller can override via options['harness_path']."""
        if "harness_path" in options:
            return Path(options["harness_path"])
        if target.type == "binary":
            return Path(target.value)
        return None

    # ---- tier 1: AFL++ ----

    def _run_aflpp(self, binary: Path, options: dict,
                    target: Target) -> list[Finding]:
        duration = int(options.get("duration", self._fuzz_duration_s))
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            corpus = self._prepare_corpus(target, options, workdir)
            output = workdir / "afl-out"

            env = os.environ.copy()
            env.setdefault("AFL_SKIP_CPUFREQ", "1")
            env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
            args = [self.aflpp,
                    "-i", str(corpus),
                    "-o", str(output),
                    "-V", str(duration),
                    "--", str(binary)]
            log.info("AFL++: %s", " ".join(args))
            try:
                subprocess.run(args, env=env, timeout=duration + 60,
                                check=False, capture_output=True)
            except subprocess.TimeoutExpired:
                pass
            return self._collect_aflpp_crashes(output, target)

    def _collect_aflpp_crashes(self, output_dir: Path,
                                target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for fuzzer in ("default", "fuzzer01"):
            crashes_dir = output_dir / fuzzer / "crashes"
            if not crashes_dir.exists():
                continue
            for idx, crash in enumerate(sorted(crashes_dir.iterdir())):
                if not crash.is_file() or crash.name.startswith("README"):
                    continue
                payload = crash.read_bytes()[:512]
                findings.append(Finding(
                    id=f"aflpp-{target.id}-{idx}",
                    title=f"AFL++ crash input #{idx}",
                    severity=Severity.high,
                    category="MemorySafety",
                    target_ref=target.id,
                    evidence=[Evidence(
                        kind="crash_input",
                        summary=f"{len(payload)}-byte input; "
                                f"prefix hex={payload[:32].hex()}",
                        artifact_ref=str(crash),
                        confidence=0.9,
                    )],
                ))
        return findings

    # ---- tier 2: subprocess-based fuzzer ----

    def _run_subprocess_fuzzer(self, binary: Path, options: dict,
                                target: Target) -> list[Finding]:
        """Naive random + dictionary mutation, stdin or argv delivery."""
        max_iters = int(options.get("max_iterations", self._max_iterations))
        timeout_ms = int(options.get("timeout_per_input",
                                       self._timeout_per_input_ms))
        timeout_s = timeout_ms / 1000.0
        seed_inputs = self._seed_inputs(options)
        delivery = options.get("delivery", "argv")  # "argv" | "stdin"

        findings: list[Finding] = []
        crashes: list[tuple[bytes, int, str]] = []
        rng = random.Random(0xC0FFEE)

        for i in range(max_iters):
            payload = self._mutate(rng.choice(seed_inputs), rng)
            rc, signal_name = self._invoke(binary, payload, delivery, timeout_s)
            if signal_name or rc < 0 or rc == 134 or rc == 139:
                crashes.append((payload, rc, signal_name or "abnormal"))
                if len(crashes) >= 10:
                    break

        for idx, (payload, rc, reason) in enumerate(crashes):
            findings.append(Finding(
                id=f"sfuzz-{target.id}-{idx}",
                title=f"Subprocess-fuzz crash on {binary.name}",
                severity=Severity.high,
                category="MemorySafety",
                target_ref=target.id,
                evidence=[Evidence(
                    kind="crash_input",
                    summary=f"reason={reason} rc={rc} "
                            f"input(len={len(payload)})={payload[:32].hex()}",
                    confidence=0.7,
                )],
                cwe="CWE-120",
            ))
        return findings

    # ---- common helpers ----

    def _prepare_corpus(self, target: Target,
                        options: dict, workdir: Path) -> Path:
        corpus = workdir / "corpus"
        corpus.mkdir()
        if "seed_corpus" in options:
            src_dir = Path(options["seed_corpus"])
            for f in src_dir.iterdir():
                if f.is_file():
                    (corpus / f.name).write_bytes(f.read_bytes())
        if target.type == "pcap" and Path(target.value).exists():
            # Naive: store the whole pcap as one seed; a real impl uses tshark
            (corpus / "seed_pcap").write_bytes(
                Path(target.value).read_bytes()
            )
        if not any(corpus.iterdir()):
            (corpus / "seed_0").write_bytes(b"A" * 16)
        return corpus

    @staticmethod
    def _seed_inputs(options: dict) -> list[bytes]:
        seeds: list[bytes] = []
        if "seed_corpus" in options:
            d = Path(options["seed_corpus"])
            if d.exists():
                for f in d.iterdir():
                    if f.is_file():
                        seeds.append(f.read_bytes())
        if not seeds:
            seeds = [b"A" * 16, b"A" * 256, b"A" * 4096,
                      b"%n%n%n%n", b"\x00" * 32]
        return seeds

    @staticmethod
    def _mutate(payload: bytes, rng: random.Random) -> bytes:
        op = rng.randrange(4)
        b = bytearray(payload)
        if op == 0 and b:  # flip byte
            i = rng.randrange(len(b))
            b[i] = rng.randrange(256)
        elif op == 1:  # extend
            extra = rng.choice([b"A" * 64, b"\x00" * 64, b"%s%s%s"])
            b.extend(extra)
        elif op == 2 and len(b) > 8:  # truncate
            b = b[: rng.randrange(1, len(b))]
        elif op == 3:  # insert format string
            b += b"%n%n%n%n"
        return bytes(b)

    @staticmethod
    def _invoke(binary: Path, payload: bytes, delivery: str,
                 timeout_s: float) -> tuple[int, str | None]:
        try:
            if delivery == "stdin":
                proc = subprocess.run(
                    [str(binary)], input=payload,
                    capture_output=True, timeout=timeout_s,
                )
            else:
                # argv cannot contain NUL bytes in POSIX exec — strip them
                # for delivery; the test target sees a string anyway.
                arg = payload.replace(b"\x00", b"").decode("latin-1", errors="replace")
                proc = subprocess.run(
                    [str(binary), arg],
                    capture_output=True, timeout=timeout_s,
                )
            rc = proc.returncode
            sig = None
            if rc < 0:
                try:
                    sig = signal.Signals(-rc).name
                except ValueError:
                    sig = f"signal-{-rc}"
            return rc, sig
        except subprocess.TimeoutExpired:
            return 0, "timeout"
        except OSError as e:
            return -1, f"oserror:{e}"
        except ValueError as e:
            # Mutation generated a payload Python refuses to pass as argv
            return -1, f"valueerror:{e}"

    def _mock_findings(self, target: Target) -> list[Finding]:
        return [Finding(
            id=f"stateafl-{target.id}-mock",
            title="[MOCK] No fuzzing target binary available",
            severity=Severity.info,
            category="ToolchainMissing",
            target_ref=target.id,
            evidence=[Evidence(kind="mock",
                                summary="provide target.value pointing to an executable",
                                confidence=0.0)],
        )]


def register(host) -> None:
    host.register_engine(StateAFLEngine())
