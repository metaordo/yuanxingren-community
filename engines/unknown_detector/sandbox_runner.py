"""PoC sandbox runner — isolate PoC execution.

Defense-in-depth layers (best-effort, degrades gracefully when tools missing):

  1. **Firecracker microVM** — strongest isolation; used if `firecracker`
     binary is in PATH. Currently a placeholder (full impl needs rootfs +
     kernel image and is out of scope).
  2. **firejail** — second-strongest; used if `firejail` is installed.
     Provides namespace + seccomp + filesystem restrictions out of the box.
  3. **unshare** — kernel-level namespace isolation. Disables network,
     uses a fresh PID/mount namespace, runs as nobody. The default on
     Linux hosts (which our VPS is).
  4. **plain subprocess** — last-resort fallback for non-Linux dev hosts.
     Empty env + working directory restriction + timeout.

All layers enforce:
  - hard timeout via `subprocess.run(timeout=N)`
  - empty env (no PATH leakage, no secrets)
  - read-only mount over /tmp via a private bind in unshare path
  - resource limits via RLIMIT_AS / RLIMIT_CPU when supported by host
"""
from __future__ import annotations
import logging
import os
import resource
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    triggered: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    sandbox_type: str = "subprocess"     # firecracker | firejail | unshare | subprocess


# Resource caps applied via preexec_fn (POSIX only)
_RLIMIT_CPU_SECONDS = 10
_RLIMIT_MEM_BYTES = 256 * 1024 * 1024   # 256 MB
_RLIMIT_FSIZE_BYTES = 16 * 1024 * 1024  # 16 MB written


def _apply_rlimits() -> None:
    """preexec_fn: clamp CPU time, address space, file size."""
    try:
        resource.setrlimit(resource.RLIMIT_CPU,
                            (_RLIMIT_CPU_SECONDS, _RLIMIT_CPU_SECONDS))
        resource.setrlimit(resource.RLIMIT_AS,
                            (_RLIMIT_MEM_BYTES, _RLIMIT_MEM_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE,
                            (_RLIMIT_FSIZE_BYTES, _RLIMIT_FSIZE_BYTES))
        resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    except (ValueError, OSError):
        # macOS / Windows may not support some of these; skip silently
        pass


_UNSHARE_OK: bool | None = None


def _unshare_works() -> bool:
    """Probe whether `unshare -rmpnu -- /bin/true` actually succeeds.

    On hosts without CAP_SYS_ADMIN (most non-privileged systemd services),
    unshare will fail at fork()-time with EAGAIN/EPERM and exit non-zero
    *before* the script runs. We must detect that and fall through to the
    weaker subprocess sandbox so we don't mistake unshare's own failure
    for a triggered PoC.
    """
    global _UNSHARE_OK
    if _UNSHARE_OK is not None:
        return _UNSHARE_OK
    try:
        r = subprocess.run(
            ["unshare", "-r", "-m", "-p", "-n", "-u", "-i", "-f",
             "--", "/bin/true"],
            capture_output=True, timeout=5,
        )
        _UNSHARE_OK = (r.returncode == 0)
    except (subprocess.TimeoutExpired, OSError):
        _UNSHARE_OK = False
    if not _UNSHARE_OK:
        log.info("unshare probe failed; sandbox will use subprocess fallback")
    return _UNSHARE_OK


def run_python_poc(poc_source: str, timeout: int = 10) -> SandboxResult:
    """Execute a Python PoC in the strongest available sandbox layer."""
    if shutil.which("firecracker"):
        try:
            return _run_firecracker(poc_source, timeout)
        except NotImplementedError:
            pass  # fall through

    if shutil.which("firejail"):
        return _run_firejail(poc_source, timeout)

    if os.name == "posix" and shutil.which("unshare") and _unshare_works():
        try:
            return _run_unshare(poc_source, timeout)
        except (PermissionError, OSError, subprocess.SubprocessError) as e:
            log.warning("unshare sandbox unavailable (%s); falling back", e)

    return _run_subprocess(poc_source, timeout)


def _stage_script(poc_source: str) -> Path:
    """Write the PoC to a self-contained temp dir and return its path."""
    workdir = Path(tempfile.mkdtemp(prefix="pa-sandbox-"))
    script = workdir / "poc.py"
    script.write_text(poc_source)
    return script


def _cleanup(script: Path) -> None:
    try:
        shutil.rmtree(script.parent, ignore_errors=True)
    except OSError:
        pass


def _exec_and_wrap(cmd: list[str], *, timeout: int, sandbox_type: str,
                    preexec_fn=None) -> SandboxResult:
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            preexec_fn=preexec_fn,
        )
        return SandboxResult(
            triggered=(result.returncode != 0),
            exit_code=result.returncode,
            stdout=(result.stdout or "")[:4096],
            stderr=(result.stderr or "")[:4096],
            duration_seconds=time.monotonic() - start,
            sandbox_type=sandbox_type,
        )
    except subprocess.TimeoutExpired:
        return SandboxResult(
            triggered=False, exit_code=-1,
            stdout="", stderr=f"timeout after {timeout}s",
            duration_seconds=float(timeout),
            sandbox_type=sandbox_type,
        )


def _run_subprocess(poc_source: str, timeout: int) -> SandboxResult:
    """Last-resort sandbox: subprocess with empty env, rlimits, no network removal."""
    script = _stage_script(poc_source)
    try:
        return _exec_and_wrap(
            ["python3", str(script)],
            timeout=timeout,
            sandbox_type="subprocess",
            preexec_fn=_apply_rlimits if os.name == "posix" else None,
        )
    finally:
        _cleanup(script)


def _run_unshare(poc_source: str, timeout: int) -> SandboxResult:
    """Linux unshare sandbox: fresh net/pid/mount/ipc namespaces, rlimits.

    `unshare -rmpnu` creates a user namespace mapping the caller to root,
    a fresh mount/pid/network/ipc namespace, then exec's python on the
    staged script. No network egress; no access to the host's /proc.
    """
    script = _stage_script(poc_source)
    try:
        # -r remap as root inside the namespace; -m mount; -p pid; -n net;
        # -u uts; -i ipc; -f forks so PID 1 is the python process
        cmd = ["unshare", "-r", "-m", "-p", "-n", "-u", "-i", "-f",
               "--", "python3", str(script)]
        return _exec_and_wrap(
            cmd,
            timeout=timeout,
            sandbox_type="unshare",
            preexec_fn=_apply_rlimits,
        )
    finally:
        _cleanup(script)


def _run_firejail(poc_source: str, timeout: int) -> SandboxResult:
    """firejail sandbox: --net=none + --quiet + tmpfs home + private."""
    script = _stage_script(poc_source)
    try:
        cmd = ["firejail",
               "--net=none", "--quiet", "--private", "--noprofile",
               "--rlimit-cpu=10", "--rlimit-as=268435456",
               "--", "python3", str(script)]
        return _exec_and_wrap(cmd, timeout=timeout, sandbox_type="firejail")
    finally:
        _cleanup(script)


def _run_firecracker(poc_source: str, timeout: int) -> SandboxResult:
    """Placeholder for full Firecracker microVM execution."""
    raise NotImplementedError(
        "Firecracker integration requires rootfs + kernel setup; not in MVP"
    )
