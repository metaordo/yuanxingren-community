"""Agent abstraction: a single LLM-driven role that audits a scoped slice of
the source-code project and emits structured findings.

An Agent is not a long-lived object; it's a stateless config bundle (role
name, system prompt, allowed engines/tools, llm task_kind) plus a `run()`
coroutine that does one pass and returns an `AgentOutput`.

The workflow runtime spawns N agents concurrently via `asyncio.gather`,
passing each a `scope_files` list (the subset of project files the agent
should read). All agents share the same project_root path on disk.
"""
from __future__ import annotations
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..llm import Message
from ..llm.router import acall

log = logging.getLogger(__name__)


@dataclass
class AgentOutput:
    """One agent's contribution to a workflow."""
    role: str
    status: str = "done"           # done | failed | skipped
    findings: list[dict] = field(default_factory=list)
    engine_calls: list[dict] = field(default_factory=list)
    transcript: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    llm_model: str = ""
    latency_ms: int = 0
    error: str | None = None


@dataclass
class AgentSpec:
    """Static configuration of an agent role."""
    role: str
    description: str
    system_prompt: str
    allowed_engines: list[str]
    allowed_tools: list[str]
    llm_task_kind: str = "triage"
    max_tokens: int = 2048
    # files this agent is interested in — used by the file selector when
    # the supervisor returned no explicit scope
    file_extensions: tuple[str, ...] = ()
    # optional regex over relative path that, if it matches, includes the
    # file in this agent's default scope
    path_pattern: str | None = None


class Agent:
    """Stateless agent runtime — one instance per role, reused per task."""

    def __init__(self, spec: AgentSpec):
        self.spec = spec

    @property
    def role(self) -> str:
        return self.spec.role

    async def run(self, *, project_root: Path, scope_files: list[str],
                  user_prompt: str, hints: dict | None = None) -> AgentOutput:
        """Read scoped files, prompt the LLM, parse JSON findings, return."""
        t0 = time.time()
        if not scope_files:
            return AgentOutput(role=self.role, status="skipped",
                                transcript="(no files in scope)")
        try:
            scope_text = self._build_scope_text(project_root, scope_files)
        except Exception as e:  # noqa: BLE001
            return AgentOutput(role=self.role, status="failed",
                                error=f"scope read error: {e}",
                                latency_ms=int((time.time() - t0) * 1000))

        user_msg = self._render_user_message(user_prompt, scope_files, scope_text, hints)
        messages = [
            Message(role="system", content=self.spec.system_prompt),
            Message(role="user", content=user_msg),
        ]
        try:
            result = await acall(self.spec.llm_task_kind, messages,
                                  max_tokens=self.spec.max_tokens)
        except Exception as e:  # noqa: BLE001
            log.warning("agent %s LLM call failed: %s", self.role, e)
            return AgentOutput(role=self.role, status="failed",
                                error=str(e),
                                latency_ms=int((time.time() - t0) * 1000))

        findings = _parse_findings_json(result.text)
        # tag every finding with the producing role so verifier can group
        for f in findings:
            f.setdefault("role", self.role)
        # Thinking models (e.g. DeepSeek v4-pro) put their chain-of-thought
        # in `reasoning_content` on the raw payload. Surface it in the
        # transcript so operators can audit how the agent arrived at its
        # findings. Non-thinking models won't populate this field — guard
        # with .get() to keep behavior unchanged for them.
        reasoning = (result.raw or {}).get("reasoning_content")
        if reasoning:
            transcript_body = (
                f"🧠 推理过程:\n{reasoning}\n\n"
                f"---\n\n"
                f"{result.text or ''}"
            )
        else:
            transcript_body = result.text or ""
        return AgentOutput(
            role=self.role,
            status="done",
            findings=findings,
            transcript=transcript_body,
            tokens_in=result.usage.input_tokens,
            tokens_out=result.usage.output_tokens,
            llm_model=result.model,
            latency_ms=int((time.time() - t0) * 1000),
        )

    # ---- helpers ----

    def _build_scope_text(self, root: Path, files: list[str],
                          per_file_cap: int = 40_000,
                          total_cap: int = 160_000) -> str:
        """Concatenate file contents into the prompt body, with caps.

        per_file_cap is the byte ceiling for a single file's text;
        total_cap is the ceiling across all files in this agent's scope.
        Caps raised from 16KB/64KB to 40KB/160KB so agents see complete
        files rather than truncated snippets.
        """
        parts: list[str] = []
        used = 0
        for rel in files:
            p = root / rel
            try:
                raw = p.read_bytes()
            except Exception as e:
                parts.append(f"### {rel}\n(read error: {e})\n")
                continue
            if len(raw) > per_file_cap:
                raw = raw[:per_file_cap]
                truncated = "\n…(truncated)"
            else:
                truncated = ""
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = "(binary file, skipped)"
            block = f"### {rel}\n```\n{text}{truncated}\n```\n"
            if used + len(block) > total_cap:
                parts.append(f"### {rel}\n(omitted — total scope cap reached)\n")
                break
            parts.append(block)
            used += len(block)
        return "\n".join(parts)

    def _render_user_message(self, user_prompt: str, scope_files: list[str],
                              scope_text: str, hints: dict | None) -> str:
        hint_block = ""
        if hints:
            # LLM supervisor occasionally returns hints as a plain string;
            # guard before calling .items().
            if not isinstance(hints, dict):
                hints = {}
            # filter out internal-only keys that confuse the model
            display_hints = {k: v for k, v in hints.items()
                             if k not in ("forced", "filler")}
            if display_hints:
                hint_block = (f"\nSupervisor hints: "
                              f"{json.dumps(display_hints, ensure_ascii=False)}\n")
        return (
            f"User objective: {user_prompt}\n"
            f"Your role: {self.spec.role} — {self.spec.description}\n"
            f"Files in your scope ({len(scope_files)}):\n"
            f"{chr(10).join('  - ' + f for f in scope_files)}\n"
            f"{hint_block}"
            f"--- BEGIN FILE CONTENTS ---\n{scope_text}\n--- END FILE CONTENTS ---\n\n"
            f"ANALYSIS PROTOCOL — follow strictly:\n"
            f"1. Read EVERY file above completely before forming conclusions.\n"
            f"2. For each vulnerability class in your role description, actively hunt "
            f"for it across ALL files — do not stop after finding one instance.\n"
            f"3. For each finding: pin EXACT file path + line number; quote the "
            f"specific code that is vulnerable as 'evidence'; write a 'rationale' "
            f"that explains the full attack chain (how an attacker reaches this code "
            f"and what the impact is).\n"
            f"4. Confidence must reflect actual code evidence: ≥0.8 only when you "
            f"can trace both the trigger and the impact; 0.5-0.7 for plausible but "
            f"requires runtime confirmation; ≤0.4 for partial visibility.\n"
            f"5. Do NOT self-censor because a finding seems 'minor' — include all "
            f"medium, high, and critical findings. Low/info only if clearly relevant.\n"
            f"6. Only output [] if you have genuinely read the entire scope and found "
            f"zero issues in your specific domain — this should be rare.\n\n"
            f"Output a JSON array ONLY (no prose, no fences). Schema per item:\n"
            f"{{\"title\": str, \"severity\": \"info|low|medium|high|critical\", "
            f"\"category\": str, \"cwe\": str|null, \"file\": str, "
            f"\"line\": int|null, \"line_end\": int|null, "
            f"\"evidence\": str, \"confidence\": 0.0-1.0, \"rationale\": str}}"
        )


def _parse_findings_json(text: str) -> list[dict]:
    """Best-effort extract a JSON array from LLM output.

    Handles ```json fences, leading prose, and trailing commentary. Returns
    [] if no valid array is found.
    """
    if not text:
        return []
    fence = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", text)
    if fence:
        try:
            return _normalize_findings(json.loads(fence.group(1)))
        except json.JSONDecodeError:
            pass
    # bracket scan: first '[' to its matching ']'
    start = text.find("[")
    if start == -1:
        return []
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                try:
                    return _normalize_findings(json.loads(text[start:i + 1]))
                except json.JSONDecodeError:
                    return []
    return []


def _normalize_findings(arr: Any) -> list[dict]:
    if not isinstance(arr, list):
        return []
    out: list[dict] = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        # accept a few common alternative key spellings
        if "lines" in item and "line" not in item:
            ln = item["lines"]
            if isinstance(ln, list) and ln:
                item["line"] = ln[0]
                item["line_end"] = ln[-1]
        # LLMs sometimes hallucinate absolute paths around an unqualified
        # filename (e.g. "/some/random/path/vuln.c"). Strip leading absolute
        # path components so we never expose phantom host paths in reports.
        f = item.get("file")
        if isinstance(f, str) and f:
            from pathlib import PurePosixPath
            p = PurePosixPath(f)
            # if it looks absolute or has more than 4 segments, keep just
            # the last 2 segments (e.g. "subdir/vuln.c")
            if p.is_absolute() or len(p.parts) > 4:
                tail = p.parts[-2:] if len(p.parts) >= 2 else p.parts
                item["file"] = "/".join(tail)
        out.append(item)
    return out
