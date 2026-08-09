"""LLM-driven PoC synthesis.

Given a Finding + its evidence chain, ask the LLM to produce a short Python
PoC that demonstrates the vulnerability. The PoC is sandboxed before it ever
runs against anything outside the controlled environment.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass

from pentest_agent_sdk.contracts import Finding

log = logging.getLogger(__name__)


@dataclass
class PoC:
    source: str
    language: str = "python"
    notes: str = ""


_SYSTEM = (
    "You are a security PoC author. Produce a short, safe, sandboxable Python "
    "proof-of-concept for the given finding. The PoC MUST: "
    "(1) not contact any real network target, "
    "(2) exit with non-zero code when the vulnerability is triggered, "
    "(3) print a one-line explanation. "
    "Output ONLY Python source code, no surrounding text."
)


def synthesize(finding: Finding) -> PoC:
    """Ask the LLM to draft a PoC. Never runs it — caller must sandbox."""
    try:
        from backend.llm import Message
        from backend.llm.router import call as llm_call
    except ImportError:
        return PoC(
            source='print("llm not available; mock poc")\nraise SystemExit(1)',
            notes="llm unavailable",
        )

    evidence_text = "\n".join(f"- {e.kind}: {e.summary[:200]}"
                               for e in finding.evidence)
    user = (
        f"Finding title: {finding.title}\n"
        f"Category: {finding.category}\n"
        f"Severity: {finding.severity.value}\n"
        f"Evidence:\n{evidence_text}\n"
    )
    try:
        result = llm_call("codegen",
                          [Message(role="system", content=_SYSTEM),
                           Message(role="user", content=user)],
                          max_tokens=1024, temperature=0.1)
        return PoC(source=_extract_code(result.text))
    except Exception as e:  # noqa: BLE001
        log.warning("PoC synthesis failed: %s", e)
        return PoC(
            source='print("poc synthesis failed")\nraise SystemExit(2)',
            notes=str(e),
        )


def _extract_code(text: str) -> str:
    """Strip markdown fences if the LLM wrapped the code."""
    import re
    m = re.search(r"```(?:python)?\s*\n(.*?)\n```", text, re.DOTALL)
    if m:
        return m.group(1)
    return text.strip()
