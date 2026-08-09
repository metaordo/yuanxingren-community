"""Run the orchestrator graph against an input.

M1: backed by a compiled LangGraph StateGraph (`graph.build_app()`). The
hand-rolled while-loop dispatcher has been retired but the public `run()`
signature is preserved so callers in chat.py / WS / tests are untouched.
"""
from __future__ import annotations
import logging
from pentest_agent_sdk.contracts import Target
from . import graph

log = logging.getLogger(__name__)


def run(user_prompt: str, target: Target, *,
        auth_scope: dict | None = None) -> dict:
    """Execute the full pipeline: plan -> route -> verify -> report.

    `auth_scope` is propagated to external tool wrappers so the orchestrator
    can call tools like zap/nmap with scope enforcement matching the calling
    user's allow-list.
    """
    initial: graph.AgentState = {
        "user_prompt": user_prompt,
        "target": target,
        "auth_scope": auth_scope or {"hosts": [], "cidrs": []},
    }
    app = graph.build_app()
    final = app.invoke(initial)
    return {
        "plan": final.get("plan", []),
        "tool_results": final.get("tool_results", []),
        "verified_findings": [_finding_to_dict(f)
                              for f in final.get("verified_findings", [])],
        "report": final.get("report", ""),
    }


def _finding_to_dict(f) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "category": f.category,
        "cwe": f.cwe,
        "cve": f.cve,
        "evidence": [{"kind": e.kind, "summary": e.summary,
                      "confidence": e.confidence} for e in f.evidence],
    }
