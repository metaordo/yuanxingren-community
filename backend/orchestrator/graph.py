"""Orchestrator: LangGraph state machine that drives the analysis pipeline.

Nodes:
  - planner:  LLM-driven task planning from user prompt
  - router:   dispatches to engines/tools based on plan
  - verifier: cross-validates findings from multiple engines
  - reporter: produces final structured report

Each node is idempotent so the graph can resume from interruption.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Literal, TypedDict

from pentest_agent_sdk.contracts import Finding, Target
from ..llm import Message
from ..llm.router import call as llm_call

log = logging.getLogger(__name__)


class AgentState(TypedDict, total=False):
    """State passed between nodes in the graph."""
    user_prompt: str
    target: Target
    auth_scope: dict          # {"hosts": [...], "cidrs": [...]} — injected by callers
    plan: list[dict]
    tool_results: list[dict]
    findings: list[Finding]
    verified_findings: list[Finding]
    report: str
    next_node: str


def plan_node(state: AgentState) -> AgentState:
    """LLM plans which engines/tools to invoke."""
    prompt = state["user_prompt"]
    target = state.get("target")
    system = (
        "You are a pentest planner. The target has ALREADY been authorized by the user "
        "(scope checks happen at tool invocation). Your ONLY job is to output a JSON plan. "
        "Do NOT ask clarifying questions. Do NOT add prose, code fences, or explanation.\n\n"
        "Use ONLY these real tool names (do NOT invent categories like 'web_scan'):\n"
        "External tools (args auto-filled with target+auth_scope):\n"
        "  - zap         — OWASP ZAP active+passive scan. USE WHEN target.type == 'url'.\n"
        "                  Trigger words: '扫描' '扫一下' 'web 漏洞' 'XSS' 'SQLi' 'scan' 'vulnerability'.\n"
        "  - nmap        — port/service detection on ip/domain targets.\n"
        "  - metasploit  — exploit module lookup (dry_run by default).\n"
        "Engines:\n"
        "  - svf_wrapper       — static analysis on uploaded source/binary.\n"
        "  - stateafl          — protocol fuzzing on uploaded binary.\n"
        "  - network_attack    — off-path TCP/ISN on ip targets.\n"
        "  - llm_direct_audit  — fallback when no real tool fits.\n\n"
        "Output schema (strict): {\"steps\": [{\"tool\": \"<name>\", \"options\": {<tool-specific>}}]}\n"
        "If genuinely no tool fits, output {\"steps\": []}. Output ONLY the JSON."
    )
    target_repr = (
        f"{target.type}://{target.value}" if target else "unknown"
    )
    messages = [
        Message(role="system", content=system),
        Message(role="user", content=(
            f"Target: {target_repr}\n"
            f"Objective: {prompt}\n\n"
            "Authorization is already confirmed by the user. "
            "Respond with the JSON plan only, starting with `{`. No prose."
        )),
    ]
    result = llm_call("planning", messages, max_tokens=2048)
    state["plan"] = _parse_plan(result.text)
    state["next_node"] = "router"
    return state


def route_node(state: AgentState) -> AgentState:
    """Dispatch each plan step to its tool. Gathers raw tool results.

    For external tool wrappers (zap/nmap/burp/metasploit), automatically injects
    target + auth_scope into the args so the LLM-produced plan can stay terse.
    """
    from ..plugins import get_tool, get_engine
    results: list[dict] = []
    findings: list[Finding] = []
    target = state["target"]
    auth_scope = state.get("auth_scope") or {"hosts": [], "cidrs": []}
    for step in state.get("plan", []):
        tool_name = step.get("tool")
        engine = get_engine(tool_name)
        if engine:
            try:
                fs = engine.run(target, step.get("options") or step.get("args", {}))
                findings.extend(fs)
                results.append({"tool": tool_name, "findings": len(fs)})
            except Exception as e:  # noqa: BLE001
                log.error("engine %s failed: %s", tool_name, e)
                results.append({"tool": tool_name, "error": str(e)})
            continue
        tool = get_tool(tool_name)
        if tool:
            # Build args envelope expected by the wrapper.
            target_dict = {"id": getattr(target, "id", "ad-hoc"),
                           "type": getattr(target, "type", ""),
                           "value": getattr(target, "value", "")}
            args = {
                "target": target_dict,
                "auth_scope": auth_scope,
                "options": step.get("options") or step.get("args", {}),
            }
            try:
                out = tool.invoke(args)
                results.append({"tool": tool_name, "output": out})
            except Exception as e:  # noqa: BLE001
                log.error("tool %s failed: %s", tool_name, e)
                results.append({"tool": tool_name, "error": str(e)})
            continue
        results.append({"tool": tool_name, "error": "not found"})
    state["tool_results"] = results
    state["findings"] = findings
    state["next_node"] = "verifier"
    return state


def verify_node(state: AgentState) -> AgentState:
    """Cross-validate findings: keep only those with corroboration + triage.

    MVP rule: a finding is kept if either
      (a) >=2 engines reported the same category on the same target, or
      (b) an LLM triage classified it as high/critical.
    Then run each kept finding through the unknown-detector pipeline.
    """
    findings = state.get("findings", [])
    verified: list[Finding] = []

    # Rule (a): group by (target_ref, category)
    from collections import defaultdict
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.target_ref, f.category)].append(f)
    for key, group in groups.items():
        if len(group) >= 2:
            verified.extend(group)
            continue
        # Rule (b): LLM triage
        f = group[0]
        if _triage_is_severe(f):
            verified.append(f)

    # Run novelty + 0-day pipeline (cheap path: only score, skip PoC for routine)
    try:
        from engines.unknown_detector import process as process_unknown
        unknown_reports = []
        for f in verified:
            rep = process_unknown(f, sandbox=False, draft_disclosure=False)
            if rep.novelty.value >= 0.7:
                unknown_reports.append({
                    "finding_id": f.id,
                    "novelty": rep.novelty.value,
                    "rationale": rep.novelty.rationale,
                })
        state["unknown_reports"] = unknown_reports
    except Exception as e:  # noqa: BLE001
        log.warning("unknown detector skipped: %s", e)

    state["verified_findings"] = verified
    state["next_node"] = "reporter"
    return state


def report_node(state: AgentState) -> AgentState:
    """Produce a human-readable report summarizing the verified findings."""
    verified = state.get("verified_findings", [])
    lines = [f"# Report for target {state['target'].id}",
             f"Verified findings: {len(verified)}", ""]
    for f in verified:
        lines.append(f"- **{f.title}** ({f.severity.value}) — {f.category}")

    # Summarize external tool outputs (e.g. ZAP alerts) so the user sees real data
    # even when verifier finds no cross-corroboration to elevate to findings.
    tool_results = state.get("tool_results", [])
    if tool_results:
        lines.append("")
        lines.append("## 工具调用结果")
        for r in tool_results:
            tool = r.get("tool", "?")
            if "error" in r:
                lines.append(f"- {tool}: ✗ {r['error']}")
                continue
            out = r.get("output") or {}
            if tool == "zap":
                summary = _summarize_zap_output(out)
                if summary:
                    lines.append(f"- zap: {summary}")
            elif "findings" in r:
                lines.append(f"- {tool}: {r['findings']} findings")
            else:
                lines.append(f"- {tool}: 完成 ({_short_repr(out)})")

    state["report"] = "\n".join(lines)
    state["next_node"] = "END"
    return state


# ---- helpers ----

def _parse_plan(text: str) -> list[dict]:
    """Parse LLM-produced plan JSON, tolerating prose, code fences, and noise."""
    import json, re
    if not text:
        return []
    # Strip ```json ... ``` or ``` ... ``` fences if present.
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1)).get("steps", [])
        except json.JSONDecodeError:
            pass
    # Fall back to the first balanced JSON object in the text.
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
        return data.get("steps", [])
    except json.JSONDecodeError:
        return []


def _triage_is_severe(finding: Finding) -> bool:
    from pentest_agent_sdk.contracts import Severity
    return finding.severity in (Severity.high, Severity.critical)


def _summarize_zap_output(out: dict) -> str:
    """Render a one-line summary of a ZAP wrapper result for the report."""
    alerts = out.get("alerts") or []
    if not alerts and "num_alerts" in out:
        return f"扫描完成,共 {out['num_alerts']} 条 alert"
    if not alerts:
        return f"扫描已启动 (scan_id={out.get('scan_id', '?')})"
    counts: dict[str, int] = {}
    for a in alerts:
        r = a.get("risk", "?")
        counts[r] = counts.get(r, 0) + 1
    parts = [f"{k}×{v}" for k, v in sorted(counts.items(),
              key=lambda kv: -{'High':3,'Medium':2,'Low':1,'Informational':0}.get(kv[0],0))]
    return f"扫描完成,共 {len(alerts)} 条 alert ({' / '.join(parts)})"


def _short_repr(out: dict, maxlen: int = 80) -> str:
    s = repr(out)
    return s if len(s) <= maxlen else s[:maxlen] + "…"


# ---- LangGraph wiring (M1: 4-node linear graph, behaviorally equivalent
# to the old hand-rolled FSM. Send/fan-in is deferred to M2.) -------------

_compiled_app = None


def build_app():
    """Compile the LangGraph StateGraph for the 4-node pipeline.

    Cached at module level — the topology is static and graph compilation
    is non-trivial. Callers should treat the returned object as immutable.
    """
    global _compiled_app
    if _compiled_app is not None:
        return _compiled_app
    from langgraph.graph import StateGraph, START, END
    g: StateGraph = StateGraph(AgentState)
    g.add_node("planner", plan_node)
    g.add_node("router", route_node)
    g.add_node("verifier", verify_node)
    g.add_node("reporter", report_node)
    g.add_edge(START, "planner")
    g.add_edge("planner", "router")
    g.add_edge("router", "verifier")
    g.add_edge("verifier", "reporter")
    g.add_edge("reporter", END)
    _compiled_app = g.compile()
    return _compiled_app
