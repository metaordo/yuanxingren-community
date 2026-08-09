"""LLM direct audit: skip the heavy engines, let the LLM analyze the input
directly with knowledge-base context. Three sub-modes:

  1. code_auditor    — small code snippet code review
  2. protocol_auditor — pcap / traffic description
  3. config_auditor  — nginx / sshd / iptables / k8s yaml config

Each sub-mode follows the same pattern:
  - retrieve relevant knowledge entries
  - prompt the LLM with the input + retrieved context
  - return structured findings with explicit reference traceability
"""
from __future__ import annotations
import logging
from dataclasses import dataclass

from pentest_agent_sdk.contracts import Evidence, Finding, Severity
from ..backend.llm import Message
from ..backend.llm.router import call as llm_call
from ..knowledge_base import retriever

log = logging.getLogger(__name__)


_SYSTEM_GUARDRAIL = (
    "You are a security auditor. Cite specific references when claiming a "
    "vulnerability. If you have no evidence to support a claim, say 'uncertain' "
    "rather than guess. Output findings in JSON with fields: "
    "title, severity (info|low|medium|high|critical), category, description, "
    "references (list of knowledge_base ids)."
)


def _audit(input_text: str, kb_query: str, *,
           categories: list[str] | None = None,
           extra_system: str = "") -> list[Finding]:
    """Shared audit loop for the three sub-modes."""
    # Retrieve KB context
    kb_hits = []
    for cat in (categories or [None]):
        kb_hits.extend(retriever.search(kb_query, category=cat, top_k=5))
    kb_context = "\n".join(
        f"- [{h.id}] {h.title} ({h.type.value}, {h.year}): {h.summary[:200]}"
        for h in kb_hits
    ) or "(no matching knowledge base entries)"

    system = _SYSTEM_GUARDRAIL + ("\n\n" + extra_system if extra_system else "")
    user = (
        f"Reference material from knowledge base:\n{kb_context}\n\n"
        f"Input to audit:\n```\n{input_text}\n```\n\n"
        "Identify security issues. For each, cite the relevant reference id."
    )
    result = llm_call("triage",
                       [Message(role="system", content=system),
                        Message(role="user", content=user)],
                       max_tokens=2048)
    return _parse_findings(result.text)


def _parse_findings(text: str) -> list[Finding]:
    import json, re
    blocks = re.findall(r"\{[^{}]*\}", text, re.DOTALL)
    findings: list[Finding] = []
    for i, b in enumerate(blocks):
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            continue
        sev = data.get("severity", "info").lower()
        try:
            severity = Severity(sev)
        except ValueError:
            severity = Severity.info
        findings.append(Finding(
            id=f"llm-direct-{i}",
            title=data.get("title", "(untitled)"),
            severity=severity,
            category=data.get("category", "Unknown"),
            target_ref="direct",
            evidence=[Evidence(
                kind="llm_audit",
                summary=data.get("description", ""),
                confidence=0.5,  # explicit moderate confidence for LLM-only
            )],
            references=data.get("references", []),
        ))
    return findings


def audit_code(snippet: str, language: str | None = None) -> list[Finding]:
    extra = f"Language: {language}." if language else ""
    return _audit(snippet, kb_query=snippet[:200], extra_system=extra)


def audit_protocol(description: str) -> list[Finding]:
    return _audit(description, kb_query=description[:200],
                   categories=["TCP", "IP", "DNS", "BGP", "TLS", "QUIC"])


def audit_config(config_text: str, kind: str | None = None) -> list[Finding]:
    extra = f"Config kind: {kind}." if kind else ""
    return _audit(config_text, kb_query=(kind or "configuration"),
                   categories=["TLS", "HTTP"], extra_system=extra)
