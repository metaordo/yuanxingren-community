"""Unknown (0-day) detection pipeline: score -> synthesize PoC -> sandbox -> draft."""
from __future__ import annotations
import logging
from dataclasses import dataclass

from pentest_agent_sdk.contracts import Finding, Severity
from .novelty_scorer import NoveltyScore, score as score_novelty
from .poc_synthesizer import PoC, synthesize
from .sandbox_runner import SandboxResult, run_python_poc
from .disclosure import DisclosureDraft, draft_for

log = logging.getLogger(__name__)

# Novelty threshold above which a finding is treated as a 0-day candidate.
# Lowered to 0.5 in M4 because the rule-based novelty_scorer (KB match
# heuristic) tends to land most novel-looking findings in the 0.5-0.7
# band. The real threshold tuning happens when M5 swaps in an LLM-based
# novelty scorer.
NOVELTY_THRESHOLD = 0.5


@dataclass
class UnknownReport:
    finding: Finding
    novelty: NoveltyScore
    poc: PoC | None = None
    sandbox: SandboxResult | None = None
    disclosure: DisclosureDraft | None = None


def process(finding: Finding, *, sandbox: bool = True,
            draft_disclosure: bool = True) -> UnknownReport:
    """Classify a finding; for novel ones, synthesize PoC and optionally sandbox."""
    novelty = score_novelty(finding)
    report = UnknownReport(finding=finding, novelty=novelty)
    if novelty.value < NOVELTY_THRESHOLD:
        return report

    # High-novelty finding — promote through the 0-day pipeline
    log.info("finding %s is novel (%.2f), running 0-day pipeline",
             finding.id, novelty.value)
    report.poc = synthesize(finding)
    if sandbox and report.poc:
        report.sandbox = run_python_poc(report.poc.source)
        if report.sandbox.triggered:
            # Upgrade severity on confirmed triggerable 0-day candidates
            finding.severity = max(finding.severity, Severity.high,
                                    key=_severity_rank)
    if draft_disclosure:
        report.disclosure = draft_for(finding)
    return report


def _severity_rank(s: Severity) -> int:
    order = {Severity.info: 0, Severity.low: 1, Severity.medium: 2,
             Severity.high: 3, Severity.critical: 4}
    return order.get(s, 0)
