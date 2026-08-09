"""Responsible disclosure draft generation."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta

from pentest_agent_sdk.contracts import Finding


@dataclass
class DisclosureDraft:
    vendor: str
    summary: str
    impact: str
    mitigation: str
    embargo_until: datetime
    cve_request_draft: str
    body: str


def draft_for(finding: Finding, vendor: str = "<vendor>") -> DisclosureDraft:
    """Produce a vendor-facing disclosure template following CERT/CC 90-day norm."""
    embargo = datetime.utcnow() + timedelta(days=90)
    summary = f"{finding.title} in {vendor} products"
    impact = (
        f"Severity: {finding.severity.value}. Category: {finding.category}. "
        f"Number of evidence items: {len(finding.evidence)}."
    )
    mitigation = (
        "Please acknowledge receipt within 7 days. "
        "A coordinated disclosure date has been tentatively set 90 days out."
    )
    body = (
        f"Subject: [Security] {summary}\n\n"
        f"Dear {vendor} security team,\n\n"
        f"We have discovered a potential vulnerability during authorized testing. "
        f"Below is the preliminary report.\n\n"
        f"Summary: {finding.title}\n"
        f"Category: {finding.category}\n"
        f"Severity: {finding.severity.value}\n"
        f"Evidence items: {len(finding.evidence)}\n\n"
        f"{mitigation}\n\n"
        f"Regards,\nPentest Agent (on behalf of an authorized operator)\n"
    )
    cve_request_draft = (
        f"[CNA request]\n"
        f"Vendor: {vendor}\n"
        f"Affected product: TBD\n"
        f"Vulnerability type: {finding.category} ({finding.cwe or 'CWE TBD'})\n"
        f"Brief description: {finding.title}\n"
        f"Discoverer: Pentest Agent\n"
    )
    return DisclosureDraft(
        vendor=vendor,
        summary=summary,
        impact=impact,
        mitigation=mitigation,
        embargo_until=embargo,
        cve_request_draft=cve_request_draft,
        body=body,
    )
