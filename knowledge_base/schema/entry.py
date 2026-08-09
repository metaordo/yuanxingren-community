"""Knowledge entry schema."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class EntryType(str, Enum):
    rfc = "RFC"
    paper = "Paper"
    cve = "CVE"
    report = "Report"
    blog = "Blog"
    book = "Book"
    tool = "Tool"


@dataclass
class KnowledgeEntry:
    id: str                    # e.g. "ref_021"
    title: str
    type: EntryType
    category: str              # TCP, IP, DNS, BGP, TLS, WiFi, 5G, ...
    year: int | None = None
    authors: list[str] = field(default_factory=list)
    venue: str | None = None   # IETF, USENIX, S&P, CCS, ...
    url: str | None = None
    summary: str = ""
    attack_surface: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    raw_text: str = ""
    embedding: list[float] = field(default_factory=list)
