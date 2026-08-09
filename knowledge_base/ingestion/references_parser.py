"""Parse references.md into structured KnowledgeEntry records."""
from __future__ import annotations
import re
from pathlib import Path
from typing import Iterator
from ..schema.entry import KnowledgeEntry, EntryType


_SECTION_RE = re.compile(r"^## (.+)$", re.MULTILINE)
_ENTRY_RE = re.compile(
    r"^\[(\d+)\]\s+(.+?)(?:,\s*\"(.+?)\")?\s*(?:,\s*(.+?))?(?:\.\s*\[(.+?)\])?\s*(?:\[Online\])?",
    re.MULTILINE
)


def parse_file(path: Path) -> Iterator[KnowledgeEntry]:
    """Yield KnowledgeEntry objects from references.md."""
    text = path.read_text(encoding="utf-8")
    sections = _SECTION_RE.split(text)
    # sections[0] is preamble, then alternating (section_title, section_body)
    current_category = "General"
    for i in range(1, len(sections), 2):
        section_title = sections[i].strip()
        section_body = sections[i + 1] if i + 1 < len(sections) else ""
        # Infer category from section title
        current_category = _infer_category(section_title)
        for entry in _parse_section(section_body, current_category):
            yield entry


def _infer_category(title: str) -> str:
    """Map section heading to a category tag."""
    lower = title.lower()
    if "tcp" in lower:
        return "TCP"
    if "ip" in lower and "ipv6" not in lower:
        return "IP"
    if "ipv6" in lower:
        return "IPv6"
    if "dns" in lower:
        return "DNS"
    if "wi-fi" in lower or "wireless" in lower or "wifi" in lower:
        return "WiFi"
    if "dos" in lower or "ddos" in lower:
        return "DoS"
    if "bgp" in lower or "routing" in lower:
        return "BGP"
    if "nat" in lower:
        return "NAT"
    if "web" in lower or "http" in lower:
        return "HTTP"
    if "vpn" in lower or "tunnel" in lower:
        return "VPN"
    if "quic" in lower:
        return "QUIC"
    if "5g" in lower or "蜂窝" in lower:
        return "5G"
    if "bluetooth" in lower or "蓝牙" in lower:
        return "Bluetooth"
    if "iot" in lower:
        return "IoT"
    if "tls" in lower or "ssl" in lower:
        return "TLS"
    if "fuzzing" in lower or "形式化" in lower:
        return "Fuzzing"
    if "sdn" in lower:
        return "SDN"
    return "General"


def _parse_section(body: str, category: str) -> Iterator[KnowledgeEntry]:
    """Extract individual entries from a section body."""
    lines = body.strip().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line or line.startswith("#"):
            i += 1
            continue
        # Check if this is a reference entry [N] ...
        m = re.match(r"^\[(\d+)\]\s+(.+)", line)
        if not m:
            i += 1
            continue
        ref_id = m.group(1)
        rest = m.group(2)
        # Accumulate continuation lines (indented or starting with ">")
        full_text = rest
        i += 1
        while i < len(lines):
            nxt = lines[i]
            if nxt.startswith((" ", "\t", ">")):
                full_text += " " + nxt.strip()
                i += 1
            else:
                break
        entry = _parse_entry(ref_id, full_text, category)
        if entry:
            yield entry


def _parse_entry(ref_id: str, text: str, category: str) -> KnowledgeEntry | None:
    """Parse a single reference line into a KnowledgeEntry."""
    # Detect type markers
    entry_type = EntryType.paper
    if "[RFC]" in text or "RFC " in text:
        entry_type = EntryType.rfc
    elif "[CVE]" in text or "CVE-" in text:
        entry_type = EntryType.cve
    elif "[Book]" in text:
        entry_type = EntryType.book
    elif "[Report]" in text:
        entry_type = EntryType.report
    elif "[Blog]" in text or "[Tool]" in text:
        entry_type = EntryType.blog
    elif "[Phrack]" in text or "[BH]" in text or "[DC]" in text:
        entry_type = EntryType.blog

    # Extract URL
    url_match = re.search(r"https?://[^\s\]]+", text)
    url = url_match.group(0) if url_match else None

    # Extract year (4-digit number)
    year_match = re.search(r"\b(19|20)\d{2}\b", text)
    year = int(year_match.group(0)) if year_match else None

    # Title is typically in quotes or after author names
    title_match = re.search(r'"([^"]+)"', text)
    title = title_match.group(1) if title_match else text[:100]

    return KnowledgeEntry(
        id=f"ref_{ref_id}",
        title=title,
        type=entry_type,
        category=category,
        year=year,
        url=url,
        summary=text[:500],  # truncate for now
        raw_text=text,
    )
