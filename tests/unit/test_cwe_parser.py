"""Unit tests for knowledge_base.cwe.parser.parse_cwec_xml.

Drives the parser via the small fixture in tests/fixtures/cwe_mini.xml
(CWE-707 Pillar, CWE-74 Class, CWE-79 Base) so the suite stays fast and
deterministic; full-file behaviour is exercised separately by a script.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.cwe.parser import parse_cwec_xml

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cwe_mini.xml"


def test_parses_three_entries():
    entries = parse_cwec_xml(FIXTURE)
    assert len(entries) == 3
    ids = {e.id for e in entries}
    assert ids == {"CWE-707", "CWE-74", "CWE-79"}


def test_abstraction_and_status():
    entries = {e.id: e for e in parse_cwec_xml(FIXTURE)}
    assert entries["CWE-707"].abstraction == "Pillar"
    assert entries["CWE-74"].abstraction == "Class"
    assert entries["CWE-79"].abstraction == "Base"
    assert entries["CWE-79"].status == "Stable"


def test_parent_chain():
    entries = {e.id: e for e in parse_cwec_xml(FIXTURE)}
    assert entries["CWE-707"].parents == []
    assert entries["CWE-74"].parents == ["CWE-707"]
    # CWE-79 has multiple ChildOf edges in real data (View 1000 and 1003 both
    # point to CWE-74); the parser must deduplicate to a single "CWE-74".
    assert "CWE-74" in entries["CWE-79"].parents
    assert entries["CWE-79"].parents.count("CWE-74") == 1


def test_peers_include_csrf():
    entries = {e.id: e for e in parse_cwec_xml(FIXTURE)}
    # CWE-79 in real data has PeerOf CWE-352 (CSRF), plus CanPrecede CWE-494.
    assert "CWE-352" in entries["CWE-79"].peers


def test_cwe79_has_rich_fields():
    entries = {e.id: e for e in parse_cwec_xml(FIXTURE)}
    e = entries["CWE-79"]
    assert e.name.startswith("Improper Neutralization of Input")
    assert e.description  # non-empty
    assert e.extended_description  # non-empty after itertext join
    assert len(e.consequences) >= 1
    assert len(e.mitigations) >= 1
    assert len(e.demonstrative_examples) >= 1
    # Consequence shape: scope and impact are lists (can repeat in source XML).
    c = e.consequences[0]
    assert "scope" in c and "impact" in c
    assert isinstance(c["scope"], list) and isinstance(c["impact"], list)


def test_demonstrative_example_body_is_markdown_string():
    entries = {e.id: e for e in parse_cwec_xml(FIXTURE)}
    ex = entries["CWE-79"].demonstrative_examples[0]
    assert isinstance(ex["body_markdown"], str)
    assert ex["body_markdown"]  # non-empty
