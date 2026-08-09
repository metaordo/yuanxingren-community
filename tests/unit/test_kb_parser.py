"""Unit test for the references.md parser. Uses the real file if available."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.ingestion.references_parser import parse_file


def test_parses_at_least_some_entries():
    repo_root = Path(__file__).resolve().parents[2].parent
    refs = repo_root / "references.md"
    if not refs.exists():
        # Project layout test: still ensure import works
        return
    entries = list(parse_file(refs))
    assert len(entries) > 100, f"expected >100 entries, got {len(entries)}"
    sample = entries[0]
    assert sample.id.startswith("ref_")
    assert sample.title


def test_handles_empty_file(tmp_path):
    f = tmp_path / "empty.md"
    f.write_text("# Title\n\nno entries here\n")
    assert list(parse_file(f)) == []
