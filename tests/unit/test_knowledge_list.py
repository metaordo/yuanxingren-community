"""Unit tests for GET /api/knowledge/list endpoint (route handler level)."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from knowledge_base.schema.entry import KnowledgeEntry, EntryType
from knowledge_base import ingestion as _ing
from backend.api import knowledge as knowledge_api


class _FakeUser:
    """Minimal stand-in for backend.auth.models.User."""
    id = 1
    username = "tester"


def _seed_entries() -> list[KnowledgeEntry]:
    return [
        KnowledgeEntry(id="r1", title="TCP seq", type=EntryType.paper,
                       category="TCP", year=2020, summary="t1",
                       attack_surface=["off-path"], mitigations=["isn"],
                       cves=["CVE-2016-5696"]),
        KnowledgeEntry(id="r2", title="TCP rfc", type=EntryType.rfc,
                       category="TCP", year=1981, summary="t2"),
        KnowledgeEntry(id="r3", title="DNS poison", type=EntryType.paper,
                       category="DNS", year=2008, summary="t3"),
        KnowledgeEntry(id="r4", title="General misc", type=EntryType.blog,
                       category="General", year=2022, summary="t4"),
    ]


def _install_entries(monkeypatch, entries):
    """Replace ingestion.all_entries() return for the duration of one test."""
    monkeypatch.setattr(_ing, "all_entries", lambda: list(entries))
    # The route imports `all_entries` by name at module import time; rebind
    # the symbol in the route module so the patch is visible to the handler.
    monkeypatch.setattr(knowledge_api, "all_entries", lambda: list(entries))


def test_list_returns_full_set(monkeypatch):
    _install_entries(monkeypatch, _seed_entries())
    out = knowledge_api.list_entries(category=None, entry_type=None,
                                      _user=_FakeUser())
    assert out["total"] == 4
    assert len(out["entries"]) == 4
    # Each entry must carry the full detail fields the UI relies on.
    e = out["entries"][0]
    assert {"id", "title", "type", "category", "year", "venue",
            "url", "summary", "attack_surface", "mitigations",
            "cves"}.issubset(e.keys())


def test_list_filters_by_category(monkeypatch):
    _install_entries(monkeypatch, _seed_entries())
    out = knowledge_api.list_entries(category="TCP", entry_type=None,
                                      _user=_FakeUser())
    assert out["total"] == 2
    assert all(e["category"] == "TCP" for e in out["entries"])


def test_list_filters_by_entry_type(monkeypatch):
    _install_entries(monkeypatch, _seed_entries())
    out = knowledge_api.list_entries(category=None, entry_type="RFC",
                                      _user=_FakeUser())
    assert out["total"] == 1
    assert out["entries"][0]["type"] == "RFC"


def test_list_combined_filter(monkeypatch):
    _install_entries(monkeypatch, _seed_entries())
    out = knowledge_api.list_entries(category="TCP", entry_type="Paper",
                                      _user=_FakeUser())
    assert out["total"] == 1
    assert out["entries"][0]["id"] == "r1"
