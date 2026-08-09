"""CWE API route handlers — direct call (no TestClient).

Uses pytest tmp_path to isolate the SQLite DB and seeds the in-memory store
with a small fixture. Auth is bypassed by passing a stub user object.
"""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


class _FakeUser:
    id = 1
    username = "tester"


class _FakeAdmin:
    id = 2
    username = "admin"


@pytest.fixture
def cwe_api(tmp_path, monkeypatch):
    """Fresh DB + cwe modules + seeded store."""
    monkeypatch.setenv("PA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PA_JWT_SECRET", "x")
    # Drop cached modules so engine is re-created against tmp_path.
    for mod in list(sys.modules):
        if mod.startswith("backend.db") or mod.startswith("backend.api.cwe") \
                or mod.startswith("knowledge_base.cwe.storage") \
                or mod.startswith("knowledge_base.cwe.retriever"):
            del sys.modules[mod]
    # Critically, do NOT drop knowledge_base.cwe.models — re-importing it would
    # re-register the table on SQLModel.metadata and raise InvalidRequestError.
    from backend.db import init_db
    init_db()
    from knowledge_base.cwe.schema import CweEntry
    from knowledge_base.cwe.storage import store as cwe_store
    from knowledge_base.cwe import retriever as cwe_retriever
    from backend.api import cwe as cwe_api_mod

    seed = [
        CweEntry(id="CWE-707", name="Improper Neutralization", abstraction="Pillar",
                 status="Incomplete", description="root pillar covering injection"),
        CweEntry(id="CWE-74", name="Injection Class", abstraction="Class",
                 status="Incomplete", parents=["CWE-707"],
                 description="generic injection class"),
        CweEntry(id="CWE-79", name="Cross-site Scripting", abstraction="Base",
                 status="Stable", parents=["CWE-74"], peers=["CWE-352"],
                 description="improper neutralization of input during web page generation",
                 consequences=[{"scope": ["Confidentiality"], "impact": ["Read"], "note": ""}]),
    ]
    cwe_store.bulk_insert(seed, force=True)
    cwe_retriever.index_all(cwe_store.all())
    return cwe_api_mod


def test_tree_roots_returns_only_pillars(cwe_api):
    out = cwe_api.tree_roots(_user=_FakeUser())
    ids = {r["id"] for r in out["roots"]}
    assert ids == {"CWE-707"}


def test_list_by_parent_returns_children(cwe_api):
    out = cwe_api.list_entries(parent_id="CWE-707", abstraction=None,
                               status=None, _user=_FakeUser())
    ids = {e["id"] for e in out["entries"]}
    assert "CWE-74" in ids
    assert out["total"] >= 1


def test_list_by_abstraction(cwe_api):
    out = cwe_api.list_entries(abstraction="Base", parent_id=None,
                               status=None, _user=_FakeUser())
    assert all(e["abstraction"] == "Base" for e in out["entries"])
    assert out["total"] >= 1


def test_search_finds_xss(cwe_api):
    out = cwe_api.search(q="cross site scripting", abstraction=None,
                         status=None, parent_id=None, top_k=5,
                         _user=_FakeUser())
    ids = [h["id"] for h in out["hits"]]
    assert "CWE-79" in ids


def test_detail_returns_full_payload(cwe_api):
    out = cwe_api.detail(cwe_id="CWE-79", _user=_FakeUser())
    e = out["entry"]
    assert e["id"] == "CWE-79"
    assert e["abstraction"] == "Base"
    assert e["parents"] == ["CWE-74"]
    assert "CWE-352" in e["peers"]
    # rich detail fields present
    assert isinstance(e["consequences"], list) and len(e["consequences"]) == 1


def test_detail_accepts_bare_number(cwe_api):
    out = cwe_api.detail(cwe_id="79", _user=_FakeUser())
    assert out["entry"]["id"] == "CWE-79"


def test_detail_404(cwe_api):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as excinfo:
        cwe_api.detail(cwe_id="CWE-99999", _user=_FakeUser())
    assert excinfo.value.status_code == 404


def test_node_shape(cwe_api):
    out = cwe_api.tree_roots(_user=_FakeUser())
    node = out["roots"][0]
    # Light shape — no detail blob
    assert set(node.keys()) == {"id", "name", "abstraction", "status", "has_children", "parents"}
    assert node["has_children"] is True   # CWE-707 has CWE-74 child


def test_refresh_admin_only_calls_pipeline(cwe_api, monkeypatch, tmp_path):
    # Point PA_CWE_XML at the mini fixture so refresh has something to parse.
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "cwe_mini.xml"
    monkeypatch.setenv("PA_CWE_XML", str(fixture))
    out = cwe_api.refresh(_admin=_FakeAdmin())
    assert out["refreshed"] >= 1
    assert "cwe_mini.xml" in out["source"]
