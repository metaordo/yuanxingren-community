"""Storage layer for CWE entries: bulk_insert idempotency, children reverse map,
read-side accessors. Uses pytest tmp_path to point PA_DATA_DIR at a fresh sqlite."""
from __future__ import annotations
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.fixture
def fresh_store(tmp_path, monkeypatch):
    """Run each test against an isolated SQLite file. Reload the storage
    module *after* PA_DATA_DIR is set so backend.db picks up the fresh path."""
    monkeypatch.setenv("PA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PA_JWT_SECRET", "x")

    # Drop cached imports so engine is created against the new path.
    # NOTE: do NOT clear knowledge_base.cwe.models — that re-registers the
    # SQLModel table on the shared metadata and raises InvalidRequestError.
    # Storage rebinds the engine on import, so clearing it is enough.
    for mod in list(sys.modules):
        if mod == "backend.db" or mod == "knowledge_base.cwe.storage":
            del sys.modules[mod]

    from backend.db import init_db  # noqa: E402
    init_db()
    from knowledge_base.cwe.storage import CweStore  # noqa: E402
    return CweStore()


def _seed_entries():
    from knowledge_base.cwe.schema import CweEntry
    return [
        CweEntry(id="CWE-707", name="Improper Neutralization",
                 abstraction="Pillar", status="Incomplete",
                 description="root pillar", parents=[]),
        CweEntry(id="CWE-74", name="Injection Class",
                 abstraction="Class", status="Incomplete",
                 description="class node", parents=["CWE-707"]),
        CweEntry(id="CWE-79", name="XSS",
                 abstraction="Base", status="Stable",
                 description="cross site scripting", parents=["CWE-74"],
                 peers=["CWE-352"],
                 consequences=[{"scope": ["Confidentiality"], "impact": ["Read"], "note": ""}],
                 mitigations=[{"phase": ["Implementation"], "strategy": "Input Validation",
                               "description": "Validate input", "effectiveness": "High"}]),
    ]


def test_bulk_insert_writes_rows_and_derives_children(fresh_store):
    n = fresh_store.bulk_insert(_seed_entries())
    assert n == 3
    assert fresh_store.count() == 3
    # children derived: CWE-707 -> [CWE-74]; CWE-74 -> [CWE-79]; CWE-79 -> []
    pillar = fresh_store.get("CWE-707")
    assert pillar is not None
    assert pillar.children == ["CWE-74"]
    cls = fresh_store.get("CWE-74")
    assert cls.children == ["CWE-79"]
    base = fresh_store.get("CWE-79")
    assert base.children == []


def test_bulk_insert_idempotent(fresh_store):
    fresh_store.bulk_insert(_seed_entries())
    again = fresh_store.bulk_insert(_seed_entries())
    assert again == 0
    assert fresh_store.count() == 3


def test_bulk_insert_force_replaces(fresh_store):
    fresh_store.bulk_insert(_seed_entries())
    from knowledge_base.cwe.schema import CweEntry
    new = [CweEntry(id="CWE-1", name="renamed", abstraction="Pillar",
                    status="Stable", description="x")]
    n = fresh_store.bulk_insert(new, force=True)
    assert n == 1
    assert fresh_store.count() == 1
    assert fresh_store.get("CWE-707") is None
    assert fresh_store.get("CWE-1") is not None


def test_get_pillars_only_returns_pillars(fresh_store):
    fresh_store.bulk_insert(_seed_entries())
    pillars = fresh_store.get_pillars()
    assert {p.id for p in pillars} == {"CWE-707"}


def test_get_children_resolves_full_entries(fresh_store):
    fresh_store.bulk_insert(_seed_entries())
    kids = fresh_store.get_children("CWE-707")
    assert {k.id for k in kids} == {"CWE-74"}
    assert kids[0].abstraction == "Class"


def test_get_accepts_id_with_or_without_prefix(fresh_store):
    fresh_store.bulk_insert(_seed_entries())
    assert fresh_store.get("CWE-79") is not None
    assert fresh_store.get("79") is not None  # normalized


def test_payload_round_trips(fresh_store):
    fresh_store.bulk_insert(_seed_entries())
    e = fresh_store.get("CWE-79")
    assert len(e.consequences) == 1
    assert e.consequences[0]["scope"] == ["Confidentiality"]
    assert e.mitigations[0]["strategy"] == "Input Validation"
    assert e.peers == ["CWE-352"]
