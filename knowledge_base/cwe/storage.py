"""SQLite-backed CWE storage with optional in-memory cache.

bulk_insert() is the only write entrypoint and is idempotent: by default it
skips when ``cwe_entries`` already has rows; pass ``force=True`` to wipe and
re-ingest. Writes happen inside a single Session/transaction so a 1000-row
ingest is one fsync, not a thousand.

Reads (get / list_by_abstraction / get_pillars / get_children / all / count)
are served from a lazy in-memory cache populated on first access. The cache
is invalidated on bulk_insert(force=True). All read paths going through the
cache return defensive copies — callers may freely mutate the returned
CweEntry without poisoning the cache.

ID normalization accepts ``"79"``, ``"CWE-79"`` and ``"cwe-79"`` uniformly.
"""
from __future__ import annotations

from typing import Iterable

from sqlmodel import Session, select, delete

from backend.db import engine

from .models import CweEntryRow
from .schema import CweEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# The 7 detail fields that round-trip through CweEntryRow.payload (instead of
# their own columns) — kept flat so the schema stays small and BM25-cheap.
_PAYLOAD_KEYS = (
    "consequences",
    "mitigations",
    "detection_methods",
    "demonstrative_examples",
    "applicable_platforms",
    "capec_ids",
    "references",
)


def _normalize_id(s: str) -> str:
    """'79' / 'cwe-79' / ' CWE-79 '  ->  'CWE-79'."""
    s = (s or "").strip().upper()
    if not s:
        return s
    if s.startswith("CWE-"):
        return s
    return f"CWE-{s}"


def _entry_to_row(e: CweEntry) -> CweEntryRow:
    payload = {k: getattr(e, k) for k in _PAYLOAD_KEYS}
    return CweEntryRow(
        id=e.id,
        name=e.name,
        abstraction=e.abstraction,
        structure=e.structure,
        status=e.status,
        description=e.description,
        extended_description=e.extended_description,
        likelihood=e.likelihood,
        parents=list(e.parents),
        children=list(e.children),
        peers=list(e.peers),
        payload=payload,
    )


def _row_to_entry(r: CweEntryRow) -> CweEntry:
    payload = r.payload or {}
    return CweEntry(
        id=r.id,
        name=r.name,
        abstraction=r.abstraction,
        structure=r.structure or "Simple",
        status=r.status,
        description=r.description or "",
        extended_description=r.extended_description or "",
        likelihood=r.likelihood,
        parents=list(r.parents or []),
        children=list(r.children or []),
        peers=list(r.peers or []),
        consequences=list(payload.get("consequences", []) or []),
        mitigations=list(payload.get("mitigations", []) or []),
        detection_methods=list(payload.get("detection_methods", []) or []),
        demonstrative_examples=list(payload.get("demonstrative_examples", []) or []),
        applicable_platforms=dict(payload.get("applicable_platforms", {}) or {}),
        capec_ids=list(payload.get("capec_ids", []) or []),
        references=list(payload.get("references", []) or []),
    )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class CweStore:
    """SQLite-backed CWE storage with a lazy in-memory cache."""

    def __init__(self) -> None:
        self._cache: dict[str, CweEntry] | None = None

    # ------------------------------------------------------------------ writes

    def bulk_insert(
        self,
        entries: Iterable[CweEntry],
        *,
        force: bool = False,
    ) -> int:
        """Insert all entries, deriving children from parents. Returns count.

        - If table non-empty and force=False: no-op, returns 0.
        - If force=True: DELETE all rows first, then insert.
        - children[id] = inverse of parents (built once before write).
        """
        entries = list(entries)
        with Session(engine) as session:
            existing = session.exec(select(CweEntryRow.id).limit(1)).first()
            if existing is not None and not force:
                return 0
            if force:
                session.exec(delete(CweEntryRow))
                session.commit()

            # Reverse parent map, computed in-memory before any write.
            child_map: dict[str, list[str]] = {}
            for e in entries:
                for p in e.parents:
                    child_map.setdefault(p, []).append(e.id)

            for e in entries:
                e.children = list(child_map.get(e.id, []))
                session.add(_entry_to_row(e))
            session.commit()

        # Force-replace must invalidate the cache; first-time inserts also
        # clear it so the next read reflects what we just wrote.
        self._cache = None
        return len(entries)

    # ------------------------------------------------------------------ reads

    def _ensure_cache(self) -> dict[str, CweEntry]:
        if self._cache is not None:
            return self._cache
        with Session(engine) as session:
            rows = session.exec(select(CweEntryRow)).all()
        self._cache = {r.id: _row_to_entry(r) for r in rows}
        return self._cache

    def get(self, cwe_id: str) -> CweEntry | None:
        cache = self._ensure_cache()
        entry = cache.get(_normalize_id(cwe_id))
        if entry is None:
            return None
        # Defensive copy so callers can mutate freely.
        return _row_to_entry(_entry_to_row(entry))

    def list_by_abstraction(self, abstraction: str) -> list[CweEntry]:
        cache = self._ensure_cache()
        return [
            _row_to_entry(_entry_to_row(e))
            for e in cache.values()
            if e.abstraction == abstraction
        ]

    def get_pillars(self) -> list[CweEntry]:
        return self.list_by_abstraction("Pillar")

    def get_children(self, parent_id: str) -> list[CweEntry]:
        parent = self.get(parent_id)
        if parent is None:
            return []
        cache = self._ensure_cache()
        out: list[CweEntry] = []
        for child_id in parent.children:
            child = cache.get(child_id)
            if child is not None:
                out.append(_row_to_entry(_entry_to_row(child)))
        return out

    def all(self) -> list[CweEntry]:
        cache = self._ensure_cache()
        return [_row_to_entry(_entry_to_row(e)) for e in cache.values()]

    def count(self) -> int:
        # Count is read-through to the DB so it stays correct even if the
        # cache hasn't been built yet (avoids a full scan just to size).
        with Session(engine) as session:
            return len(session.exec(select(CweEntryRow.id)).all())


store = CweStore()
