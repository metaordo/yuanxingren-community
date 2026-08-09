"""SQLite-backed CVE store for fast service-to-CVE queries."""
from __future__ import annotations
import sqlite3
from threading import Lock


class CveStore:
    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = Lock()
        self._ensure_schema()

    def _ensure_schema(self):
        with self._lock:
            db = sqlite3.connect(self._db_path)
            db.execute("""
                CREATE TABLE IF NOT EXISTS cve_entries (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    description_zh TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    vector_string TEXT,
                    affected_products TEXT,
                    affected_versions TEXT,
                    published TEXT,
                    updated TEXT
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_cve_products
                ON cve_entries(affected_products)
            """)
            db.commit()
            db.close()

    def bulk_insert(self, entries: list[dict]) -> int:
        count = 0
        with self._lock:
            db = sqlite3.connect(self._db_path)
            for e in entries:
                try:
                    db.execute("""
                        INSERT OR REPLACE INTO cve_entries
                        (cve_id, description, description_zh, cvss_score, severity,
                         vector_string, affected_products, affected_versions,
                         published, updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        e.get("cve_id", ""),
                        e.get("description", ""),
                        e.get("description_zh", ""),
                        e.get("cvss_score", 0.0),
                        e.get("severity", ""),
                        e.get("vector_string", ""),
                        e.get("affected_products", ""),
                        e.get("affected_versions", ""),
                        e.get("published", ""),
                        e.get("updated", ""),
                    ))
                    count += 1
                except Exception:
                    continue
            db.commit()
            db.close()
        return count

    def count(self) -> int:
        with self._lock:
            db = sqlite3.connect(self._db_path)
            n = db.execute("SELECT COUNT(*) FROM cve_entries").fetchone()[0]
            db.close()
        return n

    def search_services(self, services: list[dict]) -> list[dict]:
        """Find CVEs matching given service names.

        Args:
            services: [{"service": "nginx", "port": "80"}, ...]

        Returns:
            List of CVE entries ordered by CVSS score descending.
        """
        results: list[dict] = []
        seen_ids: set[str] = set()
        with self._lock:
            db = sqlite3.connect(self._db_path)
            db.row_factory = sqlite3.Row
            for svc in services:
                name = svc.get("service", "").lower()
                if not name:
                    continue
                rows = db.execute("""
                    SELECT * FROM cve_entries
                    WHERE LOWER(affected_products) LIKE ?
                    ORDER BY cvss_score DESC
                    LIMIT 50
                """, (f"%{name}%",)).fetchall()
                for r in rows:
                    d = dict(r)
                    if d["cve_id"] not in seen_ids:
                        seen_ids.add(d["cve_id"])
                        d["matched_service"] = name
                        d["matched_port"] = svc.get("port", "")
                        results.append(d)
            db.close()
        results.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return results

    def all(self) -> list[dict]:
        with self._lock:
            db = sqlite3.connect(self._db_path)
            db.row_factory = sqlite3.Row
            rows = db.execute("SELECT * FROM cve_entries").fetchall()
            result = [dict(r) for r in rows]
            db.close()
        return result
