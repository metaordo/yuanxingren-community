"""CVE retriever: query interface for the orchestrator and API layer."""
from __future__ import annotations
from .storage import CveStore


class CveRetriever:
    def __init__(self, store: CveStore):
        self._store = store

    def search(self, service: str, version: str | None = None) -> list[dict]:
        """Search CVEs for a specific service, optionally filtering by version.

        The version filtering is fuzzy — a CVE matches if its affected_versions
        field contains the given version string or is empty (unknown version range).
        """
        all_results = self._store.search_services([{"service": service}])
        if not version:
            return all_results
        # Fuzzy version filter
        filtered = []
        for r in all_results:
            affected = (r.get("affected_versions") or "").lower()
            ver = version.lower()
            if not affected or ver in affected:
                filtered.append(r)
        return filtered or all_results

    def search_batch(self, services: list[dict]) -> list[dict]:
        """Search CVEs for a batch of services.

        Args:
            services: [{"service": "nginx", "port": "80", "version": "1.18"}, ...]
        """
        return self._store.search_services(services)
