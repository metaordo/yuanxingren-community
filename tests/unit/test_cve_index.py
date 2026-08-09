"""Unit tests for CVE knowledge base module."""
from __future__ import annotations
import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest


class TestCveParser:
    def test_parse_single_cve_item(self):
        from backend.knowledge_base.cve.parser import parse_cve_item
        item = {
            "cve": {
                "id": "CVE-2021-12345",
                "descriptions": [
                    {"lang": "en", "value": "Buffer overflow in nginx 1.18.0"},
                    {"lang": "zh", "value": "缓冲区溢出漏洞"}
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        }
                    }]
                }
            },
            "lastModifiedDate": "2021-06-15T12:00:00.000"
        }
        entry = parse_cve_item(item)
        assert entry["cve_id"] == "CVE-2021-12345"
        assert entry["cvss_score"] == 7.5
        assert entry["severity"] == "HIGH"
        assert "nginx" in entry["description"]
        assert entry["description_zh"] == "缓冲区溢出漏洞"

    def test_parse_item_no_cvss(self):
        from backend.knowledge_base.cve.parser import parse_cve_item
        item = {
            "cve": {
                "id": "CVE-2020-99999",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {}
            },
            "lastModifiedDate": "2020-01-01T00:00:00.000"
        }
        entry = parse_cve_item(item)
        assert entry["cvss_score"] == 0.0
        assert entry["severity"] == "UNKNOWN"


class TestCveStorage:
    def test_insert_and_search(self):
        from backend.knowledge_base.cve.storage import CveStore
        db_path = os.path.join(tempfile.mkdtemp(), "test_cve.db")
        store = CveStore(db_path)
        store.bulk_insert([
            {"cve_id": "CVE-2021-111", "cvss_score": 7.5, "severity": "HIGH",
             "description": "nginx vuln", "description_zh": "",
             "affected_products": "nginx", "affected_versions": "1.18.0",
             "vector_string": "", "published": "2021-01-01", "updated": "2021-01-01"},
        ])
        assert store.count() == 1
        results = store.search_services([
            {"service": "nginx"},
        ])
        assert len(results) >= 1

    def test_empty_search(self):
        from backend.knowledge_base.cve.storage import CveStore
        db_path = os.path.join(tempfile.mkdtemp(), "test_cve.db")
        store = CveStore(db_path)
        results = store.search_services([{"service": "nonexistent_service_xyz"}])
        assert results == []


class TestCveRetriever:
    def test_search_by_service(self):
        from backend.knowledge_base.cve.storage import CveStore
        from backend.knowledge_base.cve.retriever import CveRetriever
        db_path = os.path.join(tempfile.mkdtemp(), "test_cve.db")
        store = CveStore(db_path)
        store.bulk_insert([
            {"cve_id": "CVE-2022-001", "cvss_score": 9.8, "severity": "CRITICAL",
             "description": "OpenSSH remote code execution", "description_zh": "OpenSSH 远程代码执行",
             "affected_products": "openssh", "affected_versions": "8.9",
             "vector_string": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "published": "2022-01-01", "updated": "2022-01-01"},
        ])
        retriever = CveRetriever(store)
        results = retriever.search("openssh", "8.9")
        assert len(results) >= 1
        assert results[0]["cve_id"] == "CVE-2022-001"
