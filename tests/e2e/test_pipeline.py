"""Smoke test: orchestrator runs end-to-end with mocked LLM and engines.

Avoids real network, real LLM calls, and the SQL database.
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from unittest.mock import patch
from pentest_agent_sdk.contracts import (
    Capability, Evidence, Finding, HealthStatus, Severity, Target,
)
from backend import plugins as plugin_host
from backend.orchestrator import run_pipeline


class _MockEngine:
    name = "mock_engine"
    version = "0.1.0"
    capabilities = [Capability.static_analysis]

    def setup(self, _config):
        pass

    def run(self, target, _options):
        return [
            Finding(id="m1", title="mock SQLi", severity=Severity.high,
                    category="SQLi", target_ref=target.id,
                    evidence=[Evidence(kind="mock", summary="ok")]),
            # second engine-style finding to exercise cross-validation
            Finding(id="m2", title="mock SQLi confirm", severity=Severity.high,
                    category="SQLi", target_ref=target.id,
                    evidence=[Evidence(kind="mock", summary="confirm")]),
        ]

    def health_check(self):
        return HealthStatus(ok=True, version=self.version)


def test_pipeline_smoke():
    plugin_host.register_engine(_MockEngine())

    # Mock LLM planner to return a deterministic plan
    fake_plan_text = '{"steps": [{"tool": "mock_engine", "args": {}}]}'
    fake_result = type("R", (), {
        "text": fake_plan_text,
        "usage": type("U", (), {"input_tokens": 0, "output_tokens": 0})(),
    })()

    with patch("backend.orchestrator.graph.llm_call",
                return_value=fake_result):
        target = Target(id="t1", type="url", value="https://example.com")
        out = run_pipeline("test analysis", target)

    assert out["plan"], "planner should produce a plan"
    assert any(f["category"] == "SQLi" for f in out["verified_findings"]), \
        "cross-validation should keep duplicate-category findings"
    assert "Verified findings" in out["report"]
