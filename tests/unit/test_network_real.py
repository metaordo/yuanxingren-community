"""Tests for the network attack engine — focus on logic that doesn't need
network access: endpoint extraction and predictability scoring."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from pentest_agent_sdk.contracts import Target
from engines.network import NetworkAttackEngine


def test_endpoint_url():
    host, port = NetworkAttackEngine._extract_endpoint(
        Target(id="t", type="url", value="https://example.com/api"), {}
    )
    assert host == "example.com"
    assert port == 443


def test_endpoint_url_with_explicit_port():
    host, port = NetworkAttackEngine._extract_endpoint(
        Target(id="t", type="url", value="http://example.com:8080/x"), {}
    )
    assert host == "example.com"
    assert port == 8080


def test_endpoint_protocol():
    host, port = NetworkAttackEngine._extract_endpoint(
        Target(id="t", type="protocol", value="tcp://10.0.0.1:9000"), {}
    )
    assert host == "10.0.0.1"
    assert port == 9000


def test_endpoint_cidr_picks_first_host():
    host, port = NetworkAttackEngine._extract_endpoint(
        Target(id="t", type="ip", value="10.0.0.0/24"), {"port": 22}
    )
    # First usable host of 10.0.0.0/24 is 10.0.0.1
    assert host == "10.0.0.1"
    assert port == 22


def test_predictability_constant_delta_is_one():
    samples = [1000, 1100, 1200, 1300, 1400]
    score, _ = NetworkAttackEngine._predictability(samples)
    assert score == 1.0


def test_predictability_random_is_low():
    # Wildly varying deltas → low score
    samples = [1, 1_000_000_000, 50, 999_999, 7]
    score, _ = NetworkAttackEngine._predictability(samples)
    assert score < 0.5


def test_few_samples_returns_no_findings_path():
    eng = NetworkAttackEngine()
    eng.setup({"probe_count": 0})
    # Empty samples list → predictability not called; engine returns empty
    findings = eng._probe_isn("127.0.0.1", 0, Target(id="t", type="ip", value="127.0.0.1"))
    assert findings == []
