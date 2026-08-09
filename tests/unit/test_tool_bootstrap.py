"""Tests for the external tool bootstrap: ensures Burp, Nmap, ZAP, Metasploit
are wrapped, registered, and enforce authorization scope before invocation."""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from backend import plugins as plugin_host
from backend.tools.bootstrap import bootstrap_external_tools, _ToolWrapper, _DictTarget


def test_bootstrap_registers_all_four_tools():
    # Clean slate-ish: re-bootstrap and check names
    bootstrap_external_tools(plugin_host)
    registered = {t.name for t in plugin_host.all_tools()}
    assert {"nmap", "burp", "zap", "metasploit"}.issubset(registered), \
        f"missing tools: {registered}"


def test_input_schemas_declare_target_and_scope():
    bootstrap_external_tools(plugin_host)
    for name in ("nmap", "burp", "zap", "metasploit"):
        tool = plugin_host.get_tool(name)
        assert tool is not None
        schema = tool.input_schema
        assert "target" in schema.get("properties", {})
        assert "auth_scope" in schema.get("properties", {})
        # Both are required to prevent accidental unscoped invocation
        assert "target" in schema.get("required", [])
        assert "auth_scope" in schema.get("required", [])


def test_invocation_outside_scope_is_rejected():
    bootstrap_external_tools(plugin_host)
    nmap = plugin_host.get_tool("nmap")
    args = {
        "target": {"id": "t1", "type": "url", "value": "https://evil.example/"},
        "auth_scope": {"hosts": ["*.allowed.com"], "cidrs": []},
        "options": {},
    }
    with pytest.raises(PermissionError):
        nmap.invoke(args)


def test_invocation_in_scope_passes_authz():
    """Authz check passes; actual nmap invocation may fail (no binary) but
    that's beyond the scope test — we only verify the gate."""
    bootstrap_external_tools(plugin_host)
    nmap = plugin_host.get_tool("nmap")
    args = {
        "target": {"id": "t1", "type": "domain", "value": "scanme.allowed.com"},
        "auth_scope": {"hosts": ["*.allowed.com"], "cidrs": []},
        "options": {},
    }
    # Either runs nmap (and may fail downstream) or fails for not-installed —
    # both are OK for this test. What we forbid is PermissionError.
    try:
        nmap.invoke(args)
    except PermissionError as e:
        pytest.fail(f"unexpected scope rejection: {e}")
    except Exception:
        pass


def test_burp_health_check_returns_status_object():
    """Burp adapter without config must not crash health_check."""
    bootstrap_external_tools(plugin_host)
    burp = plugin_host.get_tool("burp")
    health = burp.health_check()
    assert hasattr(health, "ok")
    # Burp without configured base_url + key should report not-ok
    assert health.ok is False
