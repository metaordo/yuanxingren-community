"""Unit tests for enhanced Nmap adapter."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest
from backend.tools.external_pentest.adapters.nmap import NmapAdapter


class TestNmapPhaseResultParsing:
    def test_parse_phase1_port_scan(self):
        """Parse minimal nmap XML with one host and two ports."""
        xml = """<?xml version="1.0"?>
<nmaprun>
<host>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx" version="1.24.0"/>
    </port>
  </ports>
</host>
</nmaprun>"""
        adapter = NmapAdapter()
        result = adapter._parse_xml(xml)
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["ip"] == "192.168.1.1"
        assert len(host["ports"]) == 2
        assert host["ports"][0]["service"] == "ssh"

    def test_parse_empty_xml_no_hosts(self):
        xml = """<?xml version="1.0"?><nmaprun></nmaprun>"""
        adapter = NmapAdapter()
        result = adapter._parse_xml(xml)
        assert result == {"hosts": []}

    def test_extract_services_for_cve(self):
        """The helper that builds a service list for CVE lookup."""
        ports_data = [
            {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh"},
            {"port": "80", "protocol": "tcp", "state": "open", "service": "http"},
        ]
        from backend.tools.external_pentest.adapters.nmap import _services_from_ports
        svcs = _services_from_ports(ports_data)
        assert len(svcs) == 2
        assert {"service": "ssh", "port": "22"} in svcs
