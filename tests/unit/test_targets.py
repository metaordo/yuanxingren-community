"""Unit tests for target parsing and authorization scope."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pytest

from backend.targets.parser import parse, ParseError, ParsedTarget
from backend.targets.models import TargetType
from backend.targets.validator import (
    validate_against_scope, AuthorizationError,
)


class TestParser:
    def test_url(self):
        assert parse("https://example.com/api").type is TargetType.url

    def test_ip(self):
        assert parse("192.168.1.100").type is TargetType.ip

    def test_cidr(self):
        assert parse("10.0.0.0/24").type is TargetType.ip

    def test_domain(self):
        assert parse("example.com").type is TargetType.domain

    def test_protocol_endpoint(self):
        assert parse("tcp://host.example.com:9000").type is TargetType.protocol

    def test_host_port_treated_as_protocol(self):
        assert parse("host.example.com:9000").type is TargetType.protocol

    def test_empty_raises(self):
        with pytest.raises(ParseError):
            parse("")

    def test_invalid_raises(self):
        with pytest.raises(ParseError):
            parse("!!! not a target !!!")


class TestScopeValidator:
    def test_url_in_scope(self):
        p = ParsedTarget(TargetType.url, "https://api.example.com/foo")
        validate_against_scope(p, ["*.example.com"], [])

    def test_url_out_of_scope(self):
        p = ParsedTarget(TargetType.url, "https://evil.com/")
        with pytest.raises(AuthorizationError):
            validate_against_scope(p, ["*.example.com"], [])

    def test_ip_in_cidr(self):
        p = ParsedTarget(TargetType.ip, "10.0.0.5")
        validate_against_scope(p, [], ["10.0.0.0/24"])

    def test_ip_out_of_cidr(self):
        p = ParsedTarget(TargetType.ip, "192.168.1.5")
        with pytest.raises(AuthorizationError):
            validate_against_scope(p, [], ["10.0.0.0/24"])

    def test_empty_scope_denies_everything(self):
        p = ParsedTarget(TargetType.domain, "example.com")
        with pytest.raises(AuthorizationError):
            validate_against_scope(p, [], [])
