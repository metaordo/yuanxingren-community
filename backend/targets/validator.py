"""Enforce that a target falls inside the user's declared authorization scope."""
from __future__ import annotations
import fnmatch
import ipaddress
from typing import Iterable
from urllib.parse import urlparse
from .models import TargetType, Target
from .parser import ParsedTarget


class AuthorizationError(PermissionError):
    pass


def _host_in_allow(host: str, allow_hosts: Iterable[str]) -> bool:
    host = host.lower()
    for pattern in allow_hosts:
        pattern = pattern.lower().strip()
        if not pattern:
            continue
        if pattern == host:
            return True
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
        if fnmatch.fnmatch(host, pattern):
            return True
    return False


def _ip_in_cidrs(ip_or_cidr: str, allow_cidrs: Iterable[str]) -> bool:
    try:
        target_net = ipaddress.ip_network(ip_or_cidr, strict=False)
    except ValueError:
        return False
    for cidr in allow_cidrs:
        try:
            allowed = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        if target_net.subnet_of(allowed):
            return True
    return False


def validate_against_scope(parsed: ParsedTarget,
                           allow_hosts: list[str],
                           allow_cidrs: list[str]) -> None:
    """Raise AuthorizationError if the parsed target is outside the allowlist.

    Empty allow lists mean nothing is permitted by that channel; you must have
    at least one match for either hosts or CIDRs (depending on target type).
    """
    if parsed.type is TargetType.url:
        host = urlparse(parsed.value).hostname or ""
        if not host:
            raise AuthorizationError("URL has no host")
        if not _host_in_allow(host, allow_hosts):
            raise AuthorizationError(f"host {host!r} not in authorized scope")
        return
    if parsed.type is TargetType.domain:
        if not _host_in_allow(parsed.value, allow_hosts):
            raise AuthorizationError(f"domain {parsed.value!r} not authorized")
        return
    if parsed.type is TargetType.ip:
        # Check both hosts (single-IP entries) and CIDRs
        if _host_in_allow(parsed.value, allow_hosts):
            return
        if _ip_in_cidrs(parsed.value, allow_cidrs):
            return
        raise AuthorizationError(f"address {parsed.value!r} not in authorized hosts or CIDRs")
    if parsed.type is TargetType.protocol:
        host = urlparse(parsed.value).hostname or ""
        if _is_ip_literal(host):
            if not _ip_in_cidrs(host, allow_cidrs):
                raise AuthorizationError(f"protocol endpoint {host!r} not in CIDRs")
        else:
            if not _host_in_allow(host, allow_hosts):
                raise AuthorizationError(f"protocol endpoint host {host!r} not authorized")
        return
    # binary / pcap are file uploads — authorization is implicit by file ownership
    return


def _is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def assert_authorized(target: Target) -> None:
    if not target.authorized:
        raise AuthorizationError("target lacks user-confirmed authorization")
