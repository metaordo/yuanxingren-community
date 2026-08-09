"""Parse user-supplied target strings into the canonical TargetType."""
from __future__ import annotations
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse
from .models import TargetType

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")
_PROTOCOL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/\s]+)")


@dataclass
class ParsedTarget:
    type: TargetType
    value: str  # canonical form


class ParseError(ValueError):
    pass


def _is_ip_or_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def parse(raw: str, hint: str | None = None) -> ParsedTarget:
    """Detect target type. `hint` may be one of TargetType values to force interpretation."""
    s = (raw or "").strip()
    if not s:
        raise ParseError("empty target")

    if hint == TargetType.binary.value:
        return ParsedTarget(TargetType.binary, s)
    if hint == TargetType.pcap.value:
        return ParsedTarget(TargetType.pcap, s)

    # URL — must have http/https scheme to count as URL target
    if s.startswith(("http://", "https://")):
        p = urlparse(s)
        if not p.netloc:
            raise ParseError("invalid URL")
        return ParsedTarget(TargetType.url, s)

    # IP or CIDR
    if _is_ip_or_cidr(s):
        return ParsedTarget(TargetType.ip, s)

    # Custom-protocol endpoint, e.g. tcp://host:9000
    m = _PROTOCOL_RE.match(s)
    if m and m.group(1).lower() not in {"http", "https"}:
        return ParsedTarget(TargetType.protocol, s)

    # Bare host:port — treat as protocol endpoint
    if ":" in s and "/" not in s and not _is_ip_or_cidr(s.split(":", 1)[0]):
        host, _, port = s.partition(":")
        if port.isdigit() and _DOMAIN_RE.match(host):
            return ParsedTarget(TargetType.protocol, f"tcp://{s}")

    # Domain name
    if _DOMAIN_RE.match(s):
        return ParsedTarget(TargetType.domain, s.lower())

    raise ParseError(f"could not classify target: {raw!r}")
