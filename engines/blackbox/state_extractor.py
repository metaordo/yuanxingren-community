"""State machine extraction from protocol implementations.

Two paths supported:
  - PCAP-based: parse a packet capture, infer state transitions by clustering
    request/response pairs.
  - Binary-based: lift binary control flow with angr/Ghidra, identify
    state-update instructions.

MVP: PCAP path with simple heuristics.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class State:
    id: str
    label: str
    incoming: list[str] = field(default_factory=list)
    outgoing: list[str] = field(default_factory=list)


@dataclass
class Transition:
    src: str
    dst: str
    trigger: str  # e.g. "SYN", "HELLO", "AUTH_REQUEST"


@dataclass
class StateMachine:
    states: list[State]
    transitions: list[Transition]
    initial: str


def extract_from_pcap(pcap_path: Path) -> StateMachine:
    """Stub: parse pcap, return state machine.

    Real implementation uses scapy/dpkt to walk packets and infer states.
    """
    return StateMachine(
        states=[State(id="s0", label="initial"),
                State(id="s1", label="connected")],
        transitions=[Transition(src="s0", dst="s1", trigger="HANDSHAKE")],
        initial="s0",
    )


def diff_state_machines(a: StateMachine, b: StateMachine) -> list[Transition]:
    """Return transitions present in `a` but missing in `b`.

    Useful for finding implementation discrepancies between two protocol
    implementations (e.g., OpenSSL vs BoringSSL).
    """
    a_keys = {(t.src, t.dst, t.trigger) for t in a.transitions}
    b_keys = {(t.src, t.dst, t.trigger) for t in b.transitions}
    diff_keys = a_keys - b_keys
    return [t for t in a.transitions if (t.src, t.dst, t.trigger) in diff_keys]
