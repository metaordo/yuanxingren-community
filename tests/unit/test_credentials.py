"""Unit tests for LLM credential encryption + custom model registration."""
from __future__ import annotations
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
os.environ.setdefault("PA_JWT_SECRET", "test-secret-for-credential-store-tests")

from backend.llm.credential_store import encrypt, decrypt


def test_roundtrip():
    plain = "sk-test-1234567890"
    cipher = encrypt(plain)
    assert cipher != plain
    assert decrypt(cipher) == plain


def test_empty():
    assert encrypt("") == ""
    assert decrypt("") == ""


def test_b64_fallback_roundtrip():
    # Force b64 path by handing in a b64-prefixed string
    assert decrypt("b64:aGVsbG8=") == "hello"
