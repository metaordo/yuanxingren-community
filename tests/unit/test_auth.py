"""Unit tests for the auth module: bcrypt + jwt + service flow."""
from __future__ import annotations
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
os.environ["PA_JWT_SECRET"] = "test-secret-do-not-use-in-prod"

import pytest

from backend.auth.password import hash_password, verify_password, is_strong
from backend.auth import jwt_handler


class TestPassword:
    def test_hash_verify_roundtrip(self):
        h = hash_password("Password!123")
        assert verify_password("Password!123", h)
        assert not verify_password("wrong", h)

    def test_invalid_hash_fails_safe(self):
        assert not verify_password("any", "not-a-bcrypt-hash")

    def test_policy_strong(self):
        assert is_strong("Aa1!aaaa")

    def test_policy_too_short(self):
        assert not is_strong("Aa1!")

    def test_policy_no_special(self):
        assert not is_strong("Password123")


class TestJWT:
    def test_issue_verify_roundtrip(self):
        from datetime import timedelta
        token = jwt_handler.issue(1, "alice", "operator", ttl=timedelta(hours=1))
        payload = jwt_handler.verify(token)
        assert payload["sub"] == "1"
        assert payload["usr"] == "alice"
        assert payload["rol"] == "operator"

    def test_tampered_rejected(self):
        from datetime import timedelta
        token = jwt_handler.issue(1, "alice", "operator", ttl=timedelta(hours=1))
        # Flip a character in the signature portion
        bad = token[:-2] + ("aa" if token[-2:] != "aa" else "bb")
        with pytest.raises(Exception):
            jwt_handler.verify(bad)
