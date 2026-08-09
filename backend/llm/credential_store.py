"""Encrypted credential storage for LLM API keys.

Uses Fernet symmetric encryption with a key derived from PA_JWT_SECRET so we
don't introduce another secret to manage. In production, replace with a real
KMS-backed key.
"""
from __future__ import annotations
import base64
import hashlib
import os


def _derive_key() -> bytes:
    """Derive a 32-byte Fernet key from PA_JWT_SECRET."""
    secret = os.environ["PA_JWT_SECRET"].encode("utf-8")  # required — no default, no fallback
    digest = hashlib.sha256(secret).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_derive_key())
        return f.encrypt(plaintext.encode("utf-8")).decode("ascii")
    except ImportError:
        # Fallback: base64 only (NOT secure — log a warning)
        import logging
        logging.getLogger(__name__).warning(
            "cryptography not installed; storing credentials with weak obfuscation"
        )
        return "b64:" + base64.b64encode(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    if ciphertext.startswith("b64:"):
        return base64.b64decode(ciphertext[4:]).decode("utf-8")
    try:
        from cryptography.fernet import Fernet
        f = Fernet(_derive_key())
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except Exception:
        raise RuntimeError("cannot decrypt credential — wrong key or corrupt data")
