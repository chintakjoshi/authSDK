"""Core helpers for email OTP generation and verification."""

from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_otp(length: int = 6) -> str:
    """Generate a zero-padded numeric OTP of fixed length."""
    return str(secrets.randbelow(10**length)).zfill(length)


def hash_otp(code: str) -> str:
    """Hash an OTP code for Redis storage."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def verify_otp(raw_code: str, stored_hash: str) -> bool:
    """Compare a raw OTP code against a stored SHA-256 digest."""
    return hmac.compare_digest(hash_otp(raw_code), stored_hash)


def mask_email(email: str) -> str:
    """Return a masked email address suitable for OTP UX."""
    local, domain = email.split("@", 1)
    return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"
