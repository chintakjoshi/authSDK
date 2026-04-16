"""Core helpers for email OTP generation and verification."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from hashlib import sha256

from app.config import Settings, get_settings, reloadable_singleton

_OTP_HASH_CONTEXT = b"otp-hash:v1"


@dataclass(frozen=True)
class OTPHasher:
    """Keyed OTP hash helper."""

    key: bytes

    @classmethod
    def from_secret(cls, secret: str) -> OTPHasher:
        """Derive a stable OTP HMAC key from configured secret material."""
        if not secret.strip():
            raise ValueError("otp hash secret must be non-empty.")
        derived_key = hmac.digest(
            secret.encode("utf-8"),
            _OTP_HASH_CONTEXT,
            "sha256",
        )
        return cls(key=derived_key)

    @classmethod
    def from_settings(cls, settings: Settings) -> OTPHasher:
        """Build hasher from verifier-secret settings or safe local fallback."""
        configured_secret = settings.session_security.refresh_token_hash_key
        if configured_secret is not None:
            return cls.from_secret(configured_secret.get_secret_value())
        return cls.from_secret(settings.jwt.private_key_pem.get_secret_value())

    def hash_code(self, code: str) -> str:
        """Hash one OTP using keyed HMAC-SHA256."""
        return hmac.new(self.key, code.encode("utf-8"), sha256).hexdigest()

    def verify_code(self, raw_code: str, stored_hash: str) -> bool:
        """Verify a stored OTP digest against the current keyed hash format."""
        current_hash = self.hash_code(raw_code)
        return hmac.compare_digest(current_hash, stored_hash)


@reloadable_singleton
def get_otp_hasher() -> OTPHasher:
    """Create and cache the OTP hasher dependency."""
    return OTPHasher.from_settings(get_settings())


def generate_otp(length: int = 6) -> str:
    """Generate a zero-padded numeric OTP of fixed length."""
    return str(secrets.randbelow(10**length)).zfill(length)


def hash_otp(code: str) -> str:
    """Hash an OTP code for Redis storage."""
    return get_otp_hasher().hash_code(code)


def verify_otp(raw_code: str, stored_hash: str) -> bool:
    """Compare a raw OTP code against a stored keyed digest."""
    return get_otp_hasher().verify_code(raw_code, stored_hash)


def mask_email(email: str) -> str:
    """Return a masked email address suitable for OTP UX."""
    local, domain = email.split("@", 1)
    return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"
