"""SMS OTP and recovery-code generation, normalization, and hashing.

SMS OTPs remain numeric zero-padded codes for parity with the existing email
OTP UX. Recovery codes use a Crockford base32 alphabet (no ambiguous
``I``, ``L``, ``O``, ``U``, ``0``, ``1``) and are formatted as ``XXXXX-XXXXX``
pairs for readability. Both are hashed through the existing keyed-HMAC OTP
hasher so rotating ``mfa.phone_lookup_hash_key`` / refresh-token hash key
invalidates the whole MFA surface as a unit.
"""

from __future__ import annotations

import re
import secrets
from typing import Final

from app.core.otp import hash_otp, verify_otp

# Crockford base32 minus ambiguous characters I, L, O, U and digits 0, 1.
RECOVERY_CODE_ALPHABET: Final[str] = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
_RECOVERY_CODE_SEGMENT_LENGTH: Final[int] = 5
_NORMALIZE_STRIP_PATTERN: Final[re.Pattern[str]] = re.compile(r"[\s\-]+")


def generate_sms_otp(length: int) -> str:
    """Return a numeric zero-padded OTP suitable for SMS delivery."""
    if length < 1:
        raise ValueError("sms otp length must be a positive integer.")
    return str(secrets.randbelow(10**length)).zfill(length)


def hash_sms_otp(code: str) -> str:
    """Hash an SMS OTP using the shared keyed-HMAC pipeline."""
    return hash_otp(code)


def verify_sms_otp(raw_code: str, stored_hash: str) -> bool:
    """Constant-time comparison of an SMS OTP against its stored digest."""
    return verify_otp(raw_code.strip(), stored_hash)


def generate_recovery_codes(*, count: int, length: int) -> list[str]:
    """Return a list of unique recovery codes formatted as ``XXXXX-XXXXX``.

    Length must be an even integer so each pair of 5-character segments has
    equal size. Uniqueness is verified in-process; the caller is expected to
    persist hashed values and rely on the database unique constraint for
    cross-process guarantees.
    """
    if count < 1:
        raise ValueError("recovery-code count must be a positive integer.")
    if length < _RECOVERY_CODE_SEGMENT_LENGTH * 2 or length % 2 != 0:
        raise ValueError("recovery-code length must be an even integer >= 10.")

    codes: set[str] = set()
    while len(codes) < count:
        raw = "".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(length))
        formatted = _format_recovery_code(raw)
        codes.add(formatted)
    return sorted(codes)


def _format_recovery_code(raw: str) -> str:
    """Format a raw recovery code into ``XXXXX-XXXXX`` segments."""
    mid = len(raw) // 2
    return f"{raw[:mid]}-{raw[mid:]}"


def normalize_recovery_code(raw: str) -> str:
    """Return a canonical recovery-code form (uppercase, segmented, alphabet-only).

    Accepts mixed-case input, extra whitespace, and missing/extra separators as
    long as the final stripped value contains an even number of alphabet
    characters. Any character outside the alphabet (other than spaces or hyphens)
    causes validation to fail.
    """
    if not isinstance(raw, str):  # type: ignore[unreachable]
        raise ValueError("recovery code must be a string.")
    compacted = _NORMALIZE_STRIP_PATTERN.sub("", raw.strip()).upper()
    if not compacted:
        raise ValueError("recovery code must not be empty.")
    if any(ch not in RECOVERY_CODE_ALPHABET for ch in compacted):
        raise ValueError("recovery code contains invalid characters.")
    if len(compacted) < _RECOVERY_CODE_SEGMENT_LENGTH * 2 or len(compacted) % 2 != 0:
        raise ValueError("recovery code has an invalid length.")
    return _format_recovery_code(compacted)


def hash_recovery_code(raw: str) -> str:
    """Normalize and hash a recovery code for durable storage."""
    normalized = normalize_recovery_code(raw)
    return hash_otp(normalized)


def verify_recovery_code(raw: str, stored_hash: str) -> bool:
    """Constant-time comparison of a user-supplied recovery code against a digest."""
    try:
        normalized = normalize_recovery_code(raw)
    except ValueError:
        return False
    return verify_otp(normalized, stored_hash)
