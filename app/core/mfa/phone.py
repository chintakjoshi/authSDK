"""Phone-number validation, encryption, lookup hashing, and masking.

Phone numbers are PII with elevated sensitivity (SIM-swap risk, account
recovery risk) and are encrypted at rest via Fernet using a dedicated
``mfa.phone_encryption_key`` secret. A separate keyed-HMAC lookup hash
powers the globally-unique partial index on ``users.phone_lookup_hash``
without exposing plaintext.

The low-level primitives here are deterministic in their inputs (validation,
hashing) and isolate Fernet key derivation so arbitrary secret material can be
rotated without re-base64-encoding existing keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Final

from cryptography.fernet import Fernet, InvalidToken

from app.config import Settings, get_settings, reloadable_singleton

_PHONE_LOOKUP_HASH_CONTEXT: Final[bytes] = b"mfa-phone-lookup:v1"
_PHONE_ENCRYPTION_CONTEXT: Final[bytes] = b"mfa-phone-fernet:v1"
_E164_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\+[1-9]\d{7,14}$")


class PhoneValidationError(ValueError):
    """Raised when a phone number fails E.164 validation or decryption."""


def normalize_e164(raw: str) -> str:
    """Return a strictly validated E.164 phone number.

    Accepts leading/trailing whitespace but rejects any internal separators,
    letters, or non-compliant lengths. The regex enforces:

    - a single leading ``+``
    - a country code digit in ``1-9``
    - a total digit count of 8-15 (per E.164 maximum length)
    """
    if not isinstance(raw, str):  # type: ignore[unreachable]
        raise PhoneValidationError("phone number must be a string.")
    trimmed = raw.strip()
    if not _E164_PATTERN.fullmatch(trimmed):
        raise PhoneValidationError("phone number must be a valid E.164 value.")
    return trimmed


def mask_e164(e164: str) -> str:
    """Return a display-safe masked phone number revealing only the last four digits."""
    normalized = normalize_e164(e164)
    # Preserve the leading '+'; mask everything between it and the last four digits.
    digits = normalized[1:]
    hidden_count = max(len(digits) - 4, 0)
    return "+" + ("*" * hidden_count) + digits[-4:]


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a stable 32-byte urlsafe-base64 Fernet key from arbitrary material.

    When ``secret`` is itself a valid Fernet key the function returns it
    unchanged so key-rotation workflows that already use ``Fernet.generate_key``
    remain round-trippable. Otherwise the material is HMAC-derived deterministically
    so the caller does not need to manage key encoding explicitly.
    """
    candidate = secret.strip()
    if not candidate:
        raise ValueError("phone encryption key must be non-empty.")

    try:
        raw = base64.urlsafe_b64decode(candidate.encode("ascii"))
        if len(raw) == 32:
            return candidate.encode("ascii")
    except (ValueError, UnicodeEncodeError):
        pass

    derived = hmac.new(
        candidate.encode("utf-8"),
        _PHONE_ENCRYPTION_CONTEXT,
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(derived)


@dataclass(frozen=True)
class PhoneCipher:
    """Symmetric encryption wrapper for phone numbers at rest."""

    fernet_key: bytes

    @classmethod
    def from_key(cls, secret: str) -> PhoneCipher:
        """Build a cipher from configured secret material."""
        return cls(fernet_key=_derive_fernet_key(secret))

    @classmethod
    def from_settings(cls, settings: Settings) -> PhoneCipher:
        """Build a cipher from the configured phone-encryption secret.

        Development environments may omit ``mfa.phone_encryption_key``; in that
        case we fall back to deriving from the JWT private-key PEM so local
        workflows function without extra configuration. Production startup
        already rejects a missing key via ``validate_production_constraints``.
        """
        configured = settings.mfa.phone_encryption_key
        if configured is not None:
            return cls.from_key(configured.get_secret_value())
        return cls.from_key(settings.jwt.private_key_pem.get_secret_value())

    def _fernet(self) -> Fernet:
        return Fernet(self.fernet_key)

    def encrypt(self, e164: str) -> bytes:
        """Encrypt a strictly validated phone number."""
        normalized = normalize_e164(e164)
        return self._fernet().encrypt(normalized.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypt a ciphertext produced by :meth:`encrypt`."""
        try:
            plaintext = self._fernet().decrypt(ciphertext)
        except InvalidToken as exc:
            raise PhoneValidationError("phone ciphertext is invalid or tampered.") from exc
        return plaintext.decode("utf-8")


@dataclass(frozen=True)
class PhoneHasher:
    """Keyed HMAC hasher producing deterministic lookup digests for indexing."""

    key: bytes

    @classmethod
    def from_secret(cls, secret: str) -> PhoneHasher:
        """Derive a stable HMAC key from configured secret material."""
        trimmed = secret.strip()
        if not trimmed:
            raise ValueError("phone lookup-hash secret must be non-empty.")
        derived = hmac.new(
            trimmed.encode("utf-8"),
            _PHONE_LOOKUP_HASH_CONTEXT,
            hashlib.sha256,
        ).digest()
        return cls(key=derived)

    @classmethod
    def from_settings(cls, settings: Settings) -> PhoneHasher:
        """Build hasher from the configured phone lookup-hash secret or fallback."""
        configured = settings.mfa.phone_lookup_hash_key
        if configured is not None:
            return cls.from_secret(configured.get_secret_value())
        return cls.from_secret(settings.jwt.private_key_pem.get_secret_value())

    def lookup_hash(self, e164: str) -> str:
        """Return the keyed-HMAC hex digest for a validated phone number."""
        normalized = normalize_e164(e164)
        return hmac.new(self.key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify(self, e164: str, stored_hash: str) -> bool:
        """Constant-time comparison of a raw phone number against a stored digest."""
        try:
            candidate = self.lookup_hash(e164)
        except PhoneValidationError:
            return False
        return hmac.compare_digest(candidate, stored_hash)


@reloadable_singleton
def get_phone_cipher() -> PhoneCipher:
    """Return the cached :class:`PhoneCipher` bound to current settings."""
    return PhoneCipher.from_settings(get_settings())


@reloadable_singleton
def get_phone_hasher() -> PhoneHasher:
    """Return the cached :class:`PhoneHasher` bound to current settings."""
    return PhoneHasher.from_settings(get_settings())
