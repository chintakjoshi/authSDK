"""Unit tests for MFA phone-number encryption, lookup hashing, and masking."""

from __future__ import annotations

import base64

import pytest
from cryptography.fernet import Fernet

from app.core.mfa.phone import (
    PhoneCipher,
    PhoneHasher,
    PhoneValidationError,
    mask_e164,
    normalize_e164,
)


def _fernet_key() -> str:
    """Return a base64url 32-byte Fernet key for cipher construction."""
    return Fernet.generate_key().decode("ascii")


class TestNormalizeE164:
    """Strict validation of E.164-format phone input."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("+14155552671", "+14155552671"),
            ("  +14155552671  ", "+14155552671"),
            ("+442071838750", "+442071838750"),
        ],
    )
    def test_accepts_valid_e164(self, raw: str, expected: str) -> None:
        assert normalize_e164(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "4155552671",  # missing '+'
            "+0123456789",  # leading zero after country code
            "+1",  # too short
            "+1234567",  # still too short (must be 8-15 digits)
            "+1234567890123456",  # too long (>15)
            "+1-415-555-2671",  # contains separators
            "+1 415 555 2671",
            "+1abc5552671",
            "tel:+14155552671",
        ],
    )
    def test_rejects_invalid_input(self, raw: str) -> None:
        with pytest.raises(PhoneValidationError):
            normalize_e164(raw)


class TestPhoneCipher:
    """Phone-number encryption roundtrip with Fernet."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        cipher = PhoneCipher.from_key(_fernet_key())
        ciphertext = cipher.encrypt("+14155552671")

        assert isinstance(ciphertext, bytes)
        assert cipher.decrypt(ciphertext) == "+14155552671"

    def test_ciphertext_is_non_deterministic(self) -> None:
        cipher = PhoneCipher.from_key(_fernet_key())

        first = cipher.encrypt("+14155552671")
        second = cipher.encrypt("+14155552671")

        assert first != second
        assert cipher.decrypt(first) == cipher.decrypt(second) == "+14155552671"

    def test_decrypt_rejects_tampered_ciphertext(self) -> None:
        cipher = PhoneCipher.from_key(_fernet_key())
        ciphertext = bytearray(cipher.encrypt("+14155552671"))
        ciphertext[-1] ^= 0x01

        with pytest.raises(PhoneValidationError):
            cipher.decrypt(bytes(ciphertext))

    def test_decrypt_rejects_ciphertext_from_different_key(self) -> None:
        cipher_a = PhoneCipher.from_key(_fernet_key())
        cipher_b = PhoneCipher.from_key(_fernet_key())
        ciphertext = cipher_a.encrypt("+14155552671")

        with pytest.raises(PhoneValidationError):
            cipher_b.decrypt(ciphertext)

    def test_from_key_rejects_blank_material(self) -> None:
        with pytest.raises(ValueError):
            PhoneCipher.from_key("   ")

    def test_from_key_accepts_arbitrary_secret_material(self) -> None:
        """Non-Fernet keys should be derived into a valid Fernet key deterministically."""
        cipher = PhoneCipher.from_key("a-rotatable-application-secret")
        ciphertext = cipher.encrypt("+14155552671")

        assert cipher.decrypt(ciphertext) == "+14155552671"


class TestPhoneHasher:
    """Keyed-HMAC lookup hashing for uniqueness indexing."""

    def test_hash_is_deterministic_for_same_key(self) -> None:
        hasher = PhoneHasher.from_secret("shared-lookup-secret")

        first = hasher.lookup_hash("+14155552671")
        second = hasher.lookup_hash("+14155552671")

        assert first == second
        assert len(first) == 64  # hex sha256

    def test_hash_changes_when_key_changes(self) -> None:
        one = PhoneHasher.from_secret("secret-a").lookup_hash("+14155552671")
        two = PhoneHasher.from_secret("secret-b").lookup_hash("+14155552671")

        assert one != two

    def test_hash_is_constant_time_comparable(self) -> None:
        hasher = PhoneHasher.from_secret("shared-lookup-secret")
        stored = hasher.lookup_hash("+14155552671")

        assert hasher.verify("+14155552671", stored) is True
        assert hasher.verify("+14155552672", stored) is False

    def test_from_secret_rejects_blank_material(self) -> None:
        with pytest.raises(ValueError):
            PhoneHasher.from_secret("   ")

    def test_hash_rejects_invalid_e164(self) -> None:
        hasher = PhoneHasher.from_secret("shared-lookup-secret")

        with pytest.raises(PhoneValidationError):
            hasher.lookup_hash("not-a-phone")


class TestMaskE164:
    """Display masking that reveals only last four digits."""

    def test_masks_to_last_four_digits(self) -> None:
        # '+14155552671' has 11 digits; hiding all but the last four leaves 7 stars.
        assert mask_e164("+14155552671") == "+*******2671"

    def test_mask_preserves_plus_prefix(self) -> None:
        masked = mask_e164("+442071838750")
        assert masked.startswith("+")
        assert masked.endswith("8750")

    def test_mask_rejects_invalid_input(self) -> None:
        with pytest.raises(PhoneValidationError):
            mask_e164("not-a-phone")


def test_fernet_key_generator_is_reusable_for_settings() -> None:
    """A raw Fernet key from Fernet.generate_key() should load into the cipher."""
    key = Fernet.generate_key().decode("ascii")
    cipher = PhoneCipher.from_key(key)

    # Sanity: the derived key must be a 32-byte base64url value Fernet accepts.
    derived = cipher.fernet_key
    base64.urlsafe_b64decode(derived)
    cipher.decrypt(cipher.encrypt("+14155552671"))
