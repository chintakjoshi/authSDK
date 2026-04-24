"""Unit tests for SMS OTP and recovery-code generation/hashing primitives."""

from __future__ import annotations

import re

import pytest

from app.core.mfa.codes import (
    RECOVERY_CODE_ALPHABET,
    generate_recovery_codes,
    generate_sms_otp,
    hash_recovery_code,
    hash_sms_otp,
    normalize_recovery_code,
    verify_recovery_code,
    verify_sms_otp,
)


class TestGenerateSmsOtp:
    """SMS OTP generation matches the existing email-OTP numeric format."""

    @pytest.mark.parametrize("length", [4, 6, 8, 12])
    def test_produces_fixed_length_numeric_code(self, length: int) -> None:
        code = generate_sms_otp(length)

        assert len(code) == length
        assert code.isdigit()

    def test_rejects_out_of_range_length(self) -> None:
        with pytest.raises(ValueError):
            generate_sms_otp(0)
        with pytest.raises(ValueError):
            generate_sms_otp(-1)


class TestHashVerifySmsOtp:
    """SMS OTPs are hashed via the existing keyed-HMAC pipeline."""

    def test_hash_is_deterministic_under_same_settings(self) -> None:
        first = hash_sms_otp("123456")
        second = hash_sms_otp("123456")

        assert first == second
        assert len(first) == 64

    def test_verify_accepts_correct_code(self) -> None:
        digest = hash_sms_otp("654321")

        assert verify_sms_otp("654321", digest) is True

    def test_verify_rejects_mismatched_code(self) -> None:
        digest = hash_sms_otp("654321")

        assert verify_sms_otp("123456", digest) is False


class TestGenerateRecoveryCodes:
    """Recovery codes follow the ``XXXXX-XXXXX`` Crockford base32 format."""

    def test_count_and_length_match_inputs(self) -> None:
        codes = generate_recovery_codes(count=10, length=10)

        assert len(codes) == 10
        for code in codes:
            assert re.fullmatch(r"[A-Z0-9]{5}-[A-Z0-9]{5}", code)

    def test_codes_are_unique(self) -> None:
        codes = generate_recovery_codes(count=20, length=10)

        assert len(set(codes)) == len(codes)

    def test_alphabet_excludes_ambiguous_characters(self) -> None:
        for forbidden in ("I", "L", "O", "U", "0", "1"):
            assert forbidden not in RECOVERY_CODE_ALPHABET

    def test_generator_uses_only_alphabet_characters(self) -> None:
        codes = generate_recovery_codes(count=50, length=10)

        for code in codes:
            for ch in code.replace("-", ""):
                assert ch in RECOVERY_CODE_ALPHABET

    @pytest.mark.parametrize("count", [0, -1])
    def test_rejects_non_positive_count(self, count: int) -> None:
        with pytest.raises(ValueError):
            generate_recovery_codes(count=count, length=10)

    @pytest.mark.parametrize("length", [7, 11])
    def test_rejects_odd_or_invalid_length(self, length: int) -> None:
        with pytest.raises(ValueError):
            generate_recovery_codes(count=1, length=length)


class TestNormalizeRecoveryCode:
    """User-submitted recovery codes should accept common formatting variants."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("ABCDE-FGHJK", "ABCDE-FGHJK"),
            ("abcde-fghjk", "ABCDE-FGHJK"),
            ("  ABCDE-FGHJK  ", "ABCDE-FGHJK"),
            ("ABCDEFGHJK", "ABCDE-FGHJK"),
            ("abcdefghjk", "ABCDE-FGHJK"),
            ("abcde fghjk", "ABCDE-FGHJK"),
        ],
    )
    def test_normalizes_common_forms(self, raw: str, expected: str) -> None:
        assert normalize_recovery_code(raw) == expected

    @pytest.mark.parametrize("raw", ["", "   ", "SHORT", "ABCDE-FGHJK-EXTRA", "ABCDE_FGHJK"])
    def test_rejects_malformed_inputs(self, raw: str) -> None:
        with pytest.raises(ValueError):
            normalize_recovery_code(raw)


class TestHashVerifyRecoveryCode:
    """Recovery codes are hashed with the same keyed HMAC as SMS OTPs."""

    def test_hash_is_deterministic_for_normalized_input(self) -> None:
        digest_a = hash_recovery_code("ABCDE-FGHJK")
        digest_b = hash_recovery_code("abcde fghjk")
        digest_c = hash_recovery_code("ABCDEFGHJK")

        assert digest_a == digest_b == digest_c
        assert len(digest_a) == 64

    def test_verify_accepts_any_normalized_form(self) -> None:
        digest = hash_recovery_code("ABCDE-FGHJK")

        assert verify_recovery_code("ABCDE-FGHJK", digest) is True
        assert verify_recovery_code("abcde-fghjk", digest) is True
        assert verify_recovery_code("ABCDEFGHJK", digest) is True

    def test_verify_rejects_wrong_code(self) -> None:
        digest = hash_recovery_code("ABCDE-FGHJK")

        assert verify_recovery_code("ZZZZZ-ZZZZZ", digest) is False

    def test_verify_returns_false_for_malformed_input(self) -> None:
        digest = hash_recovery_code("ABCDE-FGHJK")

        assert verify_recovery_code("not-a-code", digest) is False
        assert verify_recovery_code("", digest) is False
