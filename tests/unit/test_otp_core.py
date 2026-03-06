"""Unit tests for OTP core helpers."""

from app.core.otp import generate_otp, hash_otp, mask_email, verify_otp


def test_generate_otp_returns_zero_padded_numeric_code() -> None:
    """OTP generator returns fixed-length numeric strings."""
    code = generate_otp(6)
    assert len(code) == 6
    assert code.isdigit()


def test_hash_and_verify_otp_round_trip() -> None:
    """OTP hash verification succeeds for matching input and fails otherwise."""
    code = "048291"
    hashed = hash_otp(code)
    assert verify_otp(code, hashed) is True
    assert verify_otp("000000", hashed) is False


def test_mask_email_obscures_local_part() -> None:
    """Email masking keeps the domain and first local character only."""
    assert mask_email("jane@example.com") == "j***@example.com"
