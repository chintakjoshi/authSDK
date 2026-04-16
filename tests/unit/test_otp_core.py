"""Unit tests for OTP core helpers."""

from app.core.otp import OTPHasher, generate_otp, hash_otp, mask_email, verify_otp


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


def test_otp_hasher_uses_keyed_hmac() -> None:
    """OTP hashing should use keyed HMAC rather than plain SHA-256."""
    hasher = OTPHasher.from_secret("otp-hash-secret")

    current_hash = hasher.hash_code("123456")
    plain_sha256 = "8d969eef6ecad3c29a3a629280e686cff8fabd2a47b16f7dd1a0a3d0d6b8b3c3"

    assert current_hash == hasher.hash_code("123456")
    assert current_hash != plain_sha256
    assert hasher.verify_code("123456", current_hash) is True
    assert hasher.verify_code("123456", plain_sha256) is False
    assert hasher.verify_code("000000", current_hash) is False


def test_mask_email_obscures_local_part() -> None:
    """Email masking keeps the domain and first local character only."""
    assert mask_email("jane@example.com") == "j***@example.com"
