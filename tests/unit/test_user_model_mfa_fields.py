"""Unit tests for MFA-related User fields and the UserRecoveryCode model.

These tests assert the ORM surface only (no database round-trip); integration
coverage for the migration itself lives in tests/integration.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import inspect as sa_inspect

from app.models.recovery_code import UserRecoveryCode
from app.models.user import User


def test_user_model_exposes_mfa_fields_and_drops_legacy_email_otp() -> None:
    """User ORM must expose the new MFA/phone fields and no longer expose email_otp_enabled."""
    columns = {column.name for column in sa_inspect(User).columns}

    assert "phone_ciphertext" in columns
    assert "phone_last4" in columns
    assert "phone_lookup_hash" in columns
    assert "phone_verified" in columns
    assert "phone_verified_at" in columns
    assert "mfa_enabled" in columns
    assert "mfa_primary_method" in columns

    legacy_column_name = "email_otp" + "_enabled"
    assert legacy_column_name not in columns


def test_user_mfa_fields_default_to_safe_values() -> None:
    """New MFA fields must declare safe disabled/unenrolled defaults.

    ``phone_verified`` and ``mfa_enabled`` carry Python defaults plus
    ``server_default=false`` so database INSERTs, not Python construction,
    materialize the disabled state. This mirrors the existing treatment of
    ``email_verified``.
    """
    columns = {column.name: column for column in sa_inspect(User).columns}

    for column_name in ("phone_verified", "mfa_enabled"):
        column = columns[column_name]
        assert column.default is not None
        assert column.default.arg is False
        assert column.server_default is not None

    nullable_columns = (
        "phone_ciphertext",
        "phone_last4",
        "phone_lookup_hash",
        "phone_verified_at",
        "mfa_primary_method",
    )
    for column_name in nullable_columns:
        assert columns[column_name].nullable is True


def test_user_accepts_verified_phone_and_sms_mfa_state() -> None:
    """User model should accept verified-phone + SMS-MFA state assignment."""
    verified_at = datetime.now(UTC)
    user = User(
        email="enrolled@example.com",
        phone_ciphertext=b"ciphertext-placeholder",
        phone_last4="1234",
        phone_lookup_hash="a" * 64,
        phone_verified=True,
        phone_verified_at=verified_at,
        mfa_enabled=True,
        mfa_primary_method="sms",
    )

    assert user.phone_verified is True
    assert user.phone_verified_at == verified_at
    assert user.mfa_enabled is True
    assert user.mfa_primary_method == "sms"
    assert user.phone_last4 == "1234"


def test_user_recovery_code_model_exposes_required_columns() -> None:
    """UserRecoveryCode must expose user binding, hashed code, and used-at timestamp."""
    columns = {column.name for column in sa_inspect(UserRecoveryCode).columns}

    assert "id" in columns
    assert "user_id" in columns
    assert "code_hash" in columns
    assert "used_at" in columns


def test_user_recovery_code_defaults_to_unused() -> None:
    """A freshly built recovery code row should be marked unused."""
    row = UserRecoveryCode(user_id=uuid4(), code_hash="h" * 64)

    assert row.used_at is None
    assert row.code_hash == "h" * 64
