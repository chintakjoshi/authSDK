"""Unit tests for auth-facing request schema validation helpers."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.lifecycle import ResetPasswordRequest, SignupRequest
from app.schemas.user import LoginRequest


def test_signup_request_strips_email_whitespace_and_accepts_strong_password() -> None:
    """Signup request should normalize surrounding email whitespace and accept strong passwords."""
    payload = SignupRequest.model_validate(
        {"email": "  User@example.com  ", "password": "Password123!"}
    )

    assert payload.email == "User@example.com"
    assert payload.password == "Password123!"


@pytest.mark.parametrize(
    ("password", "message_fragment"),
    [
        ("password123!", "uppercase"),
        ("Password!!!", "number"),
        ("Password123", "special"),
        ("P" * 63 + "1!", "at most 64"),
    ],
)
def test_signup_request_rejects_weak_passwords(password: str, message_fragment: str) -> None:
    """Signup request should enforce the documented password policy."""
    with pytest.raises(ValidationError) as exc_info:
        SignupRequest.model_validate({"email": "user@example.com", "password": password})

    assert message_fragment in str(exc_info.value)


def test_reset_password_request_rejects_weak_new_password() -> None:
    """Password reset completion should enforce the same strong-password policy."""
    with pytest.raises(ValidationError) as exc_info:
        ResetPasswordRequest.model_validate({"token": "x" * 16, "new_password": "password123!"})

    assert "uppercase" in str(exc_info.value)


def test_login_request_keeps_existing_runtime_compatibility() -> None:
    """Login validation should remain compatible with previously-set passwords."""
    payload = LoginRequest.model_validate({"email": "user@example.com", "password": "alllowercase"})

    assert payload.password == "alllowercase"
