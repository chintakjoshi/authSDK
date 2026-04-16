"""Shared request-field validators for auth-facing schemas."""

from __future__ import annotations

import string
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, EmailStr, Field

_MAX_EMAIL_LENGTH = 320
_STRONG_PASSWORD_MIN_LENGTH = 8
_STRONG_PASSWORD_MAX_LENGTH = 64
_AUTH_PASSWORD_MIN_LENGTH = 8
_AUTH_PASSWORD_MAX_LENGTH = 256
_SPECIAL_PASSWORD_CHARACTERS = frozenset(string.punctuation)


def _strip_surrounding_whitespace(value: Any) -> Any:
    """Trim surrounding whitespace for string-like request values."""
    if isinstance(value, str):
        return value.strip()
    return value


def _validate_strong_password(value: str) -> str:
    """Enforce the shared strong-password policy for password-setting flows."""
    if not any(character.isupper() for character in value):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(character.isdigit() for character in value):
        raise ValueError("Password must contain at least one number.")
    if not any(character in _SPECIAL_PASSWORD_CHARACTERS for character in value):
        raise ValueError("Password must contain at least one special character.")
    return value


EmailAddress = Annotated[
    EmailStr,
    BeforeValidator(_strip_surrounding_whitespace),
    Field(max_length=_MAX_EMAIL_LENGTH),
]

StrongPassword = Annotated[
    str,
    Field(min_length=_STRONG_PASSWORD_MIN_LENGTH, max_length=_STRONG_PASSWORD_MAX_LENGTH),
    AfterValidator(_validate_strong_password),
]

AuthPassword = Annotated[
    str,
    Field(min_length=_AUTH_PASSWORD_MIN_LENGTH, max_length=_AUTH_PASSWORD_MAX_LENGTH),
]
