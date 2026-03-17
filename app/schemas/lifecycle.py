"""Schemas for account lifecycle endpoints."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class SignupRequest(BaseModel):
    """Password signup payload."""

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=256)


class SignupResponse(BaseModel):
    """Password signup response payload."""

    user_id: UUID
    email: str
    email_verified: bool


class VerifyEmailResponse(BaseModel):
    """Email verification success response."""

    verified: Literal[True] = True


class ResendVerifyEmailResponse(BaseModel):
    """Resend verification email success response."""

    sent: Literal[True] = True


class ForgotPasswordRequest(BaseModel):
    """Forgot-password request payload."""

    email: str = Field(min_length=3, max_length=320)


class ForgotPasswordResponse(BaseModel):
    """Forgot-password success response."""

    sent: Literal[True] = True


class ValidatePasswordResetResponse(BaseModel):
    """Password reset token validation success response."""

    valid: Literal[True] = True


class ResetPasswordRequest(BaseModel):
    """Password reset completion payload."""

    token: str = Field(min_length=16, max_length=512)
    new_password: str = Field(min_length=8, max_length=256)


class ResetPasswordResponse(BaseModel):
    """Password reset completion success response."""

    reset: Literal[True] = True


class ReauthRequest(BaseModel):
    """Password re-authentication payload."""

    password: str = Field(min_length=8, max_length=256)


class ReauthResponse(BaseModel):
    """Re-authentication success response."""

    access_token: str


class EraseAccountResponse(BaseModel):
    """Successful self-service erasure response."""

    erased: Literal[True] = True
    user_id: UUID
