"""Schemas for account lifecycle endpoints."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.validation import AuthPassword, EmailAddress, StrongPassword


class SignupRequest(BaseModel):
    """Password signup payload."""

    email: EmailAddress
    password: StrongPassword


class SignupResponse(BaseModel):
    """Non-enumerating password signup response payload."""

    accepted: Literal[True] = True


class VerifyEmailResponse(BaseModel):
    """Email verification success response."""

    verified: Literal[True] = True


class ResendVerifyEmailRequest(BaseModel):
    """Public resend-verification request payload."""

    email: EmailAddress


class ResendVerifyEmailResponse(BaseModel):
    """Resend verification email success response."""

    sent: Literal[True] = True


class ForgotPasswordRequest(BaseModel):
    """Forgot-password request payload."""

    email: EmailAddress


class ForgotPasswordResponse(BaseModel):
    """Forgot-password success response."""

    sent: Literal[True] = True


class ValidatePasswordResetResponse(BaseModel):
    """Password reset token validation success response."""

    valid: Literal[True] = True


class ResetPasswordRequest(BaseModel):
    """Password reset completion payload."""

    token: str = Field(min_length=16, max_length=512)
    new_password: StrongPassword


class ResetPasswordResponse(BaseModel):
    """Password reset completion success response."""

    reset: Literal[True] = True


class ReauthRequest(BaseModel):
    """Password re-authentication payload."""

    password: AuthPassword


class ReauthResponse(BaseModel):
    """Re-authentication success response."""

    access_token: str


class EraseAccountResponse(BaseModel):
    """Successful self-service erasure response."""

    erased: Literal[True] = True
    user_id: UUID
