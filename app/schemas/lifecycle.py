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
