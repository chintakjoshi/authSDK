"""Schemas for email OTP and action-token flows."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

OTPAction = Literal[
    "role_change",
    "delete_user",
    "revoke_sessions",
    "rotate_signing_key",
    "erase_account",
    "enable_otp",
    "disable_otp",
]


class LoginOTPChallengeResponse(BaseModel):
    """Login response when a second OTP step is required."""

    otp_required: Literal[True] = True
    challenge_token: str
    masked_email: str


class VerifyLoginOTPRequest(BaseModel):
    """OTP submission payload for login completion."""

    challenge_token: str = Field(min_length=16)
    code: str = Field(min_length=4, max_length=12)


class ResendLoginOTPRequest(BaseModel):
    """OTP resend payload for an active login challenge."""

    challenge_token: str = Field(min_length=16)


class OTPMessageSentResponse(BaseModel):
    """Generic successful OTP delivery response."""

    sent: Literal[True] = True


class RequestActionOTPRequest(BaseModel):
    """Request an OTP for a specific sensitive action."""

    action: OTPAction


class RequestActionOTPResponse(BaseModel):
    """Successful action OTP request response."""

    sent: Literal[True] = True
    action: OTPAction
    expires_in: int


class VerifyActionOTPRequest(BaseModel):
    """Verify an action OTP and mint an action token."""

    code: str = Field(min_length=4, max_length=12)
    action: OTPAction


class VerifyActionOTPResponse(BaseModel):
    """Successful action OTP verification response."""

    action_token: str


class OTPEnrollmentResponse(BaseModel):
    """OTP enrollment toggle response."""

    email_otp_enabled: bool
