"""Provider-agnostic SMS sender Protocol.

Every SMS adapter must implement :meth:`SmsSender.send_otp_sms`. The protocol
is intentionally minimal: MFA code delivery is the only operation supported in
v1. Providers are responsible for honoring the ``expires_in_seconds`` value
in the outbound message body and for rejecting invalid phone numbers, but
callers (``MfaService``) always normalize input through
:func:`app.core.mfa.phone.normalize_e164` before invoking a sender.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.core.mfa.challenge import MfaChallengePurpose


@runtime_checkable
class SmsSender(Protocol):
    """Contract for delivering MFA SMS one-time codes to a user's phone."""

    async def send_otp_sms(
        self,
        *,
        to_phone_e164: str,
        code: str,
        expires_in_seconds: int,
        purpose: MfaChallengePurpose,
    ) -> None:
        """Deliver one MFA OTP code to ``to_phone_e164``.

        Implementations must not log ``code`` or the full phone number; only
        masked identifiers and non-sensitive metadata (purpose, expires-in)
        may appear in logs.
        """
        ...
