"""Integration tests for the local SMS adapter against a live Redis."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from app.core.sessions import get_redis_client
from app.services.sms.factory import get_sms_sender
from app.services.sms.local import LocalSmsSender


@pytest.mark.asyncio
async def test_get_sms_sender_returns_local_sender_against_live_redis() -> None:
    """Factory must produce a LocalSmsSender in development against real Redis."""
    sender = get_sms_sender()
    assert isinstance(sender, LocalSmsSender)


@pytest.mark.asyncio
async def test_local_sender_roundtrips_payload_via_redis(
    local_sms_reader: Callable[[str], Any],
) -> None:
    """Sending an OTP should be readable via the integration reader fixture."""
    sender = LocalSmsSender(redis_client=get_redis_client(), ttl_seconds=600)

    phone = "+14155552671"
    await sender.send_otp_sms(
        to_phone_e164=phone,
        code="424242",
        expires_in_seconds=600,
        purpose="login",
    )

    payload = await local_sms_reader(phone)
    assert payload is not None
    assert payload["code"] == "424242"
    assert payload["purpose"] == "login"
    assert payload["to_phone_e164"] == phone
