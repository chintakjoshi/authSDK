"""Development-only SMS sender backed by Redis.

Stores outbound SMS payloads as JSON entries on a per-phone Redis list with a
short TTL. Tests and local developers read the list via :meth:`latest_message`
or directly from Redis — there is no HTTP surface, and the sender logs only
non-sensitive metadata (masked phone, purpose, expires-in) so OTP codes never
appear in log streams.

This sender must never ship in production: :func:`app.services.sms.factory.get_sms_sender`
raises a :class:`RuntimeError` when ``APP__ENVIRONMENT=production`` and
``MFA__SMS__PROVIDER=local`` in addition to the startup config guard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.core.mfa.challenge import MfaChallengePurpose
from app.core.mfa.phone import mask_e164, normalize_e164

logger = structlog.get_logger(__name__)


class LocalSmsSenderError(RuntimeError):
    """Raised when Redis-backed local delivery fails."""


@dataclass(frozen=True)
class _LocalMessage:
    """Minimal serialization helper for persisted local SMS payloads."""

    to_phone_e164: str
    code: str
    expires_in_seconds: int
    purpose: MfaChallengePurpose
    sent_at: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "to_phone_e164": self.to_phone_e164,
                "code": self.code,
                "expires_in_seconds": self.expires_in_seconds,
                "purpose": self.purpose,
                "sent_at": self.sent_at,
            }
        )


class LocalSmsSender:
    """Persist outbound OTP SMS payloads to Redis for local inspection."""

    def __init__(
        self,
        redis_client: Redis,
        *,
        ttl_seconds: int,
        max_messages_per_phone: int = 10,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive.")
        if max_messages_per_phone <= 0:
            raise ValueError("max_messages_per_phone must be positive.")
        self._redis = redis_client
        self._ttl_seconds = ttl_seconds
        self._max_messages = max_messages_per_phone

    async def send_otp_sms(
        self,
        *,
        to_phone_e164: str,
        code: str,
        expires_in_seconds: int,
        purpose: MfaChallengePurpose,
    ) -> None:
        """Persist an OTP SMS payload for local inspection."""
        normalized_phone = normalize_e164(to_phone_e164)
        message = _LocalMessage(
            to_phone_e164=normalized_phone,
            code=code,
            expires_in_seconds=expires_in_seconds,
            purpose=purpose,
            sent_at=datetime.now(UTC).isoformat(),
        )
        key = self._key(normalized_phone)
        try:
            await self._redis.lpush(key, message.to_json())
            await self._redis.ltrim(key, 0, self._max_messages - 1)
            await self._redis.expire(key, self._ttl_seconds)
        except RedisError as exc:
            raise LocalSmsSenderError("failed to persist local SMS payload.") from exc

        # Intentionally omit the raw phone and code from logs. Masked phone
        # and purpose are sufficient for local debugging without leaking PII.
        logger.info(
            "mfa.sms.local.sent",
            to_masked=mask_e164(normalized_phone),
            purpose=purpose,
            expires_in_seconds=expires_in_seconds,
        )

    async def latest_message(self, *, to_phone_e164: str) -> dict[str, Any] | None:
        """Return the most recent stored SMS payload for ``to_phone_e164``.

        Exposed for tests and local tooling. Returns ``None`` when no messages
        are present for the phone number.
        """
        normalized_phone = normalize_e164(to_phone_e164)
        try:
            items = await self._redis.lrange(self._key(normalized_phone), 0, 0)
        except RedisError as exc:
            raise LocalSmsSenderError("failed to read local SMS payload.") from exc
        if not items:
            return None
        try:
            return json.loads(items[0])
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _key(phone_e164: str) -> str:
        return f"sms:local:{phone_e164}"
