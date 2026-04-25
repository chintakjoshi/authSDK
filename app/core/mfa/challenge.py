"""Redis-backed MFA challenge store.

Each MFA challenge is keyed by ``(user_id, purpose)`` and stores the hashed
verification code, attempt counter, method, issued audience, and the JWT
``jti`` of the challenge token. Binding ``jti`` to the Redis row makes the
signed challenge JWT single-use: when ``delete`` fires on successful verify
or attempt exhaustion, any subsequent verify attempt with the same challenge
JWT fails its ``jti`` match check. Redis remains the authoritative state for
whether a challenge is still live — the JWT alone is insufficient.

The store does not generate JTIs or call Redis directly outside these helpers;
callers (``MfaService``) own the creation of code material and JTI values.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from typing import Final, Literal

from redis.asyncio.client import Redis
from redis.exceptions import RedisError

MfaMethod = Literal["sms"]
MfaChallengePurpose = Literal["login", "action", "phone_verify"]

_AUDIENCE_FIELD: Final[str] = "audience_json"
_EXTRA_FIELD: Final[str] = "extra_json"


class MfaChallengeStoreError(Exception):
    """Raised for Redis backend failures or jti/binding mismatches."""

    def __init__(
        self,
        detail: str,
        code: str,
        *,
        status_code: int = 503,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class ChallengeState:
    """Deserialized view of one persisted MFA challenge row."""

    user_id: str
    purpose: MfaChallengePurpose
    method: MfaMethod
    code_hash: str
    attempt_count: int
    jti: str
    audience: str | list[str] | None
    created_at: datetime
    extra: dict[str, str] = dataclass_field(default_factory=dict)


class MfaChallengeStore:
    """Atomic read/write access to per-user, per-purpose challenge state."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    async def store(
        self,
        *,
        user_id: str,
        purpose: MfaChallengePurpose,
        method: MfaMethod,
        code_hash: str,
        jti: str,
        ttl_seconds: int,
        audience: str | list[str] | None = None,
        extra: dict[str, str] | None = None,
    ) -> None:
        """Persist a fresh challenge, overwriting any prior row for (user, purpose).

        ``extra`` lets callers attach purpose-specific metadata (for example the
        pending phone ciphertext during a phone-verify flow, or the action name
        on an action challenge) that survives the round trip through Redis.
        Reserved field names (``user_id``, ``purpose``, ``method``,
        ``code_hash``, ``attempt_count``, ``jti``, ``created_at``,
        ``audience_json``, ``extra_json``) are silently overwritten by the
        canonical payload to prevent shadow data.
        """
        if not user_id.strip():
            raise ValueError("user_id must be non-empty.")
        if not jti.strip():
            raise ValueError("jti must be non-empty.")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive.")

        key = self._key(user_id=user_id, purpose=purpose)
        payload: dict[str, str] = {
            "user_id": user_id,
            "purpose": purpose,
            "method": method,
            "code_hash": code_hash,
            "attempt_count": "0",
            "jti": jti,
            "created_at": datetime.now(UTC).isoformat(),
            _AUDIENCE_FIELD: json.dumps(audience) if audience is not None else "",
            _EXTRA_FIELD: json.dumps(extra) if extra else "",
        }

        try:
            await self._redis.delete(key)
            await self._redis.hset(key, mapping=payload)
            await self._redis.expire(key, ttl_seconds)
        except RedisError as exc:
            raise MfaChallengeStoreError(
                "Session backend unavailable.",
                "session_backend_unavailable",
            ) from exc

    async def store_safely(
        self,
        *,
        user_id: str,
        purpose: MfaChallengePurpose,
        method: MfaMethod,
        code_hash: str,
        jti: str,
        ttl_seconds: int,
        audience: str | list[str] | None = None,
        pending_phone_ciphertext: bytes | None = None,
        pending_phone_lookup_hash: str | None = None,
    ) -> None:
        """Phone-verify-flavored ``store`` that bundles pending phone state.

        The ciphertext is hex-encoded for safe round-tripping through Redis.
        Callers can read it back via :meth:`read_extra` using the
        ``pending_phone_ciphertext_hex`` and ``pending_phone_lookup_hash`` keys.
        """
        extra: dict[str, str] = {}
        if pending_phone_ciphertext is not None:
            extra["pending_phone_ciphertext_hex"] = pending_phone_ciphertext.hex()
        if pending_phone_lookup_hash is not None:
            extra["pending_phone_lookup_hash"] = pending_phone_lookup_hash
        await self.store(
            user_id=user_id,
            purpose=purpose,
            method=method,
            code_hash=code_hash,
            jti=jti,
            ttl_seconds=ttl_seconds,
            audience=audience,
            extra=extra or None,
        )

    @staticmethod
    def read_extra(*, challenge: ChallengeState, key: str) -> str | None:
        """Return one extra field by name from a loaded :class:`ChallengeState`."""
        return challenge.extra.get(key) if challenge.extra else None

    async def load(
        self,
        *,
        user_id: str,
        purpose: MfaChallengePurpose,
    ) -> ChallengeState | None:
        """Return the challenge state for ``(user_id, purpose)`` or ``None`` when absent."""
        key = self._key(user_id=user_id, purpose=purpose)
        try:
            raw = await self._redis.hgetall(key)
        except RedisError as exc:
            raise MfaChallengeStoreError(
                "Session backend unavailable.",
                "session_backend_unavailable",
            ) from exc
        if not raw:
            return None
        return self._deserialize(raw)

    async def increment_attempts(
        self,
        *,
        user_id: str,
        purpose: MfaChallengePurpose,
    ) -> int:
        """Atomically increment the attempt counter and return the new value."""
        key = self._key(user_id=user_id, purpose=purpose)
        try:
            return int(await self._redis.hincrby(key, "attempt_count", 1))
        except RedisError as exc:
            raise MfaChallengeStoreError(
                "Session backend unavailable.",
                "session_backend_unavailable",
            ) from exc

    async def delete(
        self,
        *,
        user_id: str,
        purpose: MfaChallengePurpose,
    ) -> None:
        """Remove the challenge row, making subsequent jti checks fail."""
        key = self._key(user_id=user_id, purpose=purpose)
        try:
            await self._redis.delete(key)
        except RedisError as exc:
            raise MfaChallengeStoreError(
                "Session backend unavailable.",
                "session_backend_unavailable",
            ) from exc

    @staticmethod
    def assert_jti_matches(*, state: ChallengeState, claimed_jti: str) -> None:
        """Raise ``MfaChallengeStoreError`` when the claimed jti does not match state."""
        trimmed = (claimed_jti or "").strip()
        if not trimmed or not hmac.compare_digest(trimmed, state.jti):
            raise MfaChallengeStoreError(
                "Challenge reuse detected.",
                "challenge_reused",
                status_code=401,
            )

    @staticmethod
    def _key(*, user_id: str, purpose: MfaChallengePurpose) -> str:
        return f"mfa:challenge:{purpose}:{user_id}"

    def _deserialize(self, raw: dict[str, str]) -> ChallengeState:
        """Parse a Redis hash payload into :class:`ChallengeState`."""
        audience_raw = raw.get(_AUDIENCE_FIELD, "")
        audience: str | list[str] | None
        if not audience_raw:
            audience = None
        else:
            try:
                audience = json.loads(audience_raw)
            except json.JSONDecodeError:
                audience = None

        try:
            created_at = datetime.fromisoformat(raw["created_at"])
        except (KeyError, ValueError):
            created_at = datetime.now(UTC)

        extra_raw = raw.get(_EXTRA_FIELD, "")
        try:
            extra: dict[str, str] = (
                {str(k): str(v) for k, v in json.loads(extra_raw).items()} if extra_raw else {}
            )
        except (json.JSONDecodeError, AttributeError):
            extra = {}

        return ChallengeState(
            user_id=raw.get("user_id", ""),
            purpose=raw.get("purpose", "login"),  # type: ignore[arg-type]
            method=raw.get("method", "sms"),  # type: ignore[arg-type]
            code_hash=raw.get("code_hash", ""),
            attempt_count=int(raw.get("attempt_count", "0") or 0),
            jti=raw.get("jti", ""),
            audience=audience,
            created_at=created_at,
            extra=extra,
        )
