"""Redis-backed brute-force protection and suspicious-login tracking."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from redis.asyncio.client import Redis
from redis.exceptions import RedisError

from app.core.sessions import get_redis_client

if TYPE_CHECKING:
    from fastapi import Request

_FAILED_ATTEMPTS_TTL_SECONDS = 3600
_DISTRIBUTED_ATTACK_TTL_SECONDS = 300
_FINGERPRINT_TTL_SECONDS = 30 * 24 * 60 * 60


class BruteForceProtectionError(Exception):
    """Raised when lockout enforcement or Redis operations fail."""

    def __init__(
        self,
        detail: str,
        code: str,
        status_code: int,
        *,
        headers: dict[str, str] | None = None,
        audit_events: tuple[str, ...] = (),
        metadata: dict[str, object] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code
        self.headers = headers or {}
        self.audit_events = audit_events
        self.metadata = metadata or {}


@dataclass(frozen=True)
class FailureDecision:
    """Result of one failed login or OTP verification attempt."""

    locked: bool
    retry_after: int | None = None
    attempt_count: int = 0
    distributed_attack: bool = False


@dataclass(frozen=True)
class SuspiciousLoginResult:
    """Signals whether a successful login should emit a suspicious-login audit event."""

    suspicious: bool
    metadata: dict[str, object]


class BruteForceProtectionService:
    """Enforce account lockouts and track suspicious login fingerprints."""

    def __init__(self, redis_client: Redis) -> None:
        self._redis = redis_client

    async def get_lock_status(self, user_id: str) -> tuple[bool, int | None]:
        """Return whether an account is currently locked and the remaining TTL."""
        key = self._lockout_key(user_id)
        try:
            locked = await self._redis.get(key)
            ttl = await self._redis.ttl(key) if locked is not None else -2
        except RedisError as exc:
            raise BruteForceProtectionError(
                "Authentication backend unavailable.",
                "session_expired",
                503,
            ) from exc
        if locked is None:
            return False, None
        return True, ttl if ttl and ttl > 0 else 1

    async def ensure_not_locked(self, user_id: str) -> None:
        """Reject requests while an account lockout key is active."""
        locked, retry_after = await self.get_lock_status(user_id)
        if locked:
            raise BruteForceProtectionError(
                "Account temporarily locked.",
                "account_locked",
                401,
                headers={"Retry-After": str(retry_after or 1)},
            )

    async def record_failed_password_attempt(
        self,
        user_id: str,
        *,
        ip_address: str | None,
    ) -> FailureDecision:
        """Increment password-failure counters and apply lockout thresholds."""
        attempt_count = await self._increment_failed_attempts(user_id)
        distributed_attack = await self._record_distributed_failure(user_id, ip_address)

        if distributed_attack:
            retry_after = await self._set_lockout(user_id, 3600)
            return FailureDecision(
                locked=True,
                retry_after=retry_after,
                attempt_count=attempt_count,
                distributed_attack=True,
            )

        retry_after = self._lockout_seconds_for_attempt(attempt_count)
        if retry_after is None:
            return FailureDecision(locked=False, attempt_count=attempt_count)

        retry_after = await self._set_lockout(user_id, retry_after)
        return FailureDecision(
            locked=True,
            retry_after=retry_after,
            attempt_count=attempt_count,
            distributed_attack=False,
        )

    async def record_failed_otp_attempt(self, user_id: str) -> FailureDecision:
        """Increment shared failure counters for OTP verification failures."""
        attempt_count = await self._increment_failed_attempts(user_id)
        retry_after = self._lockout_seconds_for_attempt(attempt_count)
        if retry_after is None:
            return FailureDecision(locked=False, attempt_count=attempt_count)
        retry_after = await self._set_lockout(user_id, retry_after)
        return FailureDecision(locked=True, retry_after=retry_after, attempt_count=attempt_count)

    async def record_successful_login(
        self,
        user_id: str,
        *,
        ip_address: str | None,
        user_agent: str | None,
    ) -> SuspiciousLoginResult:
        """Clear lockout state and refresh long-lived login fingerprints."""
        failed_key = self._failed_attempts_key(user_id)
        lockout_key = self._lockout_key(user_id)
        seen_ip_key = self._seen_ip_key(user_id)
        seen_agent_key = self._seen_agent_key(user_id)

        normalized_ip = normalize_ip(ip_address)
        normalized_agent = normalize_user_agent(user_agent)

        try:
            prior_failures_raw = await self._redis.get(failed_key)
            prior_failures = int(prior_failures_raw) if prior_failures_raw is not None else 0
            new_ip = False
            new_agent = False

            if normalized_ip is not None:
                new_ip = not bool(await self._redis.sismember(seen_ip_key, normalized_ip))
            if normalized_agent is not None:
                new_agent = not bool(await self._redis.sismember(seen_agent_key, normalized_agent))

            await self._redis.delete(failed_key, lockout_key)

            if normalized_ip is not None:
                await self._redis.sadd(seen_ip_key, normalized_ip)
                await self._redis.expire(seen_ip_key, _FINGERPRINT_TTL_SECONDS)
            if normalized_agent is not None:
                await self._redis.sadd(seen_agent_key, normalized_agent)
                await self._redis.expire(seen_agent_key, _FINGERPRINT_TTL_SECONDS)
        except RedisError as exc:
            raise BruteForceProtectionError(
                "Authentication backend unavailable.",
                "session_expired",
                503,
            ) from exc

        suspicious = new_ip or new_agent or prior_failures >= 3
        return SuspiciousLoginResult(
            suspicious=suspicious,
            metadata={
                "new_ip": new_ip,
                "new_user_agent": new_agent,
                "prior_failures": prior_failures,
            },
        )

    async def _increment_failed_attempts(self, user_id: str) -> int:
        """Increment the per-account failed-attempt counter with rolling TTL."""
        key = self._failed_attempts_key(user_id)
        try:
            count = int(await self._redis.incr(key))
            await self._redis.expire(key, _FAILED_ATTEMPTS_TTL_SECONDS)
            return count
        except RedisError as exc:
            raise BruteForceProtectionError(
                "Authentication backend unavailable.",
                "session_expired",
                503,
            ) from exc

    async def _record_distributed_failure(self, user_id: str, ip_address: str | None) -> bool:
        """Track failed logins across distinct IPs using HyperLogLog."""
        normalized_ip = normalize_ip(ip_address)
        if normalized_ip is None:
            return False

        key = self._distributed_attack_key(user_id)
        try:
            await self._redis.pfadd(key, normalized_ip)
            await self._redis.expire(key, _DISTRIBUTED_ATTACK_TTL_SECONDS)
            distinct_ip_count = int(await self._redis.pfcount(key))
        except RedisError as exc:
            raise BruteForceProtectionError(
                "Authentication backend unavailable.",
                "session_expired",
                503,
            ) from exc
        return distinct_ip_count >= 10

    async def _set_lockout(self, user_id: str, duration_seconds: int) -> int:
        """Store account lockout state and return its effective Retry-After value."""
        key = self._lockout_key(user_id)
        try:
            await self._redis.set(key, "1", ex=duration_seconds)
            ttl = await self._redis.ttl(key)
        except RedisError as exc:
            raise BruteForceProtectionError(
                "Authentication backend unavailable.",
                "session_expired",
                503,
            ) from exc
        return ttl if ttl and ttl > 0 else duration_seconds

    @staticmethod
    def _lockout_seconds_for_attempt(attempt_count: int) -> int | None:
        """Map failure count to configured lockout duration."""
        if attempt_count <= 4:
            return None
        if attempt_count == 5:
            return 60
        if attempt_count == 6:
            return 300
        if attempt_count == 7:
            return 900
        return 3600

    @staticmethod
    def _failed_attempts_key(user_id: str) -> str:
        return f"failed_attempts:{user_id}"

    @staticmethod
    def _lockout_key(user_id: str) -> str:
        return f"lockout:{user_id}"

    @staticmethod
    def _distributed_attack_key(user_id: str) -> str:
        return f"distributed_attack:{user_id}"

    @staticmethod
    def _seen_ip_key(user_id: str) -> str:
        return f"seen_ips:{user_id}"

    @staticmethod
    def _seen_agent_key(user_id: str) -> str:
        return f"seen_agents:{user_id}"


def extract_client_ip(request: Request) -> str | None:
    """Extract client IP from forwarding headers or request peer address."""
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client
    if client is None:
        return None
    return client.host


def normalize_ip(ip_address: str | None) -> str | None:
    """Normalize IP strings to canonical form and drop malformed values."""
    if not ip_address:
        return None
    try:
        return str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        return None


def normalize_user_agent(user_agent: str | None) -> str | None:
    """Normalize a user agent to a compact string or None when absent."""
    if not user_agent:
        return None
    normalized = user_agent.strip()
    return normalized or None


@lru_cache
def get_brute_force_service() -> BruteForceProtectionService:
    """Create and cache brute-force protection dependency."""
    return BruteForceProtectionService(redis_client=get_redis_client())
