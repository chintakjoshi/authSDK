"""Unit tests for brute-force protection thresholds and suspicious-login state."""

from __future__ import annotations

import pytest
from redis.exceptions import RedisError

from app.services.brute_force_service import (
    BruteForceProtectionError,
    BruteForceProtectionService,
)


class _FakeRedis:
    """Redis stub covering the commands used by brute-force protection."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.hyperloglogs: dict[str, set[str]] = {}
        self.sets: dict[str, set[str]] = {}
        self.fail = False

    async def get(self, key: str) -> str | None:
        if self.fail:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def ttl(self, key: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        return self.ttls.get(key, -2)

    async def incr(self, key: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        current = int(self.values.get(key, "0"))
        current += 1
        self.values[key] = str(current)
        return current

    async def expire(self, key: str, ttl: int) -> bool:
        if self.fail:
            raise RedisError("redis unavailable")
        self.ttls[key] = ttl
        return True

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        if self.fail:
            raise RedisError("redis unavailable")
        self.values[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def delete(self, *keys: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        count = 0
        for key in keys:
            count += int(key in self.values or key in self.hyperloglogs or key in self.sets)
            self.values.pop(key, None)
            self.ttls.pop(key, None)
            self.hyperloglogs.pop(key, None)
            self.sets.pop(key, None)
        return count

    async def pfadd(self, key: str, value: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        bucket = self.hyperloglogs.setdefault(key, set())
        before = len(bucket)
        bucket.add(value)
        return int(len(bucket) > before)

    async def pfcount(self, key: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        return len(self.hyperloglogs.get(key, set()))

    async def sismember(self, key: str, value: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        return int(value in self.sets.get(key, set()))

    async def sadd(self, key: str, *values: str) -> int:
        if self.fail:
            raise RedisError("redis unavailable")
        bucket = self.sets.setdefault(key, set())
        before = len(bucket)
        bucket.update(values)
        return len(bucket) - before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attempts", "expected_retry_after"),
    [
        (5, 60),
        (6, 300),
        (7, 900),
        (8, 3600),
    ],
)
async def test_password_failures_apply_documented_lockout_thresholds(
    attempts: int,
    expected_retry_after: int,
) -> None:
    """Failed password attempts escalate lockouts at attempts 5, 6, 7, and 8+."""
    redis = _FakeRedis()
    service = BruteForceProtectionService(redis_client=redis)  # type: ignore[arg-type]

    decision = None
    for _ in range(attempts):
        decision = await service.record_failed_password_attempt("user-1", ip_address="203.0.113.10")

    assert decision is not None
    assert decision.locked is True
    assert decision.retry_after == expected_retry_after
    assert redis.ttls["lockout:user-1"] == expected_retry_after


@pytest.mark.asyncio
async def test_password_failures_before_threshold_only_increment_counter() -> None:
    """Attempts 1 through 4 do not create a lockout key."""
    redis = _FakeRedis()
    service = BruteForceProtectionService(redis_client=redis)  # type: ignore[arg-type]

    for expected_attempt in range(1, 5):
        decision = await service.record_failed_password_attempt("user-1", ip_address="203.0.113.10")
        assert decision.locked is False
        assert decision.attempt_count == expected_attempt

    assert "lockout:user-1" not in redis.values


@pytest.mark.asyncio
async def test_distributed_attack_triggers_one_hour_lock_at_ten_distinct_ips() -> None:
    """Distinct failed-login source IPs trigger the distributed lockout threshold."""
    redis = _FakeRedis()
    service = BruteForceProtectionService(redis_client=redis)  # type: ignore[arg-type]

    decision = None
    for octet in range(1, 11):
        decision = await service.record_failed_password_attempt(
            "user-1",
            ip_address=f"203.0.113.{octet}",
        )

    assert decision is not None
    assert decision.locked is True
    assert decision.distributed_attack is True
    assert decision.retry_after == 3600


@pytest.mark.asyncio
async def test_successful_login_clears_failures_and_marks_suspicious_reasons() -> None:
    """Successful login clears lockout state and emits suspicious metadata for new fingerprints."""
    redis = _FakeRedis()
    redis.values["failed_attempts:user-1"] = "3"
    redis.values["lockout:user-1"] = "1"
    service = BruteForceProtectionService(redis_client=redis)  # type: ignore[arg-type]

    result = await service.record_successful_login(
        "user-1",
        ip_address="203.0.113.5",
        user_agent="Mozilla/5.0",
    )

    assert result.suspicious is True
    assert result.metadata["new_ip"] is True
    assert result.metadata["new_user_agent"] is True
    assert result.metadata["prior_failures"] == 3
    assert "failed_attempts:user-1" not in redis.values
    assert "lockout:user-1" not in redis.values
    assert redis.ttls["seen_ips:user-1"] == 30 * 24 * 60 * 60
    assert redis.ttls["seen_agents:user-1"] == 30 * 24 * 60 * 60


@pytest.mark.asyncio
async def test_ensure_not_locked_returns_account_locked_with_retry_after() -> None:
    """Active lockout keys produce account_locked with Retry-After header."""
    redis = _FakeRedis()
    redis.values["lockout:user-1"] = "1"
    redis.ttls["lockout:user-1"] = 42
    service = BruteForceProtectionService(redis_client=redis)  # type: ignore[arg-type]

    with pytest.raises(BruteForceProtectionError) as exc_info:
        await service.ensure_not_locked("user-1")

    assert exc_info.value.code == "account_locked"
    assert exc_info.value.headers["Retry-After"] == "42"


@pytest.mark.asyncio
async def test_redis_failures_fail_closed() -> None:
    """Redis errors produce a 503-equivalent protection error."""
    redis = _FakeRedis()
    redis.fail = True
    service = BruteForceProtectionService(redis_client=redis)  # type: ignore[arg-type]

    with pytest.raises(BruteForceProtectionError) as exc_info:
        await service.record_failed_otp_attempt("user-1")

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503
