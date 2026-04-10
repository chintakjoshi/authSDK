"""Redis-backed sliding-window rate limiting middleware."""

from __future__ import annotations

import math
import time
from typing import Protocol
from uuid import uuid4

import structlog
from fastapi import Request
from redis import asyncio as redis_async
from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.config import get_settings, reloadable_singleton
from app.core.client_ip import extract_client_ip

logger = structlog.get_logger(__name__)
_WINDOW_SECONDS = 60
_FAIL_CLOSED_EXACT_PATHS = {
    "/auth/login",
    "/auth/token",
}
_FAIL_CLOSED_PREFIXES = (
    "/auth/otp/",
    "/auth/password/",
    "/auth/verify-email",
    "/auth/reauth",
)


class SlidingWindowRedis(Protocol):
    """Protocol for Redis operations used by the rate limiter."""

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        """Delete members with score inside an inclusive range."""

    async def zcard(self, key: str) -> int:
        """Return sorted-set cardinality."""

    async def zrange(
        self,
        key: str,
        start: int,
        end: int,
        *,
        withscores: bool = False,
    ) -> list[tuple[str, float]] | list[str]:
        """Return a sorted-set slice ordered by score."""

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        """Add one or more scored members to sorted set."""

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        """Apply TTL to key."""


async def _close_async_redis_client(client: Redis) -> None:
    """Close a previous async Redis client instance."""
    close = getattr(client, "aclose", None)
    if callable(close):
        await close()
        return

    close = getattr(client, "close", None)
    if callable(close):
        result = close()
        if hasattr(result, "__await__"):
            await result


@reloadable_singleton(cleanup=_close_async_redis_client)
def get_rate_limit_redis_client() -> Redis:
    """Create and cache Redis client used by rate limiter middleware."""
    settings = get_settings()
    return redis_async.from_url(
        settings.redis.url,
        decode_responses=True,
        socket_keepalive=True,
        health_check_interval=settings.redis.health_check_interval_seconds,
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Apply per-client sliding-window request limits."""

    def __init__(
        self,
        app,
        redis_client: SlidingWindowRedis | None = None,
        default_requests_per_minute: int | None = None,
        login_requests_per_minute: int | None = None,
        token_requests_per_minute: int | None = None,
    ) -> None:
        """Initialize middleware with optional explicit limits for testability."""
        super().__init__(app)
        settings = None
        if (
            redis_client is None
            or default_requests_per_minute is None
            or login_requests_per_minute is None
            or token_requests_per_minute is None
        ):
            settings = get_settings()

        self._redis = redis_client or get_rate_limit_redis_client()
        if default_requests_per_minute is None:
            assert settings is not None
            self._default_limit = settings.rate_limit.default_requests_per_minute
        else:
            self._default_limit = default_requests_per_minute

        if login_requests_per_minute is None:
            assert settings is not None
            self._login_limit = settings.rate_limit.login_requests_per_minute
        else:
            self._login_limit = login_requests_per_minute

        if token_requests_per_minute is None:
            assert settings is not None
            self._token_limit = settings.rate_limit.token_requests_per_minute
        else:
            self._token_limit = token_requests_per_minute
        self._window_milliseconds = _WINDOW_SECONDS * 1000

    async def dispatch(self, request: Request, call_next) -> Response:
        """Reject requests exceeding the configured per-minute threshold."""
        limit = self._resolve_limit(request.url.path)
        bucket_key = self._build_bucket_key(request)
        now_ms = int(time.time() * 1000)
        window_start = now_ms - self._window_milliseconds

        try:
            await self._redis.zremrangebyscore(bucket_key, "-inf", window_start)
            current_count = await self._redis.zcard(bucket_key)
            if current_count >= limit:
                retry_after = await self._retry_after_seconds(bucket_key=bucket_key, now_ms=now_ms)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded.", "code": "rate_limited"},
                    headers={"Retry-After": str(retry_after)},
                )

            member = f"{now_ms}:{uuid4()}"
            await self._redis.zadd(bucket_key, {member: now_ms})
            await self._redis.expire(bucket_key, math.ceil(self._window_milliseconds / 1000) + 1)
        except RedisError:
            # Fail closed for sensitive auth routes, but keep non-sensitive traffic available.
            logger.warning(
                "rate_limit_backend_unavailable",
                path=request.url.path,
                method=request.method,
            )
            if self._should_fail_closed(request.url.path):
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "Rate limit backend unavailable.",
                        "code": "rate_limit_unavailable",
                    },
                )

        return await call_next(request)

    async def _retry_after_seconds(self, *, bucket_key: str, now_ms: int) -> int:
        """Return the number of seconds until the oldest request leaves the window."""
        oldest_entries = await self._redis.zrange(bucket_key, 0, 0, withscores=True)
        if not oldest_entries:
            return 1

        _, oldest_score = oldest_entries[0]
        remaining_milliseconds = oldest_score + self._window_milliseconds - now_ms
        return max(1, math.ceil(remaining_milliseconds / 1000))

    def _resolve_limit(self, path: str) -> int:
        """Resolve path-specific limit override."""
        if path == "/auth/login":
            return self._login_limit
        if path == "/auth/token":
            return self._token_limit
        return self._default_limit

    def _build_bucket_key(self, request: Request) -> str:
        """Build Redis key using route and caller network identity."""
        client_id = self._extract_client_id(request)
        return f"rate_limit:{request.url.path}:{client_id}"

    @staticmethod
    def _should_fail_closed(path: str) -> bool:
        """Return True when a Redis outage should block a sensitive auth route."""
        if path in _FAIL_CLOSED_EXACT_PATHS:
            return True
        return any(path.startswith(prefix) for prefix in _FAIL_CLOSED_PREFIXES)

    @staticmethod
    def _extract_client_id(request: Request) -> str:
        """Resolve caller identity for per-client bucketing."""
        return extract_client_ip(request) or "unknown"
