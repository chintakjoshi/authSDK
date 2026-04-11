"""Unit tests for rate-limit middleware failure behavior."""

from __future__ import annotations

import types

import pytest
import starlette.middleware.base as base_middleware
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.exceptions import RedisError

import app.middleware.rate_limit as rate_limit_module
from app.middleware.rate_limit import RateLimitMiddleware


class _FailingRedis:
    """Redis stub that simulates an unavailable backend."""

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        del key, min, max
        raise RedisError("redis unavailable")

    async def zcard(self, key: str) -> int:
        del key
        raise AssertionError("zcard should not run after backend failure")

    async def zrange(
        self,
        key: str,
        start: int,
        end: int,
        *,
        withscores: bool = False,
    ) -> list[tuple[str, float]] | list[str]:
        del key, start, end, withscores
        raise AssertionError("zrange should not run after backend failure")

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        del key, mapping
        raise AssertionError("zadd should not run after backend failure")

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        del key, ttl_seconds
        raise AssertionError("expire should not run after backend failure")


class _InMemoryRedis:
    """Redis stub that supports the sliding-window operations used by the middleware."""

    def __init__(self) -> None:
        self._buckets: dict[str, dict[str, int]] = {}

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        del min
        bucket = self._buckets.get(key, {})
        to_remove = [member for member, score in bucket.items() if score <= max]
        for member in to_remove:
            del bucket[member]
        return len(to_remove)

    async def zcard(self, key: str) -> int:
        return len(self._buckets.get(key, {}))

    async def zrange(
        self,
        key: str,
        start: int,
        end: int,
        *,
        withscores: bool = False,
    ) -> list[tuple[str, float]] | list[str]:
        bucket = sorted(self._buckets.get(key, {}).items(), key=lambda item: item[1])
        stop = None if end == -1 else end + 1
        window = bucket[start:stop]
        if withscores:
            return [(member, float(score)) for member, score in window]
        return [member for member, _ in window]

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        bucket = self._buckets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if member not in bucket:
                added += 1
            bucket[member] = score
        return added

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        del key, ttl_seconds
        return True


def _build_app() -> FastAPI:
    """Create a small app with rate limiting enabled for middleware tests."""
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        redis_client=_FailingRedis(),
        default_requests_per_minute=100,
        login_requests_per_minute=10,
        token_requests_per_minute=10,
    )

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    @app.post("/auth/login")
    async def login() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/auth/otp/request/action")
    async def request_action() -> dict[str, str]:
        return {"status": "ok"}

    return app


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/auth/login", "/auth/otp/request/action"])
async def test_rate_limit_fails_closed_for_sensitive_auth_routes(path: str) -> None:
    """Sensitive auth routes return 503 when the rate-limit backend is unavailable."""
    app = _build_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(path)

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Rate limit backend unavailable.",
        "code": "rate_limit_unavailable",
    }


@pytest.mark.asyncio
async def test_rate_limit_keeps_non_sensitive_routes_available_on_backend_failure() -> None:
    """Non-sensitive routes continue through when the rate-limit backend is unavailable."""
    app = _build_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "live"}


@pytest.mark.asyncio
async def test_rate_limit_rejection_includes_retry_after_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rate-limited responses include the remaining time until the window resets."""
    redis_stub = _InMemoryRedis()
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        redis_client=redis_stub,
        default_requests_per_minute=100,
        login_requests_per_minute=1,
        token_requests_per_minute=10,
    )

    @app.post("/auth/login")
    async def login() -> dict[str, str]:
        return {"status": "ok"}

    request_times = iter((1000.0, 1000.2))
    monkeypatch.setattr(
        rate_limit_module,
        "time",
        types.SimpleNamespace(time=lambda: next(request_times)),
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        first = await client.post("/auth/login")
        second = await client.post("/auth/login")

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == {
        "detail": "Rate limit exceeded.",
        "code": "rate_limited",
    }
    assert second.headers["Retry-After"] == "60"


@pytest.mark.asyncio
async def test_rate_limit_middleware_does_not_use_base_http_streaming_wrapper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rate limiter runs as pure ASGI middleware without BaseHTTPMiddleware wrappers."""
    redis_stub = _InMemoryRedis()
    app = FastAPI()
    app.add_middleware(
        RateLimitMiddleware,
        redis_client=redis_stub,
        default_requests_per_minute=100,
        login_requests_per_minute=10,
        token_requests_per_minute=10,
    )

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "live"}

    streaming_wrapper_calls = 0
    original_init = base_middleware._StreamingResponse.__init__

    def _tracking_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal streaming_wrapper_calls
        streaming_wrapper_calls += 1
        return original_init(self, *args, **kwargs)

    monkeypatch.setattr(base_middleware._StreamingResponse, "__init__", _tracking_init)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "live"}
    assert streaming_wrapper_calls == 0
