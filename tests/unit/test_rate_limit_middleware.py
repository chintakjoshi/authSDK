"""Unit tests for rate-limit middleware failure behavior."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.exceptions import RedisError

from app.middleware.rate_limit import RateLimitMiddleware


class _FailingRedis:
    """Redis stub that simulates an unavailable backend."""

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        del key, min, max
        raise RedisError("redis unavailable")

    async def zcard(self, key: str) -> int:
        del key
        raise AssertionError("zcard should not run after backend failure")

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        del key, mapping
        raise AssertionError("zadd should not run after backend failure")

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        del key, ttl_seconds
        raise AssertionError("expire should not run after backend failure")


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
