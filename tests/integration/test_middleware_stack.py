"""Integration tests for Step 8 middleware stack behavior."""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from app.middleware.correlation_id import CorrelationIdMiddleware
from app.middleware.logging import LoggingMiddleware
from app.middleware.metrics import MetricsMiddleware, MetricsRegistry, build_metrics_endpoint
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.tracing import TracingMiddleware

_SECURITY_HEADERS = {
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
}


class _InMemoryRateLimitRedis:
    """In-memory Redis-like primitive for rate limiting middleware tests."""

    def __init__(self) -> None:
        self._buckets: dict[str, dict[str, int]] = {}

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        """Delete scores <= max and return removed count."""
        del min
        bucket = self._buckets.get(key, {})
        to_remove = [member for member, score in bucket.items() if score <= max]
        for member in to_remove:
            del bucket[member]
        return len(to_remove)

    async def zcard(self, key: str) -> int:
        """Return cardinality for key bucket."""
        return len(self._buckets.get(key, {}))

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        """Add mapping entries to bucket and return number of newly-added members."""
        bucket = self._buckets.setdefault(key, {})
        added = 0
        for member, score in mapping.items():
            if member not in bucket:
                added += 1
            bucket[member] = score
        return added

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        """No-op TTL support for protocol compatibility."""
        del key, ttl_seconds
        return True


def _build_test_app(login_limit: int = 10) -> FastAPI:
    """Build test app with middleware stack wired in production order."""
    app = FastAPI()
    registry = MetricsRegistry()
    redis_stub = _InMemoryRateLimitRedis()

    app.add_middleware(TracingMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        redis_client=redis_stub,
        default_requests_per_minute=1000,
        login_requests_per_minute=login_limit,
        token_requests_per_minute=1000,
    )
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(MetricsMiddleware, registry=registry)
    app.add_middleware(CorrelationIdMiddleware)

    app.add_api_route(
        "/metrics",
        build_metrics_endpoint(registry=registry),
        methods=["GET"],
        include_in_schema=False,
    )

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/client-error")
    async def client_error() -> None:
        raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/server-error")
    async def server_error() -> None:
        raise HTTPException(status_code=500, detail="server-error")

    @app.post("/auth/login")
    async def login() -> dict[str, bool]:
        return {"ok": True}

    return app


def _assert_security_headers(headers: dict[str, str]) -> None:
    """Assert required security headers are set on response."""
    for header_name, expected_value in _SECURITY_HEADERS.items():
        assert headers.get(header_name) == expected_value


@pytest.mark.asyncio
async def test_headers_present_on_success_and_error_responses() -> None:
    """Correlation ID and security headers are present on 2xx/4xx/5xx."""
    app = _build_test_app()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        ok_response = await client.get("/ok", headers={"x-correlation-id": "cid-test"})
        client_error = await client.get("/client-error")
        server_error = await client.get("/server-error")

    assert ok_response.status_code == 200
    assert ok_response.headers["x-correlation-id"] == "cid-test"
    _assert_security_headers(dict(ok_response.headers))

    assert client_error.status_code == 401
    assert client_error.headers.get("x-correlation-id")
    _assert_security_headers(dict(client_error.headers))

    assert server_error.status_code == 500
    assert server_error.headers.get("x-correlation-id")
    _assert_security_headers(dict(server_error.headers))


@pytest.mark.asyncio
async def test_rate_limit_rejects_auth_login_with_required_error_code() -> None:
    """Rate limiter returns 429 with code=rate_limited on /auth/login overage."""
    app = _build_test_app(login_limit=1)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.post("/auth/login")
        second = await client.post("/auth/login")

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == {"detail": "Rate limit exceeded.", "code": "rate_limited"}


@pytest.mark.asyncio
async def test_metrics_include_rejected_requests() -> None:
    """Prometheus metrics include requests rejected by rate limiter."""
    app = _build_test_app(login_limit=1)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await client.post("/auth/login")
        await client.post("/auth/login")
        metrics_response = await client.get("/metrics")

    assert metrics_response.status_code == 200
    assert "auth_service_http_requests_total" in metrics_response.text
    assert re.search(
        r'auth_service_http_requests_total\{[^}]*method="POST"[^}]*path="/auth/login"[^}]*status="429"[^}]*\}\s+1(?:\.0+)?',
        metrics_response.text,
    )
