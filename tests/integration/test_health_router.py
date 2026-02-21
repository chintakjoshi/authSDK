"""Integration tests for health endpoints."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.error_handlers import register_exception_handlers
from app.routers.health import check_postgres_ready, check_redis_ready, router


def _build_health_app(postgres_ready: bool, redis_ready: bool) -> FastAPI:
    """Build app with health router and deterministic dependency overrides."""
    app = FastAPI()
    register_exception_handlers(app, environment="production")
    app.include_router(router)

    async def _postgres_override() -> bool:
        return postgres_ready

    async def _redis_override() -> bool:
        return redis_ready

    app.dependency_overrides[check_postgres_ready] = _postgres_override
    app.dependency_overrides[check_redis_ready] = _redis_override
    return app


@pytest.mark.asyncio
async def test_health_live_returns_200() -> None:
    """Liveness probe always returns 200."""
    app = _build_health_app(postgres_ready=False, redis_ready=False)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "live"}


@pytest.mark.asyncio
async def test_health_ready_returns_200_when_backends_are_reachable() -> None:
    """Readiness returns 200 when Postgres and Redis are up."""
    app = _build_health_app(postgres_ready=True, redis_ready=True)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_health_ready_returns_503_when_postgres_is_down() -> None:
    """Readiness returns 503 when Postgres is unavailable."""
    app = _build_health_app(postgres_ready=False, redis_ready=True)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service not ready.", "code": "session_expired"}


@pytest.mark.asyncio
async def test_health_ready_returns_503_when_redis_is_down() -> None:
    """Readiness returns 503 when Redis is unavailable."""
    app = _build_health_app(postgres_ready=True, redis_ready=False)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"detail": "Service not ready.", "code": "session_expired"}
