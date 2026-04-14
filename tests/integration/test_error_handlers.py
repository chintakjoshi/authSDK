"""Integration tests for global exception handlers."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from app.error_handlers import register_exception_handlers


def _build_error_app(environment: str = "production") -> FastAPI:
    """Build minimal app with registered global exception handlers."""
    app = FastAPI()
    register_exception_handlers(app, environment=environment)

    @app.get("/auth/http-exception")
    async def auth_http_exception() -> None:
        raise HTTPException(
            status_code=401, detail={"detail": "Invalid token.", "code": "invalid_token"}
        )

    @app.get("/auth/unhandled")
    async def auth_unhandled() -> None:
        raise RuntimeError("sensitive internal detail")

    @app.get("/auth/validation")
    async def auth_validation(required_value: int) -> dict[str, int]:
        return {"required_value": required_value}

    @app.get("/auth/http-404")
    async def auth_http_404() -> None:
        raise HTTPException(status_code=404, detail="Not found.")

    @app.get("/auth/http-503")
    async def auth_http_503() -> None:
        raise HTTPException(status_code=503, detail="Backend unavailable.")

    @app.get("/auth/get-only")
    async def auth_get_only() -> dict[str, bool]:
        return {"ok": True}

    return app


@pytest.mark.asyncio
async def test_http_exception_uses_standard_error_shape() -> None:
    """HTTP exceptions are normalized to detail/code payload."""
    app = _build_error_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/http-exception")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid token.", "code": "invalid_token"}


@pytest.mark.asyncio
async def test_validation_error_uses_standard_error_shape() -> None:
    """Validation failures return standardized payload contract."""
    app = _build_error_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/validation")

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request payload.", "code": "invalid_credentials"}


@pytest.mark.asyncio
async def test_unhandled_error_hides_internal_detail_in_production() -> None:
    """Unhandled errors are sanitized in production mode."""
    app = _build_error_app(environment="production")
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/auth/unhandled")

    assert response.status_code == 500
    assert response.json() == {
        "detail": "Internal server error.",
        "code": "internal_server_error",
    }


@pytest.mark.asyncio
async def test_not_found_error_uses_semantically_correct_default_code() -> None:
    """404 HTTP exceptions without explicit codes should not masquerade as invalid tokens."""
    app = _build_error_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/http-404")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found.", "code": "not_found"}


@pytest.mark.asyncio
async def test_method_not_allowed_uses_semantically_correct_default_code() -> None:
    """405 framework errors should expose a method-specific machine-readable code."""
    app = _build_error_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/auth/get-only")

    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed", "code": "method_not_allowed"}


@pytest.mark.asyncio
async def test_service_unavailable_uses_infrastructure_failure_default_code() -> None:
    """503 HTTP exceptions without explicit codes should signal service unavailability."""
    app = _build_error_app()
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/http-503")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Backend unavailable.",
        "code": "service_unavailable",
    }
