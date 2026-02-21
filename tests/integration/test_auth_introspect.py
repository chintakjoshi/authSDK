"""Integration tests for API key introspection endpoint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.dependencies import get_database_session
from app.routers.auth import router
from app.services.api_key_service import APIKeyIntrospectionResult, get_api_key_service


@dataclass
class _APIKeyServiceStub:
    """Stub API key service for router integration tests."""

    result: APIKeyIntrospectionResult

    async def introspect(self, db_session: Any, raw_key: str) -> APIKeyIntrospectionResult:
        """Return configured introspection result."""
        return self.result


async def _fake_db_dependency() -> Any:
    """Provide fake DB dependency."""
    yield object()


@pytest.mark.asyncio
async def test_auth_introspect_returns_valid_payload() -> None:
    """Returns success contract for valid key."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_api_key_service] = lambda: _APIKeyServiceStub(
        result=APIKeyIntrospectionResult(
            valid=True,
            user_id="user-1",
            scopes=["svc:read"],
            key_id="key-1",
            expires_at="2030-01-01T00:00:00+00:00",
        )
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/auth/introspect", json={"api_key": "sk_test_key"})

    assert response.status_code == 200
    assert response.json() == {
        "valid": True,
        "user_id": "user-1",
        "scopes": ["svc:read"],
        "key_id": "key-1",
        "expires_at": "2030-01-01T00:00:00+00:00",
    }


@pytest.mark.asyncio
async def test_auth_introspect_returns_invalid_payload() -> None:
    """Returns failure contract for invalid key."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_api_key_service] = lambda: _APIKeyServiceStub(
        result=APIKeyIntrospectionResult(valid=False, code="invalid_api_key")
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/auth/introspect", json={"api_key": "sk_test_key"})

    assert response.status_code == 200
    assert response.json() == {"valid": False, "code": "invalid_api_key"}


@pytest.mark.asyncio
async def test_auth_introspect_returns_expired_payload() -> None:
    """Returns failure contract for expired key."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_api_key_service] = lambda: _APIKeyServiceStub(
        result=APIKeyIntrospectionResult(valid=False, code="expired_api_key")
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/auth/introspect", json={"api_key": "sk_test_key"})

    assert response.status_code == 200
    assert response.json() == {"valid": False, "code": "expired_api_key"}
