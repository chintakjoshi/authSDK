"""Integration tests for SDK API key middleware behavior."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from sdk.client import AuthClient
from sdk.middleware import APIKeyAuthMiddleware


@pytest.mark.asyncio
async def test_api_key_middleware_caches_valid_introspection_for_60s() -> None:
    """Valid API key should be introspected once and then served from cache."""
    introspect_calls = 0

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        nonlocal introspect_calls
        if request.url.path == "/auth/introspect":
            introspect_calls += 1
            return httpx.Response(
                status_code=200,
                json={
                    "valid": True,
                    "key_id": "key-1",
                    "scopes": ["svc:read"],
                    "user_id": None,
                },
            )
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        APIKeyAuthMiddleware,
        auth_base_url="https://auth.local",
        auth_client=auth_client,
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"identity": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.get("/protected", headers={"x-api-key": "sk_test_valid"})
        second = await client.get("/protected", headers={"x-api-key": "sk_test_valid"})

    await auth_http_client.aclose()
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["identity"]["type"] == "api_key"
    assert first.json()["identity"]["email"] is None
    assert introspect_calls == 1


@pytest.mark.asyncio
async def test_api_key_middleware_caches_invalid_result_for_10s() -> None:
    """Invalid API key should be cached to avoid repeated introspection hits."""
    introspect_calls = 0

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        nonlocal introspect_calls
        if request.url.path == "/auth/introspect":
            introspect_calls += 1
            return httpx.Response(status_code=200, json={"valid": False, "code": "invalid_api_key"})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        APIKeyAuthMiddleware,
        auth_base_url="https://auth.local",
        auth_client=auth_client,
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"identity": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.get("/protected", headers={"x-api-key": "sk_test_invalid"})
        second = await client.get("/protected", headers={"x-api-key": "sk_test_invalid"})

    await auth_http_client.aclose()
    assert first.status_code == 401
    assert first.json()["code"] == "invalid_api_key"
    assert second.status_code == 401
    assert second.json()["code"] == "invalid_api_key"
    assert introspect_calls == 1


@pytest.mark.asyncio
async def test_api_key_middleware_returns_503_when_auth_service_unreachable() -> None:
    """Unreachable auth service must return 503 and never 401."""

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down", request=request)

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        APIKeyAuthMiddleware,
        auth_base_url="https://auth.local",
        auth_client=auth_client,
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"identity": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/protected", headers={"x-api-key": "sk_test_any"})

    await auth_http_client.aclose()
    assert response.status_code == 503
    assert response.json()["code"] == "session_expired"


@pytest.mark.asyncio
async def test_api_key_middleware_does_not_fallback_to_stale_cache() -> None:
    """Expired valid cache entry should not be used when introspection later fails."""
    introspect_calls = 0
    allow_success = True

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        nonlocal introspect_calls, allow_success
        if request.url.path == "/auth/introspect":
            introspect_calls += 1
            if allow_success:
                return httpx.Response(
                    status_code=200,
                    json={
                        "valid": True,
                        "key_id": "key-2",
                        "scopes": ["svc:write"],
                        "user_id": None,
                    },
                )
            raise httpx.ConnectError("network down", request=request)
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        APIKeyAuthMiddleware,
        auth_base_url="https://auth.local",
        auth_client=auth_client,
        valid_ttl_seconds=1,
        invalid_ttl_seconds=1,
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"identity": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.get("/protected", headers={"x-api-key": "sk_test_stale"})
        assert first.status_code == 200

        allow_success = False
        await asyncio.sleep(1.2)
        second = await client.get("/protected", headers={"x-api-key": "sk_test_stale"})

    await auth_http_client.aclose()
    assert second.status_code == 503
    assert second.json()["code"] == "session_expired"
    assert introspect_calls == 2
