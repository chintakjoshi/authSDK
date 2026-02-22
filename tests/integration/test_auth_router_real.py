"""Integration tests for auth router with real Postgres and Redis backends."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.jwt import get_jwt_service


@pytest.mark.asyncio
async def test_auth_login_refresh_logout_happy_path(
    app_factory,
    user_factory,
) -> None:
    """Password login, refresh rotation, and logout work end-to-end."""
    app: FastAPI = app_factory()
    await user_factory("alice@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_response = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": "Password123!"},
        )
        assert login_response.status_code == 200
        login_payload = login_response.json()
        assert login_payload["access_token"]
        assert login_payload["refresh_token"]
        jwt_service = get_jwt_service()
        login_access_claims = jwt_service.verify_token(
            login_payload["access_token"], expected_type="access"
        )
        assert login_access_claims["email"] == "alice@example.com"
        assert login_access_claims["email_verified"] is False
        assert login_access_claims["role"] == "user"
        assert login_access_claims["scopes"] == []

        refresh_response = await client.post(
            "/auth/token",
            json={"refresh_token": login_payload["refresh_token"]},
        )
        assert refresh_response.status_code == 200
        refresh_payload = refresh_response.json()
        assert refresh_payload["refresh_token"] != login_payload["refresh_token"]
        refresh_access_claims = jwt_service.verify_token(
            refresh_payload["access_token"], expected_type="access"
        )
        assert refresh_access_claims["email"] == "alice@example.com"
        assert refresh_access_claims["email_verified"] is False
        assert refresh_access_claims["role"] == "user"
        assert refresh_access_claims["scopes"] == []

        logout_response = await client.post(
            "/auth/logout",
            json={"refresh_token": refresh_payload["refresh_token"]},
            headers={"authorization": f"Bearer {refresh_payload['access_token']}"},
        )
        assert logout_response.status_code == 204

        refresh_after_logout = await client.post(
            "/auth/token",
            json={"refresh_token": refresh_payload["refresh_token"]},
        )
        assert refresh_after_logout.status_code == 401
        assert refresh_after_logout.json()["code"] == "session_expired"


@pytest.mark.asyncio
async def test_auth_login_rejects_invalid_credentials(
    app_factory,
    user_factory,
) -> None:
    """Invalid password returns expected auth failure payload."""
    app: FastAPI = app_factory()
    await user_factory("bob@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/login",
            json={"email": "bob@example.com", "password": "WrongPass123!"},
        )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid email or password.",
        "code": "invalid_credentials",
    }


@pytest.mark.asyncio
async def test_auth_token_rejects_unknown_refresh_token(app_factory) -> None:
    """Unknown refresh token fails closed."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/auth/token", json={"refresh_token": "x" * 32})

    assert response.status_code == 401
    assert response.json()["code"] == "session_expired"


@pytest.mark.asyncio
async def test_auth_logout_requires_valid_bearer_token(app_factory) -> None:
    """Logout without valid access token returns invalid_token."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/auth/logout", json={"refresh_token": "x" * 32})

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.asyncio
async def test_jwks_endpoint_is_public_and_returns_keys(app_factory) -> None:
    """JWKS endpoint is reachable and returns at least one RSA key."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload["keys"], list)
    assert payload["keys"]
    assert payload["keys"][0]["kty"] == "RSA"
