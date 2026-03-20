"""Integration tests for API key router and introspection endpoint."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.session import get_session_factory
from app.models.user import User


@pytest.mark.asyncio
async def test_apikey_create_list_revoke_and_introspect_flow(app_factory) -> None:
    """API key lifecycle works end-to-end and introspection reflects revocation."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        admin_signup = await client.post(
            "/auth/signup",
            json={"email": "keys-admin@example.com", "password": "Password123!"},
        )
        assert admin_signup.status_code == 201
        async with get_session_factory()() as session:
            user = (
                await session.execute(select(User).where(User.email == "keys-admin@example.com"))
            ).scalar_one()
            user.role = "admin"
            user.email_verified = True
            await session.commit()

        login_response = await client.post(
            "/auth/login",
            json={"email": "keys-admin@example.com", "password": "Password123!"},
        )
        assert login_response.status_code == 200
        headers = {"authorization": f"Bearer {login_response.json()['access_token']}"}

        create_response = await client.post(
            "/auth/apikeys",
            json={
                "name": "Orders Primary Key",
                "scope": "orders:read",
                "expires_at": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            },
            headers=headers,
        )
        assert create_response.status_code == 200
        created = create_response.json()
        assert created["api_key"].startswith("sk_")
        assert created["key_prefix"] == created["api_key"][:8]
        assert created["name"] == "Orders Primary Key"
        assert created["service"] == "orders"

        list_response = await client.get("/auth/apikeys", headers=headers)
        assert list_response.status_code == 200
        listed = list_response.json()
        assert len(listed) == 1
        assert listed[0]["name"] == "Orders Primary Key"
        assert listed[0]["service"] == "orders"
        assert "api_key" not in listed[0]

        valid_introspect = await client.post(
            "/auth/introspect",
            json={"api_key": created["api_key"]},
        )
        assert valid_introspect.status_code == 200
        assert valid_introspect.json()["valid"] is True
        assert valid_introspect.json()["scopes"] == ["orders:read"]
        assert valid_introspect.json()["service"] == "orders"

        revoke_response = await client.post(
            f"/auth/apikeys/{created['key_id']}/revoke",
            headers=headers,
        )
        assert revoke_response.status_code == 200
        assert revoke_response.json()["code"] == "revoked_api_key"

        revoked_introspect = await client.post(
            "/auth/introspect",
            json={"api_key": created["api_key"]},
        )
        assert revoked_introspect.status_code == 200
        assert revoked_introspect.json() == {"valid": False, "code": "revoked_api_key"}


@pytest.mark.asyncio
async def test_auth_introspect_returns_invalid_for_unknown_key(app_factory) -> None:
    """Unknown API key returns valid=false invalid_api_key contract."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/auth/introspect", json={"api_key": "sk_unknown_key"})

    assert response.status_code == 200
    assert response.json() == {"valid": False, "code": "invalid_api_key"}


@pytest.mark.asyncio
async def test_auth_introspect_returns_expired_for_expired_key(app_factory) -> None:
    """Expired API key returns expected expired_api_key introspection code."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        admin_signup = await client.post(
            "/auth/signup",
            json={"email": "billing-admin@example.com", "password": "Password123!"},
        )
        assert admin_signup.status_code == 201
        async with get_session_factory()() as session:
            user = (
                await session.execute(select(User).where(User.email == "billing-admin@example.com"))
            ).scalar_one()
            user.role = "admin"
            user.email_verified = True
            await session.commit()

        login_response = await client.post(
            "/auth/login",
            json={"email": "billing-admin@example.com", "password": "Password123!"},
        )
        headers = {"authorization": f"Bearer {login_response.json()['access_token']}"}

        create_response = await client.post(
            "/auth/apikeys",
            json={
                "service": "billing",
                "scope": "billing:write",
                "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
            },
            headers=headers,
        )
        created = create_response.json()
        response = await client.post("/auth/introspect", json={"api_key": created["api_key"]})

    assert response.status_code == 200
    assert response.json() == {"valid": False, "code": "expired_api_key"}
