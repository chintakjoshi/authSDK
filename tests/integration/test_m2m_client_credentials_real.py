"""Real integration tests for Step 9 M2M client-credentials flow."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import get_jwt_service
from app.models.oauth_client import OAuthClient
from app.models.session import Session
from app.services.m2m_service import M2MService


async def _create_oauth_client(
    db_session: AsyncSession,
    *,
    client_id: str,
    raw_secret: str,
    scopes: list[str],
    is_active: bool = True,
    token_ttl_seconds: int = 3600,
) -> OAuthClient:
    """Seed one OAuth client row for client-credentials tests."""
    now = datetime.now(UTC)
    row = OAuthClient(
        client_id=client_id,
        client_secret_hash=M2MService.hash_client_secret(raw_secret),
        client_secret_prefix=M2MService.client_secret_prefix(raw_secret),
        name="Integration Worker",
        scopes=scopes,
        role="service",
        is_active=is_active,
        token_ttl_seconds=token_ttl_seconds,
        created_at=now,
        updated_at=now,
        deleted_at=None,
        tenant_id=None,
    )
    db_session.add(row)
    await db_session.commit()
    await db_session.refresh(row)
    return row


@pytest.mark.asyncio
async def test_client_credentials_flow_returns_m2m_token_without_session(
    app_factory,
    db_session: AsyncSession,
) -> None:
    """Valid client credentials mint M2M access token and never create user session rows."""
    await _create_oauth_client(
        db_session,
        client_id="billing-worker",
        raw_secret="cs_billing_secret",
        scopes=["billing:read", "billing:write"],
        token_ttl_seconds=1200,
    )
    app = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "billing-worker",
                "client_secret": "cs_billing_secret",
                "scope": "billing:read",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == 1200
    assert payload["scope"] == "billing:read"

    claims = get_jwt_service().verify_token(payload["access_token"], expected_type="m2m")
    assert claims["sub"] == "billing-worker"
    assert claims["role"] == "service"
    assert claims["scope"] == "billing:read"

    sessions = (await db_session.execute(select(Session))).scalars().all()
    assert sessions == []


@pytest.mark.asyncio
async def test_client_credentials_flow_rejects_invalid_scope(
    app_factory,
    db_session: AsyncSession,
) -> None:
    """Scopes outside the client allowlist return invalid_scope."""
    await _create_oauth_client(
        db_session,
        client_id="billing-worker",
        raw_secret="cs_billing_secret",
        scopes=["billing:read"],
    )
    app = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "billing-worker",
                "client_secret": "cs_billing_secret",
                "scope": "billing:write",
            },
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid scope.", "code": "invalid_scope"}


@pytest.mark.asyncio
async def test_client_credentials_flow_rejects_invalid_secret_and_inactive_client(
    app_factory,
    db_session: AsyncSession,
) -> None:
    """Invalid secret and inactive client both fail with 401."""
    await _create_oauth_client(
        db_session,
        client_id="billing-worker",
        raw_secret="cs_billing_secret",
        scopes=["billing:read"],
        is_active=True,
    )
    await _create_oauth_client(
        db_session,
        client_id="inactive-worker",
        raw_secret="cs_inactive_secret",
        scopes=["billing:read"],
        is_active=False,
    )
    app = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        bad_secret = await client.post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "billing-worker",
                "client_secret": "cs_wrong_secret",
            },
        )
        inactive = await client.post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "inactive-worker",
                "client_secret": "cs_inactive_secret",
            },
        )

    assert bad_secret.status_code == 401
    assert bad_secret.json() == {
        "detail": "Invalid client credentials.",
        "code": "invalid_credentials",
    }
    assert inactive.status_code == 401
    assert inactive.json() == {
        "detail": "Invalid client credentials.",
        "code": "invalid_credentials",
    }
