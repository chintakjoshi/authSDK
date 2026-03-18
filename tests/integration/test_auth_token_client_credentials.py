"""Router-level tests for /auth/token client-credentials handling."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.sessions import get_session_service
from app.dependencies import get_database_session
from app.routers.auth import router
from app.services.audit_service import get_audit_service
from app.services.m2m_service import ClientCredentialsTokenResult, M2MServiceError, get_m2m_service
from app.services.token_service import TokenPair, get_token_service


@dataclass
class _AuditServiceStub:
    """Audit stub collecting emitted event types."""

    events: list[str]

    async def record(self, **kwargs: Any) -> None:
        self.events.append(str(kwargs["event_type"]))


class _SessionServiceStub:
    """Session service stub for refresh branch and M2M guardrails."""

    async def rotate_refresh_session(
        self,
        db_session: Any,
        raw_refresh_token: str,
        token_issuer: Any,
    ) -> TokenPair:
        del db_session, raw_refresh_token
        return await token_issuer("user-1", email="user@example.com", role="user", scopes=[])


class _TokenServiceStub:
    """Token service stub used by refresh tests."""

    async def issue_token_pair(
        self,
        *,
        db_session: Any,
        user_id: str,
        email: str | None = None,
        role: str = "user",
        scopes: list[str] | None = None,
        email_verified: bool = False,
        email_otp_enabled: bool = False,
        auth_time=None,
    ) -> TokenPair:
        del db_session, email, role, scopes, email_verified, email_otp_enabled, auth_time
        return TokenPair(
            access_token=f"access-{user_id}",
            refresh_token=f"refresh-{user_id}",
        )


class _M2MServiceStub:
    """M2M stub issuing or rejecting client-credentials tokens."""

    async def authenticate_client_credentials(
        self,
        db_session: Any,
        *,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        audience: str | None = None,
    ) -> ClientCredentialsTokenResult:
        del db_session, client_secret, audience
        if scope == "bad:scope":
            raise M2MServiceError("Invalid scope.", "invalid_scope", 400)
        return ClientCredentialsTokenResult(
            access_token=f"m2m-{client_id}",
            expires_in=3600,
            scope=scope or "billing:read",
            client_id=client_id,
        )


async def _fake_db_dependency() -> Any:
    """Provide fake DB dependency."""
    yield object()


@pytest.mark.asyncio
async def test_auth_token_accepts_client_credentials_form_requests() -> None:
    """Client credentials requests return OAuth access-token response shape."""
    app = FastAPI()
    app.include_router(router)
    audit_stub = _AuditServiceStub(events=[])
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_m2m_service] = _M2MServiceStub
    app.dependency_overrides[get_audit_service] = lambda: audit_stub

    class _NeverSessionService:
        async def rotate_refresh_session(self, *args: Any, **kwargs: Any) -> TokenPair:
            raise AssertionError("M2M branch must not touch session rotation")

    app.dependency_overrides[get_session_service] = _NeverSessionService
    app.dependency_overrides[get_token_service] = _TokenServiceStub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "billing-worker",
                "client_secret": "cs_secret",
                "scope": "billing:read",
            },
        )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "m2m-billing-worker",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "billing:read",
    }
    assert "client.authenticated" in audit_stub.events


@pytest.mark.asyncio
async def test_auth_token_returns_invalid_scope_for_bad_client_scope() -> None:
    """Bad client-credentials scope requests return the documented error code."""
    app = FastAPI()
    app.include_router(router)
    audit_stub = _AuditServiceStub(events=[])
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_m2m_service] = _M2MServiceStub
    app.dependency_overrides[get_audit_service] = lambda: audit_stub
    app.dependency_overrides[get_session_service] = _SessionServiceStub
    app.dependency_overrides[get_token_service] = _TokenServiceStub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/auth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "billing-worker",
                "client_secret": "cs_secret",
                "scope": "bad:scope",
            },
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid scope.", "code": "invalid_scope"}
    assert "client.auth.failure" in audit_stub.events


@pytest.mark.asyncio
async def test_auth_token_preserves_json_refresh_flow() -> None:
    """JSON refresh requests still use the existing refresh-token path."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_m2m_service] = _M2MServiceStub
    app.dependency_overrides[get_audit_service] = lambda: _AuditServiceStub(events=[])
    app.dependency_overrides[get_session_service] = _SessionServiceStub
    app.dependency_overrides[get_token_service] = _TokenServiceStub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/auth/token", json={"refresh_token": "r" * 32})

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "access-user-1",
        "refresh_token": "refresh-user-1",
        "token_type": "bearer",
    }
