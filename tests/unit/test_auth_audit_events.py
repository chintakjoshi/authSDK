"""Unit tests for Step 13 auth audit event wiring."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.jwt import get_jwt_service
from app.core.sessions import get_session_service
from app.core.signing_keys import get_signing_key_service
from app.dependencies import get_database_session
from app.routers.auth import get_user_service, router
from app.services.api_key_service import APIKeyIntrospectionResult, get_api_key_service
from app.services.audit_service import get_audit_service
from app.services.token_service import TokenPair, get_token_service


@dataclass(frozen=True)
class _UserStub:
    """Minimal authenticated user shape used by auth router."""

    id: Any
    email: str


class _UserServiceStub:
    """User service stub returning one deterministic authenticated user."""

    async def authenticate_user(
        self, db_session: Any, email: str, password: str
    ) -> _UserStub | None:
        """Return a user object for the configured credential set."""
        del db_session
        if email == "alice@example.com" and password == "Password123!":
            return _UserStub(id=uuid4(), email=email)
        return None


class _TokenServiceStub:
    """Token service stub producing deterministic token pairs."""

    def __init__(self) -> None:
        self._counter = 0

    def issue_token_pair(
        self,
        user_id: str,
        email: str | None = None,
        role: str | None = None,
        scopes: list[str] | None = None,
    ) -> TokenPair:
        """Return synthetic token pair with stable format."""
        del email, role, scopes
        self._counter += 1
        return TokenPair(
            access_token=f"access-token-{self._counter}-{user_id}",
            refresh_token=f"refresh-token-{self._counter}-{user_id}",
        )


class _SessionServiceStub:
    """Session service stub for login/refresh/logout happy paths."""

    async def create_login_session(
        self,
        db_session: Any,
        user_id: Any,
        email: str,
        role: str,
        scopes: list[str],
        raw_refresh_token: str,
    ) -> Any:
        """No-op login session create."""
        del db_session, user_id, email, role, scopes, raw_refresh_token
        return uuid4()

    async def rotate_refresh_session(
        self,
        db_session: Any,
        raw_refresh_token: str,
        token_issuer: Any,
    ) -> TokenPair:
        """Issue a fresh token pair for refresh route."""
        del db_session, raw_refresh_token
        return token_issuer("user-refresh", role="user")

    async def revoke_session(
        self,
        db_session: Any,
        raw_refresh_token: str,
        access_jti: str,
        access_expiration_epoch: int,
    ) -> None:
        """No-op session revocation."""
        del db_session, raw_refresh_token, access_jti, access_expiration_epoch


class _JWTServiceStub:
    """JWT service stub for logout token verification path."""

    def verify_token(
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Return deterministic claims payload."""
        del token
        assert expected_type == "access"
        del public_keys_by_kid
        return {
            "jti": str(uuid4()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "sub": "user-refresh",
        }


class _SigningKeyServiceStub:
    """Signing key service stub for logout verification dependency."""

    async def get_verification_public_keys(self, db_session: Any) -> dict[str, str]:
        """Return one deterministic verification key mapping."""
        del db_session
        return {"kid-1": "public-key"}


class _APIKeyServiceStub:
    """API key service stub for introspection happy path."""

    async def introspect(self, db_session: Any, raw_key: str) -> APIKeyIntrospectionResult:
        """Return a valid introspection payload."""
        del db_session
        if raw_key == "sk_valid_key":
            return APIKeyIntrospectionResult(
                valid=True,
                user_id="user-refresh",
                scopes=["orders:read"],
                key_id="key-123",
                expires_at=None,
            )
        return APIKeyIntrospectionResult(valid=False, code="invalid_api_key")


class _AuditServiceStub:
    """Audit service stub collecting event emissions for assertions."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def record(self, **kwargs: Any) -> None:
        event = {key: value for key, value in kwargs.items() if key != "db"}
        self.events.append(event)


async def _fake_db_dependency() -> Any:
    """Provide fake DB dependency object."""
    yield object()


@pytest.mark.asyncio
async def test_auth_routes_emit_required_step13_audit_events() -> None:
    """Auth router emits login, issuance, refresh, logout, and API key usage events."""
    app = FastAPI()
    app.include_router(router)

    audit_stub = _AuditServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_user_service] = _UserServiceStub
    app.dependency_overrides[get_token_service] = _TokenServiceStub
    app.dependency_overrides[get_session_service] = _SessionServiceStub
    app.dependency_overrides[get_jwt_service] = _JWTServiceStub
    app.dependency_overrides[get_signing_key_service] = _SigningKeyServiceStub
    app.dependency_overrides[get_api_key_service] = _APIKeyServiceStub
    app.dependency_overrides[get_audit_service] = lambda: audit_stub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": "Password123!"},
            headers={"x-correlation-id": "cid-1"},
        )
        assert login.status_code == 200

        refresh = await client.post(
            "/auth/token",
            json={"refresh_token": login.json()["refresh_token"]},
            headers={"x-correlation-id": "cid-2"},
        )
        assert refresh.status_code == 200

        logout = await client.post(
            "/auth/logout",
            json={"refresh_token": refresh.json()["refresh_token"]},
            headers={
                "authorization": f"Bearer {refresh.json()['access_token']}",
                "x-correlation-id": "cid-3",
            },
        )
        assert logout.status_code == 204

        introspect = await client.post(
            "/auth/introspect",
            json={"api_key": "sk_valid_key"},
            headers={"x-correlation-id": "cid-4"},
        )
        assert introspect.status_code == 200
        assert introspect.json()["valid"] is True

    event_types = [event["event_type"] for event in audit_stub.events]
    assert "user.login.success" in event_types
    assert "session.created" in event_types
    assert "token.issued" in event_types
    assert "token.refreshed" in event_types
    assert "user.logout" in event_types
    assert "api_key.used" in event_types

    serialized = str(audit_stub.events)
    assert "Password123!" not in serialized
    assert "sk_valid_key" not in serialized
