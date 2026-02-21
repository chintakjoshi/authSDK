"""Integration tests for OAuth router behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.dependencies import get_database_session
from app.routers.oauth import router
from app.services.oauth_service import OAuthServiceError, get_oauth_service


@dataclass(frozen=True)
class _TokenPairStub:
    """Minimal token pair object for callback success tests."""

    access_token: str
    refresh_token: str


class _OAuthServiceStub:
    """Stub OAuth service for router-level integration tests."""

    def __init__(
        self,
        login_url: str = "https://accounts.google.com/o/oauth2/v2/auth?state=test-state",
        callback_result: _TokenPairStub | OAuthServiceError | None = None,
    ) -> None:
        self.login_url = login_url
        self.callback_result = callback_result

    async def build_google_login_url(self, redirect_uri: str | None) -> str:
        """Return deterministic login URL for redirect tests."""
        return self.login_url

    async def complete_google_callback(
        self,
        db_session: Any,
        state: str,
        code: str,
    ) -> _TokenPairStub:
        """Return token pair or raise configured error."""
        if isinstance(self.callback_result, OAuthServiceError):
            raise self.callback_result
        assert self.callback_result is not None
        return self.callback_result


async def _fake_db_dependency() -> Any:
    """Provide a fake DB dependency object."""
    yield object()


@pytest.mark.asyncio
async def test_google_login_redirects_to_google_url() -> None:
    """Login endpoint redirects browser to OAuth provider URL."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_oauth_service] = lambda: _OAuthServiceStub()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/oauth/google/login")

    assert response.status_code == 302
    assert response.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth")


@pytest.mark.asyncio
async def test_google_callback_rejects_state_mismatch() -> None:
    """Callback endpoint returns oauth_state_mismatch on missing/invalid state."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_oauth_service] = lambda: _OAuthServiceStub(
        callback_result=OAuthServiceError(
            detail="OAuth state mismatch.",
            code="oauth_state_mismatch",
            status_code=401,
        )
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/oauth/google/callback",
            params={"state": "missing-state", "code": "auth-code"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "OAuth state mismatch.", "code": "oauth_state_mismatch"}


@pytest.mark.asyncio
async def test_google_callback_returns_token_pair_on_success() -> None:
    """Callback endpoint returns access and refresh token on successful exchange."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_oauth_service] = lambda: _OAuthServiceStub(
        callback_result=_TokenPairStub(
            access_token="access-token-value",
            refresh_token="refresh-token-value",
        )
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/oauth/google/callback",
            params={"state": "valid-state", "code": "auth-code"},
        )

    assert response.status_code == 200
    assert response.json()["access_token"] == "access-token-value"
    assert response.json()["refresh_token"] == "refresh-token-value"
    assert response.json()["token_type"] == "bearer"
