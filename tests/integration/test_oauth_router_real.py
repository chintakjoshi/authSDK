"""Integration tests for OAuth router with real DB/Redis and stubbed provider."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.sessions import get_redis_client, get_session_service
from app.services.oauth_service import OAuthService, get_oauth_service
from app.services.token_service import get_token_service


@dataclass
class _OAuthClientStub:
    """Google OAuth protocol stub used by integration router tests."""

    redirect_uri: str = "http://localhost:8000/auth/oauth/google/callback"

    def resolve_redirect_uri(self, redirect_uri: str | None) -> str:
        """Resolve redirect URI using defaults."""
        return redirect_uri or self.redirect_uri

    def generate_state(self) -> str:
        """Return deterministic state value."""
        return "state-12345678"

    def generate_nonce(self) -> str:
        """Return deterministic nonce value."""
        return "nonce-12345678"

    def generate_code_verifier(self) -> str:
        """Return deterministic PKCE code verifier."""
        return "verifier-12345678"

    async def create_google_authorization_url(
        self,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        """Return deterministic OAuth authorization URL."""
        del nonce, code_verifier
        return f"https://accounts.google.com/o/oauth2/v2/auth?state={state}&redirect_uri={redirect_uri}"

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict[str, str]:
        """Return deterministic id_token payload wrapper."""
        del code, code_verifier, redirect_uri
        return {"id_token": "stub-id-token"}

    async def verify_id_token(self, id_token: str, nonce: str) -> dict[str, object]:
        """Return deterministic verified claim-set."""
        del id_token, nonce
        return {
            "sub": "google-user-1",
            "email": "oauth-user@example.com",
            "email_verified": True,
        }


def _build_oauth_service() -> OAuthService:
    """Build OAuth service with stubbed protocol client and real state/session backends."""
    return OAuthService(
        oauth_client=_OAuthClientStub(),
        redis_client=get_redis_client(),
        token_service=get_token_service(),
        session_service=get_session_service(),
    )


@pytest.mark.asyncio
async def test_oauth_google_login_and_callback_success(app_factory) -> None:
    """OAuth login stores state in Redis and callback issues token pair."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_oauth_service] = _build_oauth_service

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login_response = await client.get("/auth/oauth/google/login")
        assert login_response.status_code == 302
        state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

        callback_response = await client.get(
            "/auth/oauth/google/callback",
            params={"state": state, "code": "oauthcode"},
        )

    assert callback_response.status_code == 200
    payload = callback_response.json()
    assert payload["access_token"]
    assert payload["refresh_token"]
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_oauth_google_callback_rejects_state_mismatch(app_factory) -> None:
    """OAuth callback fails with oauth_state_mismatch when state is unknown."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_oauth_service] = _build_oauth_service

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/oauth/google/callback",
            params={"state": "missing-state-123", "code": "oauthcode"},
        )

    assert response.status_code == 401
    assert response.json()["code"] == "oauth_state_mismatch"
    app.dependency_overrides.clear()
