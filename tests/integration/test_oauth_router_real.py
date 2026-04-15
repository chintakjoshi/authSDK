"""Integration tests for OAuth router with real DB/Redis and stubbed provider."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.jwt import get_jwt_service
from app.core.sessions import get_redis_client, get_session_service
from app.models.user import User, UserIdentity
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
        return (
            f"https://accounts.google.com/o/oauth2/auth?state={state}&redirect_uri={redirect_uri}"
        )

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
        allowed_redirect_uris=(),
    )


def _build_oauth_service_with_redirects(*allowed_redirect_uris: str) -> OAuthService:
    """Build OAuth service with explicit post-auth redirect allowlist for browser-flow tests."""
    return OAuthService(
        oauth_client=_OAuthClientStub(),
        redis_client=get_redis_client(),
        token_service=get_token_service(),
        session_service=get_session_service(),
        allowed_redirect_uris=allowed_redirect_uris,
    )


def _cookie_value(response, cookie_name: str) -> str:
    """Extract one cookie value from the response Set-Cookie headers."""
    for header in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        if cookie_name in parsed:
            return parsed[cookie_name].value
    raise AssertionError(f"Missing Set-Cookie header for {cookie_name}.")


@pytest.mark.asyncio
async def test_oauth_google_login_and_callback_success(app_factory, db_session) -> None:
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
    claims = get_jwt_service().verify_token(payload["access_token"], expected_type="access")
    assert claims["email_verified"] is True
    user = (
        await db_session.execute(
            select(User).where(User.email == "oauth-user@example.com", User.deleted_at.is_(None))
        )
    ).scalar_one()
    assert user.email_verified is True
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_oauth_google_callback_redirects_browser_flow_with_requested_audience(
    app_factory,
) -> None:
    """OAuth browser flows should set cookies, preserve caller redirect, and honor audience."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_oauth_service] = lambda: _build_oauth_service_with_redirects(
        "http://app.example.com/post-auth"
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login_response = await client.get(
            "/auth/oauth/google/login",
            params={
                "redirect_uri": "http://app.example.com/post-auth",
                "audience": "orders-api",
            },
        )
        state = parse_qs(urlparse(login_response.headers["location"]).query)["state"][0]

        callback_response = await client.get(
            "/auth/oauth/google/callback",
            params={"state": state, "code": "oauthcode"},
        )

    assert callback_response.status_code == 303
    assert callback_response.headers["location"] == "http://app.example.com/post-auth"

    access_cookie = _cookie_value(callback_response, "auth_access")
    refresh_cookie = _cookie_value(callback_response, "auth_refresh")
    csrf_cookie = _cookie_value(callback_response, "auth_csrf")

    assert access_cookie
    assert refresh_cookie
    assert csrf_cookie
    claims = get_jwt_service().verify_token(
        access_cookie,
        expected_type="access",
        expected_audience="orders-api",
    )
    assert claims["email_verified"] is True
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


@pytest.mark.asyncio
async def test_oauth_google_callback_rejects_soft_deleted_user_relogin(
    app_factory,
    db_session,
) -> None:
    """Soft-deleted OAuth accounts stay blocked instead of being recreated."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_oauth_service] = _build_oauth_service

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first_login = await client.get("/auth/oauth/google/login")
        first_state = parse_qs(urlparse(first_login.headers["location"]).query)["state"][0]
        first_callback = await client.get(
            "/auth/oauth/google/callback",
            params={"state": first_state, "code": "oauthcode"},
        )
        assert first_callback.status_code == 200

        created_user = (
            await db_session.execute(select(User).where(User.email == "oauth-user@example.com"))
        ).scalar_one()
        created_user.deleted_at = datetime.now(UTC)
        created_user.is_active = False
        await db_session.commit()

        second_login = await client.get("/auth/oauth/google/login")
        second_state = parse_qs(urlparse(second_login.headers["location"]).query)["state"][0]
        second_callback = await client.get(
            "/auth/oauth/google/callback",
            params={"state": second_state, "code": "oauthcode"},
        )

    assert second_callback.status_code == 401
    assert second_callback.json()["code"] == "invalid_credentials"

    db_session.expire_all()
    users = (
        (await db_session.execute(select(User).where(User.email == "oauth-user@example.com")))
        .scalars()
        .all()
    )
    identity = (
        await db_session.execute(
            select(UserIdentity).where(
                UserIdentity.provider == "google",
                UserIdentity.provider_user_id == "google-user-1",
            )
        )
    ).scalar_one()
    assert len(users) == 1
    assert users[0].deleted_at is not None
    assert identity.user_id == users[0].id
    app.dependency_overrides.clear()
