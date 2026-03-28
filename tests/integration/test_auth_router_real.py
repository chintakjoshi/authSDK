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
    await user_factory("alice@example.com", "Password123!", email_verified=True)

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
        assert login_access_claims["email_verified"] is True
        assert login_access_claims["email_otp_enabled"] is False
        assert login_access_claims["role"] == "user"
        assert login_access_claims["scopes"] == []
        assert isinstance(login_access_claims["auth_time"], int)

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
        assert refresh_access_claims["email_verified"] is True
        assert refresh_access_claims["email_otp_enabled"] is False
        assert refresh_access_claims["role"] == "user"
        assert refresh_access_claims["scopes"] == []
        assert refresh_access_claims["auth_time"] == login_access_claims["auth_time"]

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
async def test_auth_cookie_login_refresh_logout_happy_path(
    app_factory,
    user_factory,
) -> None:
    """Cookie-mode login, refresh, and logout work end-to-end for browser clients."""
    app: FastAPI = app_factory()
    await user_factory("cookie-alice@example.com", "Password123!", email_verified=True)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        csrf_response = await client.get("/auth/csrf")
        assert csrf_response.status_code == 200
        csrf_token = csrf_response.json()["csrf_token"]

        login_response = await client.post(
            "/auth/login",
            json={"email": "cookie-alice@example.com", "password": "Password123!"},
            headers={
                "X-Auth-Session-Transport": "cookie",
                "X-CSRF-Token": csrf_token,
            },
        )
        assert login_response.status_code == 200
        assert login_response.json() == {
            "authenticated": True,
            "session_transport": "cookie",
        }

        jwt_service = get_jwt_service()
        login_access_token = client.cookies.get("auth_access")
        login_refresh_token = client.cookies.get("auth_refresh")
        assert login_access_token
        assert login_refresh_token
        login_access_claims = jwt_service.verify_token(login_access_token, expected_type="access")
        assert login_access_claims["email"] == "cookie-alice@example.com"
        assert login_access_claims["email_verified"] is True
        assert login_access_claims["role"] == "user"

        refresh_response = await client.post(
            "/auth/token",
            headers={
                "X-Auth-Session-Transport": "cookie",
                "X-CSRF-Token": csrf_token,
            },
        )
        assert refresh_response.status_code == 200
        assert refresh_response.json() == {
            "authenticated": True,
            "session_transport": "cookie",
        }

        refreshed_access_token = client.cookies.get("auth_access")
        refreshed_refresh_token = client.cookies.get("auth_refresh")
        assert refreshed_access_token
        assert refreshed_refresh_token
        assert refreshed_refresh_token != login_refresh_token
        refresh_access_claims = jwt_service.verify_token(
            refreshed_access_token, expected_type="access"
        )
        assert refresh_access_claims["email"] == "cookie-alice@example.com"
        assert refresh_access_claims["auth_time"] == login_access_claims["auth_time"]

        logout_response = await client.post(
            "/auth/logout",
            headers={
                "X-Auth-Session-Transport": "cookie",
                "X-CSRF-Token": csrf_token,
            },
        )
        assert logout_response.status_code == 204

        replacement_csrf = await client.get("/auth/csrf")
        assert replacement_csrf.status_code == 200
        refresh_after_logout = await client.post(
            "/auth/token",
            headers={
                "X-Auth-Session-Transport": "cookie",
                "X-CSRF-Token": replacement_csrf.json()["csrf_token"],
            },
        )
        assert refresh_after_logout.status_code == 401
        assert refresh_after_logout.json()["code"] == "session_expired"


@pytest.mark.asyncio
async def test_auth_cookie_login_refresh_logout_defaults_without_transport_header(
    app_factory,
    user_factory,
) -> None:
    """Browser-session context should default auth flows to cookie mode without the transport header."""
    app: FastAPI = app_factory()
    await user_factory(
        "implicit-cookie-alice@example.com",
        "Password123!",
        email_verified=True,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        csrf_response = await client.get("/auth/csrf")
        assert csrf_response.status_code == 200
        csrf_token = csrf_response.json()["csrf_token"]

        login_response = await client.post(
            "/auth/login",
            json={
                "email": "implicit-cookie-alice@example.com",
                "password": "Password123!",
            },
            headers={"X-CSRF-Token": csrf_token},
        )
        assert login_response.status_code == 200
        assert login_response.json() == {
            "authenticated": True,
            "session_transport": "cookie",
        }

        login_access_token = client.cookies.get("auth_access")
        login_refresh_token = client.cookies.get("auth_refresh")
        assert login_access_token
        assert login_refresh_token

        refresh_response = await client.post(
            "/auth/token",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert refresh_response.status_code == 200
        assert refresh_response.json() == {
            "authenticated": True,
            "session_transport": "cookie",
        }

        refreshed_refresh_token = client.cookies.get("auth_refresh")
        assert refreshed_refresh_token
        assert refreshed_refresh_token != login_refresh_token

        logout_response = await client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert logout_response.status_code == 204

        replacement_csrf = await client.get("/auth/csrf")
        assert replacement_csrf.status_code == 200
        refresh_after_logout = await client.post(
            "/auth/token",
            headers={"X-CSRF-Token": replacement_csrf.json()["csrf_token"]},
        )
        assert refresh_after_logout.status_code == 401
        assert refresh_after_logout.json()["code"] == "session_expired"


@pytest.mark.asyncio
async def test_auth_login_rejects_unverified_email(
    app_factory,
    user_factory,
) -> None:
    """Unverified users must verify email before password login succeeds."""
    app: FastAPI = app_factory()
    await user_factory("pending@example.com", "Password123!", email_verified=False)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/auth/login",
            json={"email": "pending@example.com", "password": "Password123!"},
        )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Email is not verified.",
        "code": "email_not_verified",
    }


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


@pytest.mark.asyncio
async def test_reauth_issues_fresh_access_token_without_rotating_refresh(
    app_factory,
    user_factory,
) -> None:
    """Re-authentication returns a newer auth_time while leaving the session refresh flow intact."""
    app: FastAPI = app_factory()
    await user_factory("reauth-user@example.com", "Password123!", email_verified=True)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_response = await client.post(
            "/auth/login",
            json={"email": "reauth-user@example.com", "password": "Password123!"},
        )
        assert login_response.status_code == 200
        login_access_token = login_response.json()["access_token"]
        jwt_service = get_jwt_service()
        login_claims = jwt_service.verify_token(login_access_token, expected_type="access")

        reauth_response = await client.post(
            "/auth/reauth",
            json={"password": "Password123!"},
            headers={"authorization": f"Bearer {login_access_token}"},
        )
        assert reauth_response.status_code == 200
        fresh_access_token = reauth_response.json()["access_token"]
        fresh_claims = jwt_service.verify_token(fresh_access_token, expected_type="access")
        assert fresh_claims["auth_time"] >= login_claims["auth_time"]
        assert fresh_claims["jti"] != login_claims["jti"]

        refresh_response = await client.post(
            "/auth/token",
            json={"refresh_token": login_response.json()["refresh_token"]},
        )
        assert refresh_response.status_code == 200
        refreshed_claims = jwt_service.verify_token(
            refresh_response.json()["access_token"],
            expected_type="access",
        )
        assert refreshed_claims["auth_time"] == fresh_claims["auth_time"]
