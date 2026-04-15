"""Integration tests for SAML router with real DB/Redis and stubbed core."""

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
from app.core.saml import SamlAssertion, SamlLoginRequest, SamlProtocolError
from app.core.sessions import get_redis_client, get_session_service
from app.models.user import User, UserIdentity
from app.services.saml_service import SamlService, get_saml_service
from app.services.token_service import get_token_service


@dataclass
class _SamlCoreStub:
    """Stub SAML core implementation for router integration tests."""

    mode: str = "success"

    def login_url(
        self,
        request_data: dict[str, str],
        relay_state: str | None,
    ) -> SamlLoginRequest:
        """Return deterministic IdP redirect URL."""
        del request_data
        return SamlLoginRequest(
            redirect_url=f"https://idp.example.com/sso?RelayState={relay_state}",
            request_id="request-1",
        )

    def parse_assertion(
        self,
        request_data: dict[str, str],
        *,
        expected_request_id: str,
    ) -> SamlAssertion:
        """Return normalized assertion or raise configured protocol failure."""
        del request_data
        assert expected_request_id == "request-1"
        if self.mode == "error":
            raise SamlProtocolError("SAML assertion invalid.", "saml_assertion_invalid", 401)
        return SamlAssertion(provider_user_id="saml-user-1", email="saml-user@example.com")

    def metadata_xml(self) -> str:
        """Return deterministic metadata XML."""
        return "<EntityDescriptor><X509Certificate>cert</X509Certificate></EntityDescriptor>"


def _build_saml_service(mode: str = "success") -> SamlService:
    """Build SAML service using stub protocol core and real token/session services."""
    return SamlService(
        saml_core=_SamlCoreStub(mode=mode),
        token_service=get_token_service(),
        session_service=get_session_service(),
        redis_client=get_redis_client(),
        allowed_redirect_uris=(),
    )


def _build_saml_service_with_redirects(*allowed_redirect_uris: str) -> SamlService:
    """Build SAML service with an explicit browser redirect allowlist."""
    return SamlService(
        saml_core=_SamlCoreStub(mode="success"),
        token_service=get_token_service(),
        session_service=get_session_service(),
        redis_client=get_redis_client(),
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
async def test_saml_login_callback_and_metadata_success(app_factory) -> None:
    """SAML login redirects, callback issues tokens, and metadata is exposed."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="success")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login_response = await client.get("/auth/saml/login")
        assert login_response.status_code == 302
        relay_state = login_response.headers["location"].split("RelayState=", 1)[1]

        callback_response = await client.post(
            "/auth/saml/callback",
            content=f"SAMLResponse=fake&RelayState={relay_state}",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert callback_response.status_code == 200
        assert callback_response.json()["access_token"]
        assert callback_response.json()["refresh_token"]

        metadata_response = await client.get("/auth/saml/metadata")

    assert metadata_response.status_code == 200
    assert "X509Certificate" in metadata_response.text
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_saml_callback_redirects_browser_flow_and_honors_requested_audience(
    app_factory,
) -> None:
    """SAML browser flows should preserve caller relay context, set cookies, and honor audience."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service_with_redirects(
        "http://app.example.com/post-auth"
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login_response = await client.get(
            "/auth/saml/login",
            params={
                "relay_state": "http://app.example.com/post-auth",
                "audience": "orders-api",
            },
        )
        relay_state = parse_qs(urlparse(login_response.headers["location"]).query)["RelayState"][0]
        assert relay_state != "http://app.example.com/post-auth"

        callback_response = await client.post(
            "/auth/saml/callback",
            content=f"SAMLResponse=fake&RelayState={relay_state}",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert callback_response.status_code == 303
    assert callback_response.headers["location"] == "http://app.example.com/post-auth"

    access_cookie = _cookie_value(callback_response, "auth_access")
    refresh_cookie = _cookie_value(callback_response, "auth_refresh")
    csrf_cookie = _cookie_value(callback_response, "auth_csrf")

    assert access_cookie
    assert refresh_cookie
    assert csrf_cookie
    get_jwt_service().verify_token(
        access_cookie,
        expected_type="access",
        expected_audience="orders-api",
    )
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_saml_callback_invalid_assertion_failure(app_factory) -> None:
    """SAML callback maps protocol failure to saml_assertion_invalid error contract."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="error")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        login_response = await client.get("/auth/saml/login")
        relay_state = login_response.headers["location"].split("RelayState=", 1)[1]
        response = await client.post(
            "/auth/saml/callback",
            content=f"SAMLResponse=fake&RelayState={relay_state}",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == 401
    assert response.json()["code"] == "saml_assertion_invalid"
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_saml_callback_rejects_soft_deleted_user_relogin(app_factory, db_session) -> None:
    """Soft-deleted SAML accounts stay blocked instead of being recreated."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="success")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first_login = await client.get("/auth/saml/login")
        first_relay_state = first_login.headers["location"].split("RelayState=", 1)[1]
        first_callback = await client.post(
            "/auth/saml/callback",
            content=f"SAMLResponse=fake&RelayState={first_relay_state}",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert first_callback.status_code == 200

        created_user = (
            await db_session.execute(select(User).where(User.email == "saml-user@example.com"))
        ).scalar_one()
        created_user.deleted_at = datetime.now(UTC)
        created_user.is_active = False
        await db_session.commit()

        second_login = await client.get("/auth/saml/login")
        second_relay_state = second_login.headers["location"].split("RelayState=", 1)[1]
        second_callback = await client.post(
            "/auth/saml/callback",
            content=f"SAMLResponse=fake&RelayState={second_relay_state}",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert second_callback.status_code == 401
    assert second_callback.json()["code"] == "invalid_credentials"

    db_session.expire_all()
    users = (
        (await db_session.execute(select(User).where(User.email == "saml-user@example.com")))
        .scalars()
        .all()
    )
    identity = (
        await db_session.execute(
            select(UserIdentity).where(
                UserIdentity.provider == "saml",
                UserIdentity.provider_user_id == "saml-user-1",
            )
        )
    ).scalar_one()
    assert len(users) == 1
    assert users[0].deleted_at is not None
    assert identity.user_id == users[0].id
    app.dependency_overrides.clear()
