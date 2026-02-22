"""Integration tests for persisted audit events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.saml import SamlAssertion, SamlProtocolError
from app.core.sessions import get_redis_client, get_session_service
from app.models.audit_event import AuditEvent
from app.services.oauth_service import OAuthService, OAuthServiceError, get_oauth_service
from app.services.saml_service import SamlService, get_saml_service
from app.services.token_service import get_token_service


async def _load_events(db_session: AsyncSession) -> list[AuditEvent]:
    """Load all audit events in insertion order."""
    result = await db_session.execute(select(AuditEvent).order_by(AuditEvent.created_at.asc()))
    return list(result.scalars().all())


@dataclass
class _OAuthClientStub:
    """Google OAuth protocol stub used for audit integration tests."""

    redirect_uri: str = "http://localhost:8000/auth/oauth/google/callback"

    def resolve_redirect_uri(self, redirect_uri: str | None) -> str:
        return redirect_uri or self.redirect_uri

    def generate_state(self) -> str:
        return "state-12345678"

    def generate_nonce(self) -> str:
        return "nonce-12345678"

    def generate_code_verifier(self) -> str:
        return "verifier-12345678"

    async def create_google_authorization_url(
        self,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        del nonce, code_verifier
        return f"https://accounts.google.com/o/oauth2/v2/auth?state={state}&redirect_uri={redirect_uri}"

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict[str, str]:
        del code, code_verifier, redirect_uri
        return {"id_token": "stub-id-token"}

    async def verify_id_token(self, id_token: str, nonce: str) -> dict[str, object]:
        del id_token, nonce
        return {"sub": "google-user-1", "email": "oauth-user@example.com", "email_verified": True}


class _FailingOAuthService:
    """OAuth service stub that fails login start."""

    async def build_google_login_url(self, redirect_uri: str | None) -> str:
        del redirect_uri
        raise OAuthServiceError("OAuth state mismatch.", "oauth_state_mismatch", 503)

    async def complete_google_callback(self, db_session: AsyncSession, state: str, code: str):
        del db_session, state, code
        raise AssertionError("callback should not be called")


def _build_oauth_service() -> OAuthService:
    """Build OAuth service with stubbed protocol and real Redis/session dependencies."""
    return OAuthService(
        oauth_client=_OAuthClientStub(),
        redis_client=get_redis_client(),
        token_service=get_token_service(),
        session_service=get_session_service(),
    )


@dataclass
class _SamlCoreStub:
    """SAML core stub supporting success and error modes."""

    mode: str = "success"

    def login_url(self, request_data: dict[str, str], relay_state: str | None) -> str:
        del request_data, relay_state
        if self.mode == "login_error":
            raise SamlProtocolError("SAML request invalid.", "saml_invalid_request", 400)
        return "https://idp.example.com/sso"

    def parse_assertion(self, request_data: dict[str, str]) -> SamlAssertion:
        del request_data
        if self.mode == "callback_error":
            raise SamlProtocolError("SAML assertion invalid.", "saml_assertion_invalid", 401)
        return SamlAssertion(provider_user_id="saml-user-1", email="saml-user@example.com")

    def metadata_xml(self) -> str:
        return "<EntityDescriptor><X509Certificate>cert</X509Certificate></EntityDescriptor>"


def _build_saml_service(mode: str) -> SamlService:
    """Build SAML service for selected test mode."""
    return SamlService(
        saml_core=_SamlCoreStub(mode=mode),
        token_service=get_token_service(),
        session_service=get_session_service(),
    )


@pytest.mark.asyncio
async def test_auth_router_persists_success_and_failure_audit_events(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Password auth and API key flows store expected audit event types and outcomes."""
    app: FastAPI = app_factory()
    await user_factory("alice@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        failed_login = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": "WrongPassword123!"},
        )
        assert failed_login.status_code == 401

        login = await client.post(
            "/auth/login",
            json={"email": "alice@example.com", "password": "Password123!"},
        )
        assert login.status_code == 200

        failed_refresh = await client.post("/auth/token", json={"refresh_token": "x" * 32})
        assert failed_refresh.status_code == 401

        refreshed = await client.post(
            "/auth/token",
            json={"refresh_token": login.json()["refresh_token"]},
        )
        assert refreshed.status_code == 200

        failed_logout = await client.post(
            "/auth/logout",
            json={"refresh_token": refreshed.json()["refresh_token"]},
        )
        assert failed_logout.status_code == 401

        logout = await client.post(
            "/auth/logout",
            json={"refresh_token": refreshed.json()["refresh_token"]},
            headers={"authorization": f"Bearer {refreshed.json()['access_token']}"},
        )
        assert logout.status_code == 204

        invalid_introspect = await client.post("/auth/introspect", json={"api_key": "sk_missing_key"})
        assert invalid_introspect.status_code == 200
        assert invalid_introspect.json()["valid"] is False

        created_key = await client.post(
            "/auth/apikeys",
            json={
                "service": "orders",
                "scope": "orders:read",
                "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        )
        assert created_key.status_code == 200

        valid_introspect = await client.post(
            "/auth/introspect",
            json={"api_key": created_key.json()["api_key"]},
        )
        assert valid_introspect.status_code == 200
        assert valid_introspect.json()["valid"] is True

    events = await _load_events(db_session)
    pairs = {(event.event_type, event.success) for event in events}
    assert ("user.login.failure", False) in pairs
    assert ("user.login.success", True) in pairs
    assert ("session.created", True) in pairs
    assert ("token.issued", True) in pairs
    assert ("token.refreshed", False) in pairs
    assert ("token.refreshed", True) in pairs
    assert ("user.logout", False) in pairs
    assert ("user.logout", True) in pairs
    assert ("api_key.created", True) in pairs
    assert ("api_key.used", False) in pairs
    assert ("api_key.used", True) in pairs


@pytest.mark.asyncio
async def test_oauth_routes_persist_expected_audit_events(app_factory, db_session) -> None:
    """OAuth login start/callback success and failures are written to audit_events."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_oauth_service] = _build_oauth_service

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.get("/auth/oauth/google/login")
        assert login.status_code == 302
        state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]

        callback_failure = await client.get(
            "/auth/oauth/google/callback",
            params={"state": "missing-state-123", "code": "oauthcode"},
        )
        assert callback_failure.status_code == 401

        callback_success = await client.get(
            "/auth/oauth/google/callback",
            params={"state": state, "code": "oauthcode"},
        )
        assert callback_success.status_code == 200

    app.dependency_overrides[get_oauth_service] = lambda: _FailingOAuthService()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_failure = await client.get("/auth/oauth/google/login")
        assert login_failure.status_code == 503

    events = await _load_events(db_session)
    pairs = {(event.event_type, event.success) for event in events}
    assert ("user.login.success", True) in pairs
    assert ("user.login.failure", False) in pairs
    assert ("session.created", True) in pairs
    assert ("token.issued", True) in pairs


@pytest.mark.asyncio
async def test_saml_routes_persist_expected_audit_events(app_factory, db_session) -> None:
    """SAML login start/callback success and failures are written to audit_events."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="success")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.get("/auth/saml/login")
        assert login.status_code == 302

        callback_success = await client.post(
            "/auth/saml/callback",
            content="SAMLResponse=fake",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert callback_success.status_code == 200

    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="callback_error")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        callback_failure = await client.post(
            "/auth/saml/callback",
            content="SAMLResponse=fake",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert callback_failure.status_code == 401

    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="login_error")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_failure = await client.get("/auth/saml/login")
        assert login_failure.status_code == 400

    events = await _load_events(db_session)
    pairs = {(event.event_type, event.success) for event in events}
    assert ("user.login.success", True) in pairs
    assert ("user.login.failure", False) in pairs
    assert ("session.created", True) in pairs
    assert ("token.issued", True) in pairs


@pytest.mark.asyncio
async def test_apikey_routes_persist_success_and_failure_audit_events(app_factory, db_session) -> None:
    """API key create/list/revoke paths persist expected created/used/revoked audit rows."""
    app: FastAPI = app_factory()
    missing_key_id = str(uuid4())

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        create_failure = await client.post(
            "/auth/apikeys",
            json={"service": "orders", "scope": "   "},
        )
        assert create_failure.status_code == 400

        created = await client.post(
            "/auth/apikeys",
            json={"service": "orders", "scope": "orders:read"},
        )
        assert created.status_code == 200

        listed = await client.get("/auth/apikeys")
        assert listed.status_code == 200

        revoke_failure = await client.post(f"/auth/apikeys/{missing_key_id}/revoke")
        assert revoke_failure.status_code == 404

        revoke_success = await client.post(f"/auth/apikeys/{created.json()['key_id']}/revoke")
        assert revoke_success.status_code == 200

    events = await _load_events(db_session)
    pairs = {(event.event_type, event.success) for event in events}
    assert ("api_key.created", False) in pairs
    assert ("api_key.created", True) in pairs
    assert ("api_key.used", True) in pairs
    assert ("api_key.revoked", False) in pairs
    assert ("api_key.revoked", True) in pairs
