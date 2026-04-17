"""Unit tests for OAuth and SAML router audit-event semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.dependencies import get_database_session
from app.routers.oauth import router as oauth_router
from app.routers.saml import router as saml_router
from app.services.audit_service import get_audit_service
from app.services.oauth_service import get_oauth_service
from app.services.saml_service import get_saml_service
from app.services.webhook_service import get_webhook_service


@dataclass(frozen=True)
class _TokenPairStub:
    """Minimal token-pair response payload for callback success tests."""

    access_token: str
    refresh_token: str
    user_id: str = "user-123"
    session_id: str = "session-123"
    redirect_uri: str | None = None
    relay_state: str | None = None


class _OAuthServiceStub:
    """OAuth service stub for router audit tests."""

    async def build_google_login_url(
        self,
        redirect_uri: str | None,
        audience: str | None = None,
    ) -> str:
        """Return deterministic authorization URL."""
        del redirect_uri, audience
        return "https://accounts.google.com/o/oauth2/auth?state=test-state"

    async def complete_google_callback(
        self,
        db_session: Any,
        state: str,
        code: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> _TokenPairStub:
        """Return deterministic callback tokens."""
        del db_session, state, code, client_ip, user_agent
        return _TokenPairStub("access-token", "refresh-token")


class _SamlServiceStub:
    """SAML service stub for router audit tests."""

    async def create_login_url(
        self,
        request_data: dict[str, str],
        relay_state: str | None,
        audience: str | None = None,
    ) -> str:
        """Return deterministic IdP redirect URL."""
        del request_data, relay_state, audience
        return "https://idp.example.com/sso"

    async def complete_callback(
        self,
        db_session: Any,
        request_data: dict[str, str],
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> _TokenPairStub:
        """Return deterministic callback tokens."""
        del db_session, request_data, client_ip, user_agent
        return _TokenPairStub("access-token", "refresh-token")

    def metadata_xml(self) -> str:
        """Return deterministic metadata XML."""
        return "<EntityDescriptor />"


class _AuditServiceStub:
    """Audit service stub recording emitted events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def record(self, **kwargs: Any) -> None:
        """Capture audit event payloads excluding DB session."""
        self.events.append({key: value for key, value in kwargs.items() if key != "db"})


class _WebhookServiceStub:
    """Webhook stub capturing emitted events."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def emit_event(self, *, event_type: str, data: dict[str, Any]) -> None:
        self.events.append({"event_type": event_type, "data": data})


async def _fake_db_dependency() -> Any:
    """Provide fake DB dependency object."""
    yield object()


@pytest.mark.asyncio
async def test_oauth_login_start_does_not_emit_false_success_event() -> None:
    """OAuth initiation should redirect without logging login success."""
    app = FastAPI()
    app.include_router(oauth_router)
    audit_stub = _AuditServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_oauth_service] = lambda: _OAuthServiceStub()
    app.dependency_overrides[get_audit_service] = lambda: audit_stub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/oauth/google/login")

    assert response.status_code == 302
    assert all(event["event_type"] != "user.login.success" for event in audit_stub.events)


@pytest.mark.asyncio
async def test_saml_login_start_does_not_emit_false_success_event() -> None:
    """SAML initiation should redirect without logging login success."""
    app = FastAPI()
    app.include_router(saml_router)
    audit_stub = _AuditServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_saml_service] = lambda: _SamlServiceStub()
    app.dependency_overrides[get_audit_service] = lambda: audit_stub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/saml/login")

    assert response.status_code == 302
    assert all(event["event_type"] != "user.login.success" for event in audit_stub.events)


@pytest.mark.asyncio
async def test_oauth_callback_success_records_actor_and_session_identifiers() -> None:
    """OAuth callback success should emit attributable audit rows and session webhook data."""
    app = FastAPI()
    app.include_router(oauth_router)
    audit_stub = _AuditServiceStub()
    webhook_stub = _WebhookServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_oauth_service] = lambda: _OAuthServiceStub()
    app.dependency_overrides[get_audit_service] = lambda: audit_stub
    app.dependency_overrides[get_webhook_service] = lambda: webhook_stub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/auth/oauth/google/callback",
            params={"state": "state-123", "code": "code-123"},
        )

    assert response.status_code == 200
    login_event = next(
        event for event in audit_stub.events if event["event_type"] == "user.login.success"
    )
    assert login_event["actor_id"] == "user-123"
    session_event = next(
        event for event in audit_stub.events if event["event_type"] == "session.created"
    )
    assert session_event["actor_id"] == "user-123"
    assert session_event["target_id"] == "session-123"
    assert session_event["target_type"] == "session"
    assert webhook_stub.events[0]["data"]["user_id"] == "user-123"
    assert webhook_stub.events[0]["data"]["session_id"] == "session-123"


@pytest.mark.asyncio
async def test_saml_callback_success_records_actor_and_session_identifiers() -> None:
    """SAML callback success should emit attributable audit rows and session webhook data."""
    app = FastAPI()
    app.include_router(saml_router)
    audit_stub = _AuditServiceStub()
    webhook_stub = _WebhookServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_saml_service] = lambda: _SamlServiceStub()
    app.dependency_overrides[get_audit_service] = lambda: audit_stub
    app.dependency_overrides[get_webhook_service] = lambda: webhook_stub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/auth/saml/callback",
            content="SAMLResponse=fake&RelayState=relay-state-1",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == 200
    login_event = next(
        event for event in audit_stub.events if event["event_type"] == "user.login.success"
    )
    assert login_event["actor_id"] == "user-123"
    session_event = next(
        event for event in audit_stub.events if event["event_type"] == "session.created"
    )
    assert session_event["actor_id"] == "user-123"
    assert session_event["target_id"] == "session-123"
    assert session_event["target_type"] == "session"
    assert webhook_stub.events[0]["data"]["user_id"] == "user-123"
    assert webhook_stub.events[0]["data"]["session_id"] == "session-123"
