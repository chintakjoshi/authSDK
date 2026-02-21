"""Integration tests for SAML router with real DB/Redis and stubbed core."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.saml import SamlAssertion, SamlProtocolError
from app.core.sessions import get_session_service
from app.services.saml_service import SamlService, get_saml_service
from app.services.token_service import get_token_service


@dataclass
class _SamlCoreStub:
    """Stub SAML core implementation for router integration tests."""

    mode: str = "success"

    def login_url(self, request_data: dict[str, str], relay_state: str | None) -> str:
        """Return deterministic IdP redirect URL."""
        del request_data, relay_state
        return "https://idp.example.com/sso"

    def parse_assertion(self, request_data: dict[str, str]) -> SamlAssertion:
        """Return normalized assertion or raise configured protocol failure."""
        del request_data
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
    )


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
        assert login_response.headers["location"] == "https://idp.example.com/sso"

        callback_response = await client.post(
            "/auth/saml/callback",
            content="SAMLResponse=fake",
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
async def test_saml_callback_invalid_assertion_failure(app_factory) -> None:
    """SAML callback maps protocol failure to saml_assertion_invalid error contract."""
    app: FastAPI = app_factory()
    app.dependency_overrides[get_saml_service] = lambda: _build_saml_service(mode="error")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/auth/saml/callback",
            content="SAMLResponse=fake",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == 401
    assert response.json()["code"] == "saml_assertion_invalid"
    app.dependency_overrides.clear()
