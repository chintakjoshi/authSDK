"""Integration tests for SAML router behavior."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.dependencies import get_database_session
from app.routers.saml import router
from app.services.saml_service import SamlServiceError, get_saml_service


@dataclass(frozen=True)
class _TokenPairStub:
    """Minimal token pair object for callback success path."""

    access_token: str
    refresh_token: str


class _SamlServiceStub:
    """Stub SAML service for router tests."""

    def __init__(
        self,
        callback_result: _TokenPairStub | SamlServiceError | None = None,
        metadata: str = "<EntityDescriptor><X509Certificate>ci-cert</X509Certificate></EntityDescriptor>",
    ) -> None:
        self.callback_result = callback_result
        self.metadata = metadata

    def create_login_url(self, request_data: dict[str, str], relay_state: str | None) -> str:
        """Return deterministic redirect URL."""
        return "https://idp.example.com/sso"

    async def complete_callback(
        self,
        db_session: Any,
        request_data: dict[str, str],
    ) -> _TokenPairStub:
        """Return callback token pair or raise configured error."""
        if isinstance(self.callback_result, SamlServiceError):
            raise self.callback_result
        assert self.callback_result is not None
        return self.callback_result

    def metadata_xml(self) -> str:
        """Return deterministic metadata XML."""
        return self.metadata


async def _fake_db_dependency() -> Any:
    """Provide fake DB dependency."""
    yield object()


@pytest.mark.asyncio
async def test_saml_login_redirects_to_idp() -> None:
    """Login endpoint redirects to IdP SSO URL."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_saml_service] = lambda: _SamlServiceStub(
        callback_result=_TokenPairStub("a", "b")
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/saml/login")

    assert response.status_code == 302
    assert response.headers["location"] == "https://idp.example.com/sso"


@pytest.mark.asyncio
async def test_saml_callback_invalid_assertion_maps_error_payload() -> None:
    """Callback rejects invalid assertions with saml_assertion_invalid code."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_saml_service] = lambda: _SamlServiceStub(
        callback_result=SamlServiceError(
            detail="SAML assertion invalid.",
            code="saml_assertion_invalid",
            status_code=401,
        )
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/auth/saml/callback",
            content="SAMLResponse=fake",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "SAML assertion invalid.",
        "code": "saml_assertion_invalid",
    }


@pytest.mark.asyncio
async def test_saml_metadata_exposes_certificate_data() -> None:
    """Metadata endpoint returns XML containing SP certificate block."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_saml_service] = lambda: _SamlServiceStub(
        callback_result=_TokenPairStub("a", "b"),
        metadata="<EntityDescriptor><X509Certificate>current-cert</X509Certificate></EntityDescriptor>",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/saml/metadata")

    assert response.status_code == 200
    assert "current-cert" in response.text
