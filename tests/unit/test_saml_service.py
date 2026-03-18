"""Unit tests for SAML service verification propagation."""

from __future__ import annotations

from dataclasses import dataclass
from types import MethodType
from typing import Any

import pytest

from app.core.saml import SamlAssertion
from app.services.saml_service import SamlService, SamlStateRecord
from app.services.token_service import TokenPair


@dataclass(frozen=True)
class _UserStub:
    """Minimal user object returned by the upsert hook."""

    id: str
    email: str
    role: str
    email_verified: bool
    email_otp_enabled: bool = False


class _SamlCoreStub:
    """SAML core stub returning a verified assertion."""

    def parse_assertion(
        self,
        request_data: dict[str, str],
        *,
        expected_request_id: str,
    ) -> SamlAssertion:
        """Return deterministic assertion payload."""
        del request_data
        assert expected_request_id == "request-1"
        return SamlAssertion(
            provider_user_id="saml-user-1",
            email="saml-user@example.com",
            email_verified=True,
        )


class _RedisStub:
    """Minimal async Redis stub for SAML request-state tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def setex(self, key: str, ttl_seconds: int, value: str) -> None:
        del ttl_seconds
        self.values[key] = value

    async def getdel(self, key: str) -> str | None:
        return self.values.pop(key, None)


class _TokenServiceStub:
    """Token service stub returning deterministic tokens."""

    async def issue_token_pair(
        self,
        db_session: Any,
        user_id: str,
        email: str,
        role: str,
        email_verified: bool,
        scopes: list[str],
    ) -> TokenPair:
        """Return token pair and assert email_verified reaches issuance."""
        del db_session, user_id, email, role, scopes
        assert email_verified is True
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionServiceStub:
    """Session service stub asserting verified state reaches session creation."""

    async def create_login_session(
        self,
        db_session: Any,
        user_id: Any,
        email: str,
        role: str,
        email_verified: bool,
        email_otp_enabled: bool,
        scopes: list[str],
        raw_access_token: str,
        raw_refresh_token: str,
    ) -> str:
        """Assert verified state is propagated into session metadata."""
        del (
            db_session,
            user_id,
            email,
            role,
            email_otp_enabled,
            scopes,
            raw_access_token,
            raw_refresh_token,
        )
        assert email_verified is True
        return "session-id"


@pytest.mark.asyncio
async def test_complete_callback_propagates_saml_email_verified_state() -> None:
    """SAML callback passes provider email_verified state into user/session/token flow."""
    service = SamlService(
        saml_core=_SamlCoreStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
    )
    captured: dict[str, object] = {}

    async def _fake_upsert(
        self: SamlService,
        db_session: Any,
        provider_user_id: str,
        email: str,
        email_verified: bool,
    ) -> _UserStub:
        """Capture upsert inputs and return deterministic verified user."""
        del db_session
        captured["provider_user_id"] = provider_user_id
        captured["email"] = email
        captured["email_verified"] = email_verified
        return _UserStub(
            id="user-1",
            email="saml-user@example.com",
            role="user",
            email_verified=True,
        )

    service._upsert_identity_then_resolve_user = MethodType(_fake_upsert, service)  # type: ignore[assignment]

    await service._store_state(  # type: ignore[attr-defined]
        state="relay-state",
        record=SamlStateRecord(request_id="request-1"),
    )
    result = await service.complete_callback(
        db_session=object(),  # type: ignore[arg-type]
        request_data={"post_data": {"SAMLResponse": "fake", "RelayState": "relay-state"}},
    )

    assert result.access_token == "access-token"
    assert result.refresh_token == "refresh-token"
    assert captured == {
        "provider_user_id": "saml-user-1",
        "email": "saml-user@example.com",
        "email_verified": True,
    }
