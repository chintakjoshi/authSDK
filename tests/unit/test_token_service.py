"""Unit tests for token issuance helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from app.services.token_service import AccessToken, TokenPair, TokenService


@dataclass(frozen=True)
class _ActiveKey:
    kid: str
    private_key_pem: str


class _JWTStub:
    """Capture token issuance calls."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def issue_token(
        self,
        *,
        subject: str,
        token_type: str,
        expires_in_seconds: int,
        additional_claims: dict[str, object] | None = None,
        audience: str | list[str] | None = None,
        signing_private_key_pem: str | None = None,
        signing_kid: str | None = None,
    ) -> str:
        self.calls.append(
            {
                "subject": subject,
                "token_type": token_type,
                "expires_in_seconds": expires_in_seconds,
                "additional_claims": additional_claims,
                "audience": audience,
                "signing_private_key_pem": signing_private_key_pem,
                "signing_kid": signing_kid,
            }
        )
        return f"{token_type}:{subject}:{signing_kid}"


class _AsyncJWTStub(_JWTStub):
    """Capture async token issuance calls and fail if the sync path is used."""

    def __init__(self) -> None:
        super().__init__()
        self.async_calls: list[dict[str, object]] = []

    async def issue_token_async(
        self,
        **kwargs: object,
    ) -> str:
        self.async_calls.append(dict(kwargs))
        token_type = str(kwargs["token_type"])
        subject = str(kwargs["subject"])
        signing_kid = str(kwargs["signing_kid"])
        return f"{token_type}:{subject}:{signing_kid}:async"

    def issue_token(self, *args: object, **kwargs: object) -> str:
        raise AssertionError("TokenService should use issue_token_async when available")


class _SigningKeyServiceStub:
    """Return one active signing key."""

    async def get_active_signing_key(self, db_session) -> _ActiveKey:  # type: ignore[no-untyped-def]
        del db_session
        return _ActiveKey(kid="kid-1", private_key_pem="private-key")


@pytest.mark.asyncio
async def test_issue_token_pair_includes_expected_claims() -> None:
    """Token pairs carry email, role, OTP, scopes, and auth_time claims."""
    jwt_service = _JWTStub()
    service = TokenService(
        jwt_service=jwt_service,  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        access_token_ttl_seconds=300,
        refresh_token_ttl_seconds=900,
        auth_service_audience="auth-service",
    )
    auth_time = datetime(2025, 1, 2, tzinfo=UTC)

    result = await service.issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-1",
        email="user@example.com",
        role="admin",
        email_verified=True,
        email_otp_enabled=True,
        scopes=["orders:read"],
        audience="orders-api",
        auth_time=auth_time,
    )

    assert result == TokenPair(
        access_token="access:user-1:kid-1",
        refresh_token="refresh:user-1:kid-1",
    )
    assert len(jwt_service.calls) == 2
    access_call, refresh_call = jwt_service.calls
    assert access_call["additional_claims"] == {
        "role": "admin",
        "email_verified": True,
        "email_otp_enabled": True,
        "auth_time": int(auth_time.timestamp()),
        "email": "user@example.com",
        "scopes": ["orders:read"],
    }
    assert access_call["audience"] == ["auth-service", "orders-api"]
    assert refresh_call["audience"] == "auth-service"
    assert refresh_call["additional_claims"] is None


@pytest.mark.asyncio
async def test_issue_access_token_omits_optional_claims_when_absent() -> None:
    """Access-only issuance skips email and scopes when the caller omits them."""
    jwt_service = _JWTStub()
    service = TokenService(
        jwt_service=jwt_service,  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        access_token_ttl_seconds=300,
        refresh_token_ttl_seconds=900,
        auth_service_audience="auth-service",
    )

    result = await service.issue_access_token(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-2",
    )

    assert result == AccessToken(access_token="access:user-2:kid-1")
    assert jwt_service.calls[0]["additional_claims"] == {
        "role": "user",
        "email_verified": False,
        "email_otp_enabled": False,
        "auth_time": pytest.approx(int(datetime.now(UTC).timestamp()), abs=3),
    }
    assert jwt_service.calls[0]["audience"] == ["auth-service"]


@pytest.mark.asyncio
async def test_token_service_prefers_async_issue_helper_when_available() -> None:
    """Async request paths should use the JWT async helper instead of sync signing."""
    jwt_service = _AsyncJWTStub()
    service = TokenService(
        jwt_service=jwt_service,  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        access_token_ttl_seconds=300,
        refresh_token_ttl_seconds=900,
        auth_service_audience="auth-service",
    )

    token_pair = await service.issue_token_pair(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-async",
    )
    access_token = await service.issue_access_token(
        db_session=object(),  # type: ignore[arg-type]
        user_id="user-async",
    )

    assert token_pair == TokenPair(
        access_token="access:user-async:kid-1:async",
        refresh_token="refresh:user-async:kid-1:async",
    )
    assert access_token == AccessToken(access_token="access:user-async:kid-1:async")
    assert [call["token_type"] for call in jwt_service.async_calls] == [
        "access",
        "refresh",
        "access",
    ]
