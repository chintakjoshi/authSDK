"""Unit tests for OTP access-token validation rules."""

from __future__ import annotations

from typing import Any

import pytest
from redis.exceptions import RedisError

from app.core.sessions import SessionStateError
from app.services.otp_service import OTPService, OTPServiceError


class _JWTServiceStub:
    """JWT stub returning deterministic access-token claims."""

    def verify_token(
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid: dict[str, str] | None = None,
        expected_audience=None,
    ) -> dict[str, object]:
        """Return one synthetic access-token payload."""
        del token, expected_type, public_keys_by_kid, expected_audience
        return {"sub": "user-1", "type": "access", "jti": "jti-456"}


class _SigningKeyServiceStub:
    """Signing-key stub returning one verification key."""

    async def get_verification_public_keys(self, db_session: Any) -> dict[str, str]:
        """Return deterministic key mapping."""
        del db_session
        return {"kid-1": "public-key"}


class _RedisStub:
    """Minimal Redis stub for OTP validation tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_get = False
        self.deleted_keys: list[str] = []

    async def get(self, key: str) -> str | None:
        """Return blocklist state or raise backend failure."""
        if self.fail_get:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def delete(self, *keys: str) -> int:
        """Capture deleted keys for OTP cleanup assertions."""
        self.deleted_keys.extend(keys)
        return len(keys)


class _TokenServiceStub:
    """Unused token-service dependency placeholder."""


class _SessionServiceStub:
    """Unused session-service dependency placeholder."""

    def __init__(self) -> None:
        self.validation_error: Exception | None = None

    async def validate_access_token_session(
        self,
        db_session: Any,
        *,
        access_jti: str,
    ) -> object:
        del db_session, access_jti
        if self.validation_error is not None:
            raise self.validation_error
        return object()


class _BruteForceServiceStub:
    """Unused brute-force dependency placeholder."""


class _EmailSenderStub:
    """Unused email-sender dependency placeholder."""


def _build_service(
    redis_client: _RedisStub,
    *,
    session_service: _SessionServiceStub | None = None,
) -> OTPService:
    """Create OTP service with only the dependencies needed here."""
    return OTPService(
        jwt_service=_JWTServiceStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceServiceStub(),  # type: ignore[arg-type]
        redis_client=redis_client,  # type: ignore[arg-type]
        email_sender=_EmailSenderStub(),  # type: ignore[arg-type]
        otp_code_length=6,
        otp_ttl_seconds=600,
        otp_max_attempts=5,
        action_token_ttl_seconds=300,
        auth_service_audience="auth-service",
    )


@pytest.mark.asyncio
async def test_validate_access_token_rejects_blocklisted_jti() -> None:
    """OTP access-token validation rejects logged-out tokens."""
    redis_client = _RedisStub()
    redis_client.values["blocklist:jti:jti-456"] = "1"
    service = _build_service(redis_client)

    with pytest.raises(OTPServiceError) as exc_info:
        await service.validate_access_token(db_session=object(), token="access-token")

    assert exc_info.value.code == "invalid_token"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_validate_access_token_fails_closed_when_blocklist_backend_unavailable() -> None:
    """OTP access-token validation fails closed on Redis errors."""
    redis_client = _RedisStub()
    redis_client.fail_get = True
    service = _build_service(redis_client)

    with pytest.raises(OTPServiceError) as exc_info:
        await service.validate_access_token(db_session=object(), token="access-token")

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_validate_access_token_rejects_revoked_session_binding() -> None:
    """OTP access-token validation rejects tokens bound to revoked sessions."""
    session_service = _SessionServiceStub()
    session_service.validation_error = SessionStateError("Session expired.", "session_expired", 401)
    service = _build_service(_RedisStub(), session_service=session_service)

    with pytest.raises(OTPServiceError) as exc_info:
        await service.validate_access_token(db_session=object(), token="access-token")

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_clear_user_otp_state_deletes_all_otp_keys() -> None:
    """Cleanup removes all OTP Redis state for one user."""
    redis_client = _RedisStub()
    service = _build_service(redis_client)

    await service.clear_user_otp_state("user-1")

    assert set(redis_client.deleted_keys) == {
        "otp:login:user-1",
        "otp:action:user-1",
        "otp_failed:user-1",
        "otp_issuance_blocked:user-1",
        "otp_resend_login:user-1",
    }
