"""Unit tests for lifecycle access-token validation rules."""

from __future__ import annotations

from typing import Any

import pytest
from redis.exceptions import RedisError

from app.services.lifecycle_service import LifecycleService, LifecycleServiceError


class _JWTServiceStub:
    """JWT stub returning deterministic access-token claims."""

    def verify_token(
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """Return one synthetic access-token payload."""
        del token, expected_type, public_keys_by_kid
        return {"sub": "user-1", "type": "access", "jti": "jti-123"}


class _SigningKeyServiceStub:
    """Signing-key stub returning one verification key."""

    async def get_verification_public_keys(self, db_session: Any) -> dict[str, str]:
        """Return deterministic key mapping."""
        del db_session
        return {"kid-1": "public-key"}


class _RedisStub:
    """Minimal Redis stub for lifecycle validation tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_get = False

    async def get(self, key: str) -> str | None:
        """Return blocklist state or raise backend failure."""
        if self.fail_get:
            raise RedisError("redis unavailable")
        return self.values.get(key)


class _UserServiceStub:
    """Unused user-service dependency placeholder."""


class _EmailSenderStub:
    """Unused email-sender dependency placeholder."""


def _build_service(redis_client: _RedisStub) -> LifecycleService:
    """Create lifecycle service with only the dependencies needed here."""
    return LifecycleService(
        jwt_service=_JWTServiceStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        user_service=_UserServiceStub(),  # type: ignore[arg-type]
        redis_client=redis_client,  # type: ignore[arg-type]
        email_sender=_EmailSenderStub(),  # type: ignore[arg-type]
        email_verify_ttl_seconds=86400,
    )


@pytest.mark.asyncio
async def test_validate_access_token_rejects_blocklisted_jti() -> None:
    """Lifecycle access-token validation rejects logged-out tokens."""
    redis_client = _RedisStub()
    redis_client.values["blocklist:jti:jti-123"] = "1"
    service = _build_service(redis_client)

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.validate_access_token(db_session=object(), token="access-token")

    assert exc_info.value.code == "invalid_token"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_validate_access_token_fails_closed_when_blocklist_backend_unavailable() -> None:
    """Lifecycle access-token validation fails closed on Redis errors."""
    redis_client = _RedisStub()
    redis_client.fail_get = True
    service = _build_service(redis_client)

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.validate_access_token(db_session=object(), token="access-token")

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503
