"""Unit tests for lifecycle access-token validation rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.core.sessions import SessionStateError
from app.services.lifecycle_service import LifecycleService, LifecycleServiceError


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

    async def incr(self, key: str) -> int:
        """Increment one rate-limit counter."""
        self.values[key] = str(int(self.values.get(key, "0")) + 1)
        return int(self.values[key])

    async def expire(self, key: str, ttl: int) -> bool:
        """Accept counter TTL initialization."""
        del key, ttl
        return True


class _UserServiceStub:
    """User-service stub covering password reset test flows."""

    def __init__(self) -> None:
        self.users_by_email: dict[str, _UserRecord] = {}
        self.verify_calls: list[tuple[str, str]] = []

    async def get_user_by_email(self, db_session: Any, email: str) -> _UserRecord | None:
        del db_session
        return self.users_by_email.get(email.lower())

    def hash_password(self, password: str) -> str:
        return f"hashed::{password}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        self.verify_calls.append((password, password_hash))
        return True


class _EmailSenderStub:
    """Email sender stub capturing password reset deliveries."""

    def __init__(self) -> None:
        self.reset_links: list[tuple[str, str]] = []
        self.confirmations: list[str] = []

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        del to_email, verification_link

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        self.reset_links.append((to_email, reset_link))

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        self.confirmations.append(to_email)


class _SessionServiceStub:
    """Session-service stub used by password reset tests."""

    def __init__(self) -> None:
        self.revoked_user_ids: list[object] = []
        self.fail_with_redis = False
        self.validation_error: SessionStateError | None = None

    async def revoke_user_sessions(
        self,
        db_session: Any,
        user_id: object,
        *,
        commit: bool = True,
    ) -> list[object]:
        del db_session
        if self.fail_with_redis:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503)
        self.revoked_user_ids.append((user_id, commit))
        return []

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


class _DBSessionStub:
    """Minimal DB-session stub for lifecycle unit tests."""

    def __init__(self) -> None:
        self.flush_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    async def flush(self) -> None:
        self.flush_count += 1

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1


@dataclass
class _UserRecord:
    """In-memory user record used by password reset tests."""

    id: object
    email: str
    email_verified: bool = False
    password_hash: str | None = "hashed::initial"
    password_reset_token_hash: str | None = None
    password_reset_token_expires: datetime | None = None


def _build_service(
    redis_client: _RedisStub,
    *,
    user_service: _UserServiceStub | None = None,
    email_sender: _EmailSenderStub | None = None,
    session_service: _SessionServiceStub | None = None,
) -> LifecycleService:
    """Create lifecycle service with only the dependencies needed here."""
    return LifecycleService(
        jwt_service=_JWTServiceStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        redis_client=redis_client,  # type: ignore[arg-type]
        email_sender=email_sender or _EmailSenderStub(),  # type: ignore[arg-type]
        email_verify_ttl_seconds=86400,
        password_reset_ttl_seconds=3600,
        public_base_url="http://localhost:8000",
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


@pytest.mark.asyncio
async def test_validate_access_token_rejects_revoked_session_binding() -> None:
    """Lifecycle access-token validation rejects tokens bound to revoked sessions."""
    session_service = _SessionServiceStub()
    session_service.validation_error = SessionStateError("Session expired.", "session_expired", 401)
    service = _build_service(_RedisStub(), session_service=session_service)

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.validate_access_token(db_session=object(), token="access-token")

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_request_password_reset_uses_dummy_workload_for_unknown_email() -> None:
    """Forgot-password requests avoid enumeration by doing dummy password work."""
    user_service = _UserServiceStub()
    email_sender = _EmailSenderStub()
    service = _build_service(
        _RedisStub(),
        user_service=user_service,
        email_sender=email_sender,
    )
    db_session = _DBSessionStub()

    user_id = await service.request_password_reset(
        db_session=db_session,  # type: ignore[arg-type]
        email="missing@example.com",
    )

    assert user_id is None
    assert user_service.verify_calls
    assert email_sender.reset_links == []
    assert db_session.commit_count == 0


@pytest.mark.asyncio
async def test_complete_password_reset_hashes_password_and_revokes_sessions() -> None:
    """Completing password reset updates password and revokes active sessions in one flow."""
    user = _UserRecord(
        id=uuid4(),
        email="reset@example.com",
        password_hash="hashed::old",
    )
    user.password_reset_token_hash = LifecycleService._hash_password_reset_token("reset-token")
    user.password_reset_token_expires = datetime.now(UTC) + timedelta(minutes=10)
    user_service = _UserServiceStub()
    email_sender = _EmailSenderStub()
    session_service = _SessionServiceStub()
    service = _build_service(
        _RedisStub(),
        user_service=user_service,
        email_sender=email_sender,
        session_service=session_service,
    )
    db_session = _DBSessionStub()

    async def _fake_lookup(
        self: LifecycleService,
        db_session: _DBSessionStub,
        token: str,
        *,
        for_update: bool,
    ) -> _UserRecord | None:
        del db_session
        assert token == "reset-token"
        assert for_update is True
        return user

    service._get_user_by_password_reset_token = _fake_lookup.__get__(service, LifecycleService)  # type: ignore[assignment]

    updated_user = await service.complete_password_reset(
        db_session=db_session,  # type: ignore[arg-type]
        token="reset-token",
        new_password="NewPassword123!",
    )

    assert updated_user is user
    assert user.password_hash == "hashed::NewPassword123!"
    assert user.password_reset_token_hash is None
    assert user.password_reset_token_expires is None
    assert session_service.revoked_user_ids == [(user.id, False)]
    assert email_sender.confirmations == ["reset@example.com"]
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_complete_password_reset_rejects_invalid_or_expired_token() -> None:
    """Reset completion does not distinguish invalid from expired tokens."""
    service = _build_service(_RedisStub(), session_service=_SessionServiceStub())

    async def _fake_lookup(
        self: LifecycleService,
        db_session: _DBSessionStub,
        token: str,
        *,
        for_update: bool,
    ) -> None:
        del db_session, token, for_update
        return None

    service._get_user_by_password_reset_token = _fake_lookup.__get__(service, LifecycleService)  # type: ignore[assignment]

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.complete_password_reset(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="expired-or-invalid",
            new_password="NewPassword123!",
        )

    assert exc_info.value.code == "invalid_reset_token"
    assert exc_info.value.status_code == 400
