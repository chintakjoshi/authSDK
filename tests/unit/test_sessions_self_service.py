"""Unit tests for self-service session helpers on SessionService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import MethodType
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.core.sessions import RefreshTokenHasher, SessionService, SessionStateError
from app.models.session import Session

TEST_REFRESH_TOKEN_HASH_SECRET = "session-hash-secret"


class _FakeRedis:
    """Minimal async Redis stub for session self-service tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.fail_get = False

    async def get(self, key: str) -> str | None:
        if self.fail_get:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        self.values[key] = value
        self.ttls[key] = ttl
        return True

    async def delete(self, *keys: str) -> int:
        for key in keys:
            self.values.pop(key, None)
            self.ttls.pop(key, None)
        return len(keys)


class _FakeDBSession:
    """Minimal async DB session stub for in-memory session revocation tests."""

    def __init__(self) -> None:
        self.commit_count = 0
        self.rollback_count = 0

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1


def _session_row() -> Session:
    now = datetime.now(UTC)
    hasher = RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET)
    return Session(
        session_id=uuid4(),
        id=uuid4(),
        user_id=uuid4(),
        hashed_refresh_token=hasher.hash_token(f"refresh-{uuid4()}"),
        auth_time=now,
        expires_at=now + timedelta(minutes=10),
        revoked_at=None,
        ip_address=None,
        user_agent=None,
        last_seen_at=now,
    )


def _service() -> SessionService:
    return SessionService(
        redis_client=_FakeRedis(),
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )


@pytest.mark.asyncio
async def test_revoke_user_sessions_except_preserves_current_session() -> None:
    """Caller's current session id is skipped during self-service bulk revoke."""
    service = _service()
    current = _session_row()
    other = _session_row()

    async def _fake_fetch_for_user(
        self: SessionService,
        db_session,
        user_id,
    ) -> list[Session]:
        del self, db_session, user_id
        return [current, other]

    service._fetch_active_sessions_for_user = MethodType(  # type: ignore[assignment]
        _fake_fetch_for_user,
        service,
    )

    db_session = _FakeDBSession()
    revoked_ids = await service.revoke_user_sessions_except(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=uuid4(),
        except_session_id=current.session_id,
        reason="self_revoke_others",
    )

    assert revoked_ids == [other.session_id]
    assert current.revoked_at is None
    assert current.revoke_reason is None
    assert other.revoked_at is not None
    assert other.revoke_reason == "self_revoke_others"
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_revoke_user_sessions_except_revokes_all_when_no_current() -> None:
    """When no current session is supplied every active session is revoked."""
    service = _service()
    first = _session_row()
    second = _session_row()

    async def _fake_fetch_for_user(
        self: SessionService,
        db_session,
        user_id,
    ) -> list[Session]:
        del self, db_session, user_id
        return [first, second]

    service._fetch_active_sessions_for_user = MethodType(  # type: ignore[assignment]
        _fake_fetch_for_user,
        service,
    )

    db_session = _FakeDBSession()
    revoked_ids = await service.revoke_user_sessions_except(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=uuid4(),
        except_session_id=None,
        reason="manual_sweep",
    )

    assert set(revoked_ids) == {first.session_id, second.session_id}
    assert first.revoke_reason == "manual_sweep"
    assert second.revoke_reason == "manual_sweep"


@pytest.mark.asyncio
async def test_resolve_session_id_for_access_jti_returns_none_on_miss() -> None:
    """Public resolver swallows SessionStateError and returns None when unbound."""
    service = _service()
    result = await service.resolve_session_id_for_access_jti("nonexistent-jti")
    assert result is None


@pytest.mark.asyncio
async def test_resolve_session_id_for_access_jti_preserves_backend_failures() -> None:
    """Advisory access-token lookups should still surface backend availability errors."""
    redis_client = _FakeRedis()
    redis_client.fail_get = True
    service = SessionService(
        redis_client=redis_client,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )

    with pytest.raises(SessionStateError) as exc_info:
        await service.resolve_session_id_for_access_jti("any-jti")

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503
