"""Unit tests for session creation, rotation, and revocation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import MethodType
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.core.sessions import SessionService, SessionStateError
from app.models.session import Session
from app.services.token_service import TokenPair


class _FakeRedis:
    """Minimal async Redis stub used for session unit tests."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.fail_get = False
        self.fail_setex = False
        self.fail_delete = False

    async def get(self, key: str) -> str | None:
        """Return stored value for key."""
        if self.fail_get:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        """Store value with TTL."""
        if self.fail_setex:
            raise RedisError("redis unavailable")
        self.values[key] = value
        self.ttls[key] = ttl
        return True

    async def delete(self, key: str) -> int:
        """Delete a key."""
        if self.fail_delete:
            raise RedisError("redis unavailable")
        self.values.pop(key, None)
        self.ttls.pop(key, None)
        return 1


class _FakeDBSession:
    """Minimal async DB session stub."""

    def __init__(self) -> None:
        self.added: list[Session] = []
        self.flush_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def add(self, instance: Session) -> None:
        """Capture added model."""
        self.added.append(instance)

    async def flush(self) -> None:
        """Count flush calls."""
        self.flush_count += 1

    async def commit(self) -> None:
        """Count commits."""
        self.commit_count += 1

    async def rollback(self) -> None:
        """Count rollbacks."""
        self.rollback_count += 1


def _session_row(raw_refresh_token: str) -> Session:
    """Build an in-memory session row for tests."""
    now = datetime.now(UTC)
    return Session(
        session_id=uuid4(),
        id=uuid4(),
        user_id=uuid4(),
        hashed_refresh_token=sha256(raw_refresh_token.encode("utf-8")).hexdigest(),
        expires_at=now + timedelta(minutes=10),
        revoked_at=None,
        created_at=now,
        updated_at=now,
        deleted_at=None,
        tenant_id=None,
    )


@pytest.mark.asyncio
async def test_create_login_session_stores_hashed_token_and_redis_payload() -> None:
    """Login session stores token hash in DB and metadata in Redis."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(redis_client=redis, refresh_token_ttl_seconds=600)
    user_id = uuid4()

    session_id = await service.create_login_session(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=user_id,
        email="user@example.com",
        role="user",
        email_verified=False,
        scopes=["read:all"],
        raw_refresh_token="refresh-token-raw-value",
    )

    stored = db_session.added[0]
    assert stored.session_id == session_id
    assert stored.hashed_refresh_token == sha256(b"refresh-token-raw-value").hexdigest()

    redis_key = f"session:{session_id}"
    assert redis_key in redis.values
    assert "refresh-token-raw-value" not in redis.values[redis_key]
    assert redis.ttls[redis_key] == 600
    assert db_session.commit_count == 1
    assert db_session.rollback_count == 0


@pytest.mark.asyncio
async def test_rotate_refresh_session_updates_hash_and_ttl() -> None:
    """Refresh rotation updates DB token hash and refreshes Redis TTL."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(redis_client=redis, refresh_token_ttl_seconds=900)
    row = _session_row(raw_refresh_token="old-refresh-token")
    redis.values[f"session:{row.session_id}"] = (
        '{"user_id":"u1","email":"user@example.com","role":"admin","scopes":[],"issued_at":"now"}'
    )
    redis.ttls[f"session:{row.session_id}"] = 30

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        assert refresh_token_hash == sha256(b"old-refresh-token").hexdigest()
        assert for_update is True
        return row

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]

    token_pair = await service.rotate_refresh_session(
        db_session=db_session,  # type: ignore[arg-type]
        raw_refresh_token="old-refresh-token",
        token_issuer=lambda _user_id, email=None, role=None, scopes=None: TokenPair(
            access_token="new-access-token", refresh_token="new-refresh-token"
        ),
    )

    assert token_pair.access_token == "new-access-token"
    assert row.hashed_refresh_token == sha256(b"new-refresh-token").hexdigest()
    assert redis.ttls[f"session:{row.session_id}"] == 900
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_rotate_refresh_session_fails_closed_when_redis_unavailable() -> None:
    """Refresh rotation fails closed when Redis is down."""
    redis = _FakeRedis()
    redis.fail_get = True
    db_session = _FakeDBSession()
    service = SessionService(redis_client=redis, refresh_token_ttl_seconds=900)
    row = _session_row(raw_refresh_token="old-refresh-token")

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        return row

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]

    with pytest.raises(SessionStateError) as exc_info:
        await service.rotate_refresh_session(
            db_session=db_session,  # type: ignore[arg-type]
            raw_refresh_token="old-refresh-token",
            token_issuer=lambda _user_id, email=None, role=None, scopes=None: TokenPair(
                access_token="new-access-token", refresh_token="new-refresh-token"
            ),
        )

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503
    assert db_session.rollback_count == 1


@pytest.mark.asyncio
async def test_revoke_session_deletes_redis_key_and_blocklists_jti() -> None:
    """Logout revokes DB session, removes Redis session, and blocklists JTI."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(redis_client=redis, refresh_token_ttl_seconds=900)
    row = _session_row(raw_refresh_token="logout-refresh-token")
    redis.values[f"session:{row.session_id}"] = (
        '{"user_id":"u1","email":"user@example.com","role":"user","scopes":[],"issued_at":"now"}'
    )
    redis.ttls[f"session:{row.session_id}"] = 300

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        return row

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]

    await service.revoke_session(
        db_session=db_session,  # type: ignore[arg-type]
        raw_refresh_token="logout-refresh-token",
        access_jti="jti-123",
        access_expiration_epoch=int(datetime.now(UTC).timestamp()) + 120,
    )

    assert row.revoked_at is not None
    assert f"session:{row.session_id}" not in redis.values
    assert "blocklist:jti:jti-123" in redis.values
    assert redis.ttls["blocklist:jti:jti-123"] >= 1
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_revoke_session_fails_closed_when_redis_unavailable() -> None:
    """Logout fails closed when Redis delete fails."""
    redis = _FakeRedis()
    redis.fail_delete = True
    db_session = _FakeDBSession()
    service = SessionService(redis_client=redis, refresh_token_ttl_seconds=900)
    row = _session_row(raw_refresh_token="logout-refresh-token")

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        return row

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]

    with pytest.raises(SessionStateError) as exc_info:
        await service.revoke_session(
            db_session=db_session,  # type: ignore[arg-type]
            raw_refresh_token="logout-refresh-token",
            access_jti="jti-123",
            access_expiration_epoch=int(datetime.now(UTC).timestamp()) + 120,
        )

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503
    assert db_session.rollback_count == 1
