"""Unit tests for session creation, rotation, and revocation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import MethodType
from uuid import uuid4

import pytest
from authlib.jose import jwt
from redis.exceptions import RedisError

from app.core.sessions import RefreshTokenHasher, SessionService, SessionStateError
from app.models.session import Session
from app.services.token_service import TokenPair

TEST_REFRESH_TOKEN_HASH_SECRET = "session-hash-secret"


@dataclass(frozen=True)
class _FakeUser:
    """Minimal user payload returned by refresh-time user lookups."""

    id: object
    email: str
    role: str
    email_verified: bool
    mfa_enabled: bool = False


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

    async def delete(self, *keys: str) -> int:
        """Delete one or more keys."""
        if self.fail_delete:
            raise RedisError("redis unavailable")
        for key in keys:
            self.values.pop(key, None)
            self.ttls.pop(key, None)
        return len(keys)


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


def _session_row(raw_refresh_token: str, *, use_legacy_hash: bool = False) -> Session:
    """Build an in-memory session row for tests."""
    now = datetime.now(UTC)
    hasher = RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET)
    return Session(
        session_id=uuid4(),
        id=uuid4(),
        user_id=uuid4(),
        hashed_refresh_token=(
            sha256(raw_refresh_token.encode("utf-8")).hexdigest()
            if use_legacy_hash
            else hasher.hash_token(raw_refresh_token)
        ),
        auth_time=now,
        expires_at=now + timedelta(minutes=10),
        revoked_at=None,
        created_at=now,
        updated_at=now,
        deleted_at=None,
        tenant_id=None,
    )


def _build_access_token(
    *,
    user_id: str = "u1",
    email: str = "user@example.com",
    email_verified: bool = False,
    mfa_enabled: bool = False,
    role: str = "user",
    scopes: list[str] | None = None,
    auth_time: int | None = None,
    jti: str = "access-jti-1",
) -> str:
    """Build a syntactically valid JWT for unverified-claims parsing."""
    now = datetime.now(UTC)
    payload = {
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": user_id,
        "type": "access",
        "email": email,
        "email_verified": email_verified,
        "mfa_enabled": mfa_enabled,
        "role": role,
        "scopes": scopes or [],
        "auth_time": auth_time if auth_time is not None else int(now.timestamp()),
    }
    return jwt.encode({"alg": "HS256"}, payload, "session-test-secret").decode("utf-8")


@pytest.mark.asyncio
async def test_create_login_session_stores_hashed_token_and_redis_payload() -> None:
    """Login session stores token hash in DB and metadata in Redis."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=600,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    user_id = uuid4()

    session_id = await service.create_login_session(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=user_id,
        email="user@example.com",
        role="user",
        email_verified=False,
        mfa_enabled=False,
        scopes=["read:all"],
        raw_access_token=_build_access_token(user_id=str(user_id), jti="login-jti"),
        raw_refresh_token="refresh-token-raw-value",
    )

    stored = db_session.added[0]
    assert stored.session_id == session_id
    assert stored.hashed_refresh_token == RefreshTokenHasher.from_secret(
        TEST_REFRESH_TOKEN_HASH_SECRET
    ).hash_token("refresh-token-raw-value")
    assert stored.hashed_refresh_token != sha256(b"refresh-token-raw-value").hexdigest()

    redis_key = f"session:{session_id}"
    assert redis_key in redis.values
    assert "refresh-token-raw-value" not in redis.values[redis_key]
    assert redis.ttls[redis_key] == 600
    assert redis.values["session_access:login-jti"] == str(session_id)
    assert db_session.commit_count == 1
    assert db_session.rollback_count == 0


@pytest.mark.asyncio
async def test_create_login_session_persists_suspicious_flags() -> None:
    """Login session stores normalized suspicious-session metadata on the row."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=600,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    user_id = uuid4()

    await service.create_login_session(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=user_id,
        email="user@example.com",
        role="user",
        email_verified=True,
        mfa_enabled=False,
        scopes=["read:all"],
        raw_access_token=_build_access_token(user_id=str(user_id), jti="risk-jti"),
        raw_refresh_token="refresh-token-raw-value",
        is_suspicious=True,
        suspicious_reasons=["new_ip", "prior_failures", "new_ip", ""],
    )

    stored = db_session.added[0]
    assert stored.is_suspicious is True
    assert stored.suspicious_reasons == ["new_ip", "prior_failures"]


@pytest.mark.asyncio
async def test_rotate_refresh_session_updates_hash_and_ttl() -> None:
    """Refresh rotation updates DB token hash and refreshes Redis TTL."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    row = _session_row(raw_refresh_token="old-refresh-token")
    redis.values[f"session:{row.session_id}"] = (
        '{"user_id":"u1","email":"user@example.com","role":"admin","email_verified":false,"mfa_enabled":false,"scopes":[],"issued_at":"now","auth_time":"now"}'
    )
    redis.ttls[f"session:{row.session_id}"] = 30

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        assert refresh_token_hash == RefreshTokenHasher.from_secret(
            TEST_REFRESH_TOKEN_HASH_SECRET
        ).hash_token("old-refresh-token")
        assert for_update is True
        return row

    async def _fake_user_lookup(
        self: SessionService,
        db_session: _FakeDBSession,
        user_id: object,
    ) -> _FakeUser:
        del db_session
        assert user_id == row.user_id
        return _FakeUser(
            id=row.user_id,
            email="updated@example.com",
            role="user",
            email_verified=True,
        )

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]
    service._get_active_user = MethodType(_fake_user_lookup, service)  # type: ignore[assignment]

    token_pair = await service.rotate_refresh_session(
        db_session=db_session,  # type: ignore[arg-type]
        raw_refresh_token="old-refresh-token",
        token_issuer=lambda _user_id, email=None, role=None, email_verified=None, scopes=None, auth_time=None: (
            TokenPair(
                access_token=_build_access_token(
                    user_id=_user_id,
                    email=email or "updated@example.com",
                    email_verified=bool(email_verified),
                    role=role or "user",
                    scopes=scopes,
                    auth_time=int((auth_time or datetime.now(UTC)).timestamp()),
                    jti="refresh-jti",
                ),
                refresh_token="new-refresh-token",
            )
            if email == "updated@example.com" and role == "user" and email_verified is True
            else (_ for _ in ()).throw(AssertionError("refresh used stale user claims"))
        ),
    )

    assert token_pair.access_token
    assert row.hashed_refresh_token == RefreshTokenHasher.from_secret(
        TEST_REFRESH_TOKEN_HASH_SECRET
    ).hash_token("new-refresh-token")
    assert redis.ttls[f"session:{row.session_id}"] == 900
    assert redis.values["session_access:refresh-jti"] == str(row.session_id)
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_rotate_refresh_session_accepts_legacy_sha256_rows_during_hash_migration() -> None:
    """Legacy SHA-256 session rows remain refreshable and are upgraded on successful rotation."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    row = _session_row(raw_refresh_token="old-refresh-token", use_legacy_hash=True)
    redis.values[f"session:{row.session_id}"] = (
        '{"user_id":"u1","email":"user@example.com","role":"admin","email_verified":false,"mfa_enabled":false,"scopes":[],"issued_at":"now","auth_time":"now"}'
    )

    async def _fake_user_lookup(
        self: SessionService,
        db_session: _FakeDBSession,
        user_id: object,
    ) -> _FakeUser:
        del db_session
        assert user_id == row.user_id
        return _FakeUser(
            id=row.user_id,
            email="updated@example.com",
            role="user",
            email_verified=True,
        )

    service._get_active_user = MethodType(_fake_user_lookup, service)  # type: ignore[assignment]

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session | None:
        del db_session
        assert for_update is True
        if refresh_token_hash == sha256(b"old-refresh-token").hexdigest():
            return row
        return None

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]

    token_pair = await service.rotate_refresh_session(
        db_session=db_session,  # type: ignore[arg-type]
        raw_refresh_token="old-refresh-token",
        token_issuer=lambda _user_id, email=None, role=None, email_verified=None, scopes=None, auth_time=None: (
            TokenPair(
                access_token=_build_access_token(
                    user_id=_user_id,
                    email=email or "updated@example.com",
                    email_verified=bool(email_verified),
                    role=role or "user",
                    scopes=scopes,
                    auth_time=int((auth_time or datetime.now(UTC)).timestamp()),
                    jti="refresh-jti-legacy",
                ),
                refresh_token="new-refresh-token",
            )
        ),
    )

    assert token_pair.refresh_token == "new-refresh-token"
    assert row.hashed_refresh_token == RefreshTokenHasher.from_secret(
        TEST_REFRESH_TOKEN_HASH_SECRET
    ).hash_token("new-refresh-token")
    assert row.hashed_refresh_token != sha256(b"new-refresh-token").hexdigest()


@pytest.mark.asyncio
async def test_rotate_refresh_session_fails_closed_when_redis_unavailable() -> None:
    """Refresh rotation fails closed when Redis is down."""
    redis = _FakeRedis()
    redis.fail_get = True
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    row = _session_row(raw_refresh_token="old-refresh-token")

    async def _fake_fetch(
        self: SessionService,
        db_session: _FakeDBSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        return row

    async def _fake_user_lookup(
        self: SessionService,
        db_session: _FakeDBSession,
        user_id: object,
    ) -> _FakeUser:
        del db_session, user_id
        return _FakeUser(
            id=row.user_id,
            email="user@example.com",
            role="user",
            email_verified=False,
        )

    service._fetch_session_by_refresh_hash = MethodType(_fake_fetch, service)  # type: ignore[assignment]
    service._get_active_user = MethodType(_fake_user_lookup, service)  # type: ignore[assignment]

    with pytest.raises(SessionStateError) as exc_info:
        await service.rotate_refresh_session(
            db_session=db_session,  # type: ignore[arg-type]
            raw_refresh_token="old-refresh-token",
            token_issuer=lambda _user_id, email=None, role=None, email_verified=None, scopes=None, auth_time=None: (
                TokenPair(
                    access_token=_build_access_token(
                        user_id=_user_id,
                        email=email or "user@example.com",
                        email_verified=bool(email_verified),
                        role=role or "user",
                        scopes=scopes,
                        auth_time=int((auth_time or datetime.now(UTC)).timestamp()),
                    ),
                    refresh_token="new-refresh-token",
                )
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
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    row = _session_row(raw_refresh_token="logout-refresh-token")
    redis.values[f"session:{row.session_id}"] = (
        '{"user_id":"u1","email":"user@example.com","role":"user","email_verified":false,"mfa_enabled":false,"scopes":[],"issued_at":"now","auth_time":"now"}'
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
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
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


@pytest.mark.asyncio
async def test_revoke_user_sessions_marks_all_sessions_revoked_without_committing() -> None:
    """Bulk revocation supports caller-managed transactions for password reset."""
    redis = _FakeRedis()
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    first = _session_row(raw_refresh_token="refresh-token-1")
    second = _session_row(raw_refresh_token="refresh-token-2")
    redis.values[f"session:{first.session_id}"] = (
        '{"user_id":"u1","email":"a@example.com","role":"user","email_verified":false,"mfa_enabled":false,"scopes":[],"issued_at":"now","auth_time":"now"}'
    )
    redis.values[f"session:{second.session_id}"] = (
        '{"user_id":"u1","email":"a@example.com","role":"user","email_verified":false,"mfa_enabled":false,"scopes":[],"issued_at":"now","auth_time":"now"}'
    )

    async def _fake_fetch_for_user(
        self: SessionService,
        db_session: _FakeDBSession,
        user_id: object,
    ) -> list[Session]:
        del db_session, user_id
        return [first, second]

    service._fetch_active_sessions_for_user = MethodType(  # type: ignore[assignment]
        _fake_fetch_for_user,
        service,
    )

    revoked_ids = await service.revoke_user_sessions(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=uuid4(),
        commit=False,
    )

    assert revoked_ids == [first.session_id, second.session_id]
    assert first.revoked_at is not None
    assert second.revoked_at is not None
    assert f"session:{first.session_id}" not in redis.values
    assert f"session:{second.session_id}" not in redis.values
    assert db_session.commit_count == 0
    assert db_session.rollback_count == 0


@pytest.mark.asyncio
async def test_revoke_user_sessions_rolls_back_when_redis_delete_fails() -> None:
    """Bulk revocation fails closed when Redis cannot delete session keys."""
    redis = _FakeRedis()
    redis.fail_delete = True
    db_session = _FakeDBSession()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    first = _session_row(raw_refresh_token="refresh-token-1")

    async def _fake_fetch_for_user(
        self: SessionService,
        db_session: _FakeDBSession,
        user_id: object,
    ) -> list[Session]:
        del db_session, user_id
        return [first]

    service._fetch_active_sessions_for_user = MethodType(  # type: ignore[assignment]
        _fake_fetch_for_user,
        service,
    )

    with pytest.raises(SessionStateError) as exc_info:
        await service.revoke_user_sessions(
            db_session=db_session,  # type: ignore[arg-type]
            user_id=uuid4(),
            commit=False,
        )

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 503
    assert db_session.rollback_count == 1


@pytest.mark.asyncio
async def test_validate_access_token_session_accepts_active_bound_session() -> None:
    """Access-token validation accepts tokens still bound to an active session."""
    redis = _FakeRedis()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    row = _session_row(raw_refresh_token="refresh-token-1")
    redis.values["session_access:jti-123"] = str(row.session_id)
    redis.values[f"session:{row.session_id}"] = (
        '{"user_id":"u1","email":"a@example.com","role":"user","email_verified":false,"mfa_enabled":false,"scopes":[],"issued_at":"now","auth_time":"now"}'
    )

    async def _fake_fetch_by_session_id(
        self: SessionService,
        db_session: _FakeDBSession,
        session_id,
        *,
        for_update: bool,
    ) -> Session:
        del db_session
        assert session_id == row.session_id
        assert for_update is False
        return row

    service._fetch_session_by_session_id = MethodType(  # type: ignore[assignment]
        _fake_fetch_by_session_id,
        service,
    )

    validated = await service.validate_access_token_session(
        db_session=_FakeDBSession(),  # type: ignore[arg-type]
        access_jti="jti-123",
    )

    assert validated == row.session_id


@pytest.mark.asyncio
async def test_validate_access_token_session_rejects_when_session_payload_missing() -> None:
    """Access tokens fail once bulk revocation deletes the Redis session payload."""
    redis = _FakeRedis()
    service = SessionService(
        redis_client=redis,
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
        refresh_token_hasher=RefreshTokenHasher.from_secret(TEST_REFRESH_TOKEN_HASH_SECRET),
    )
    row = _session_row(raw_refresh_token="refresh-token-1")
    redis.values["session_access:jti-123"] = str(row.session_id)

    async def _fake_fetch_by_session_id(
        self: SessionService,
        db_session: _FakeDBSession,
        session_id,
        *,
        for_update: bool,
    ) -> Session:
        del db_session
        assert session_id == row.session_id
        assert for_update is False
        return row

    service._fetch_session_by_session_id = MethodType(  # type: ignore[assignment]
        _fake_fetch_by_session_id,
        service,
    )

    with pytest.raises(SessionStateError) as exc_info:
        await service.validate_access_token_session(
            db_session=_FakeDBSession(),  # type: ignore[arg-type]
            access_jti="jti-123",
        )

    assert exc_info.value.code == "session_expired"
    assert exc_info.value.status_code == 401
