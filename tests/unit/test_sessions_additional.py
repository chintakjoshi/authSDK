"""Additional unit tests for session service helper branches."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import MethodType
from uuid import uuid4

import pytest
from jose import jwt
from redis.exceptions import RedisError

from app.core.sessions import SessionPayload, SessionService, SessionStateError
from app.models.session import Session
from app.services.token_service import TokenPair


class _RedisStub:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}
        self.fail_get = False
        self.fail_setex = False
        self.fail_delete = False

    async def get(self, key: str) -> str | None:
        if self.fail_get:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def setex(self, key: str, ttl: int, value: str) -> bool:
        if self.fail_setex:
            raise RedisError("redis unavailable")
        self.values[key] = value
        self.ttls[key] = ttl
        return True

    async def delete(self, *keys: str) -> int:
        if self.fail_delete:
            raise RedisError("redis unavailable")
        for key in keys:
            self.values.pop(key, None)
            self.ttls.pop(key, None)
        return len(keys)


class _DBSessionStub:
    def __init__(self) -> None:
        self.rollback_count = 0

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        return self

    def scalar_one_or_none(self):  # type: ignore[no-untyped-def]
        return None

    async def rollback(self) -> None:
        self.rollback_count += 1


def _service(redis_client: _RedisStub | None = None) -> SessionService:
    return SessionService(
        redis_client=redis_client or _RedisStub(),  # type: ignore[arg-type]
        refresh_token_ttl_seconds=900,
        access_token_ttl_seconds=300,
    )


def _access_token(
    *,
    token_type: str = "access",
    jti: str = "access-jti",
    auth_time: int | None = None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": "user-1",
        "type": token_type,
    }
    if auth_time is not None:
        payload["auth_time"] = auth_time
    return jwt.encode(payload, "session-secret", algorithm="HS256")


@pytest.mark.asyncio
async def test_get_session_payload_applies_defaults_and_handles_backend_failures() -> None:
    """Session payload parsing fills legacy defaults and fails closed on Redis issues."""
    redis_client = _RedisStub()
    service = _service(redis_client)
    session_id = uuid4()
    redis_client.values[f"session:{session_id}"] = (
        '{"user_id":"u1","email":"user@example.com","scopes":[],"issued_at":"2025-01-01T00:00:00+00:00"}'
    )

    payload = await service._get_session_payload(session_id)
    assert payload == SessionPayload(
        user_id="u1",
        email="user@example.com",
        role="user",
        email_verified=False,
        email_otp_enabled=False,
        scopes=[],
        audiences=[],
        issued_at="2025-01-01T00:00:00+00:00",
        auth_time="2025-01-01T00:00:00+00:00",
    )

    redis_client.values[f"session:{session_id}"] = "{bad-json"
    with pytest.raises(SessionStateError) as exc_info:
        await service._get_session_payload(session_id)
    assert exc_info.value.code == "session_expired"

    redis_client.fail_get = True
    with pytest.raises(SessionStateError) as exc_info:
        await service._get_session_payload(session_id)
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_binding_lookup_and_redis_write_helpers_fail_closed() -> None:
    """Session binding lookup and Redis write helpers reject invalid and unavailable state."""
    redis_client = _RedisStub()
    service = _service(redis_client)

    with pytest.raises(SessionStateError) as exc_info:
        await service._get_session_id_for_access_jti("missing-jti")
    assert exc_info.value.code == "session_expired"

    redis_client.values["session_access:bad-jti"] = "not-a-uuid"
    with pytest.raises(SessionStateError) as exc_info:
        await service._get_session_id_for_access_jti("bad-jti")
    assert exc_info.value.code == "session_expired"

    redis_client.values["session_access:good-jti"] = str(uuid4())
    assert await service._get_session_id_for_access_jti("good-jti")

    redis_client.fail_get = True
    with pytest.raises(SessionStateError) as exc_info:
        await service._get_session_id_for_access_jti("good-jti")
    assert exc_info.value.status_code == 503

    redis_client.fail_get = False
    redis_client.fail_setex = True
    with pytest.raises(SessionStateError):
        await service._set_session_payload(
            session_id=uuid4(),
            payload=SessionPayload(
                user_id="u1",
                email="user@example.com",
                role="user",
                email_verified=False,
                email_otp_enabled=False,
                scopes=[],
                audiences=[],
                issued_at="now",
                auth_time="now",
            ),
        )
    with pytest.raises(SessionStateError):
        await service._add_to_blocklist("jti-1", 60)


def test_extract_access_claims_invoke_token_issuer_and_ttl_helpers() -> None:
    """Session helper functions handle invalid tokens, auth_time, legacy issuers, and TTL math."""
    access_claims = SessionService._extract_access_claims(
        _access_token(auth_time=int(datetime.now(UTC).timestamp()))
    )
    assert access_claims["type"] == "access"

    with pytest.raises(SessionStateError):
        SessionService._extract_access_claims("not-a-token")
    with pytest.raises(SessionStateError):
        SessionService._extract_access_claims(_access_token(token_type="refresh"))
    with pytest.raises(SessionStateError):
        SessionService._extract_access_jti({})

    fallback = datetime(2025, 1, 1, tzinfo=UTC)
    assert SessionService._extract_auth_time({}, fallback=fallback) == fallback

    issued = SessionService._invoke_token_issuer(
        lambda user_id, email=None, role=None, scopes=None, audiences=None: TokenPair(
            access_token=f"{user_id}:{email}:{role}:{scopes}:{audiences}",
            refresh_token="refresh-token",
        ),
        "user-1",
        "user@example.com",
        "admin",
        True,
        False,
        ["orders:read"],
        ["auth-service", "orders-api"],
        fallback,
    )
    assert (
        issued.access_token
        == "user-1:user@example.com:admin:['orders:read']:['auth-service', 'orders-api']"
    )

    assert SessionService._remaining_lifetime_seconds(int(datetime.now(UTC).timestamp()) - 10) == 1
    assert SessionService._remaining_session_ttl(datetime.now(UTC) - timedelta(seconds=5)) == 1


@pytest.mark.asyncio
async def test_rotate_refresh_session_rejects_missing_user_and_expired_session() -> None:
    """Refresh rotation fails closed when the session is expired or the user is gone."""
    service = _service()
    row = Session(
        session_id=uuid4(),
        id=uuid4(),
        user_id=uuid4(),
        hashed_refresh_token=SessionService._hash_token("refresh-token"),
        auth_time=datetime.now(UTC),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        revoked_at=None,
    )

    async def _fetch(
        self: SessionService,
        db_session,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session:
        del db_session, refresh_token_hash, for_update
        return row

    service._fetch_session_by_refresh_hash = MethodType(_fetch, service)  # type: ignore[assignment]
    with pytest.raises(SessionStateError) as exc_info:
        await service.rotate_refresh_session(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            raw_refresh_token="refresh-token",
            token_issuer=lambda user_id, **kwargs: TokenPair("access", "refresh"),
        )
    assert exc_info.value.code == "session_expired"

    row.expires_at = datetime.now(UTC) + timedelta(minutes=5)

    async def _missing_user(self: SessionService, db_session, user_id):  # type: ignore[no-untyped-def]
        del db_session, user_id
        return None

    service._get_active_user = MethodType(_missing_user, service)  # type: ignore[assignment]

    async def _payload(session_id):  # type: ignore[no-untyped-def]
        return SessionPayload(
            user_id=str(row.user_id),
            email="user@example.com",
            role="user",
            email_verified=False,
            email_otp_enabled=False,
            scopes=[],
            audiences=[],
            issued_at="now",
            auth_time="now",
        )

    service._get_session_payload = _payload  # type: ignore[assignment]
    with pytest.raises(SessionStateError) as exc_info:
        await service.rotate_refresh_session(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            raw_refresh_token="refresh-token",
            token_issuer=lambda user_id, **kwargs: TokenPair("access", "refresh"),
        )
    assert exc_info.value.code == "session_expired"
