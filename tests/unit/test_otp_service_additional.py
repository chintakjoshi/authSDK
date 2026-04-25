"""Additional unit tests for OTP service helper branches."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.core.jwt import TokenValidationError
from app.services.otp_service import OTPService, OTPServiceError
from app.services.token_service import TokenPair


class _JWTStub:
    def __init__(self) -> None:
        self.raise_error: TokenValidationError | None = None
        self.claims: dict[str, object] = {"sub": "user-1", "action": "enable_otp"}

    def verify_token(  # type: ignore[no-untyped-def]
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid=None,
        expected_audience=None,
    ):
        del token, expected_type, public_keys_by_kid, expected_audience
        if self.raise_error is not None:
            raise self.raise_error
        return self.claims

    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return "action-token"


class _SigningKeyStub:
    async def get_verification_public_keys(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return {"kid": "public"}

    async def get_active_signing_key(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return type("Key", (), {"private_key_pem": "private", "kid": "kid-1"})()


class _TokenServiceStub:
    async def issue_token_pair(self, **kwargs: object) -> TokenPair:
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionServiceStub:
    async def validate_access_token_session(self, *, db_session, access_jti):  # type: ignore[no-untyped-def]
        del db_session, access_jti
        return uuid4()

    async def create_login_session(self, **kwargs: object) -> object:
        return uuid4()


@dataclass
class _Decision:
    locked: bool = False
    retry_after: int | None = None
    suspicious: bool = False
    metadata: dict[str, object] | None = None


class _BruteForceStub:
    def __init__(self) -> None:
        self.failed_decision = _Decision()
        self.success_decision = _Decision()

    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id

    async def record_failed_otp_attempt(self, user_id: str):  # type: ignore[no-untyped-def]
        del user_id
        return self.failed_decision

    async def record_successful_login(self, user_id: str, ip_address=None, user_agent=None):  # type: ignore[no-untyped-def]
        del user_id, ip_address, user_agent
        return self.success_decision


class _RedisStub:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.expirations: dict[str, int] = {}
        self.fail_get = False
        self.fail_delete = False
        self.fail_incr = False
        self.fail_set = False

    async def get(self, key: str) -> str | None:
        if self.fail_get:
            raise RedisError("redis unavailable")
        return self.values.get(key)

    async def ttl(self, key: str) -> int:
        return self.expirations.get(key, -2)

    async def incr(self, key: str) -> int:
        if self.fail_incr:
            raise RedisError("redis unavailable")
        self.values[key] = str(int(self.values.get(key, "0")) + 1)
        return int(self.values[key])

    async def expire(self, key: str, ttl: int) -> bool:
        self.expirations[key] = ttl
        return True

    async def set(self, key: str, value: str, *, ex: int, nx: bool):  # type: ignore[no-untyped-def]
        if self.fail_set:
            raise RedisError("redis unavailable")
        if nx and key in self.values:
            return False
        self.values[key] = value
        self.expirations[key] = ex
        return True

    async def hincrby(self, key: str, field: str, amount: int) -> int:
        self.hashes.setdefault(key, {})
        current = int(self.hashes[key].get(field, "0")) + amount
        self.hashes[key][field] = str(current)
        return current

    async def hgetall(self, key: str) -> dict[str, str]:
        return self.hashes.get(key, {})

    async def hset(self, key: str, mapping: dict[str, str]) -> int:
        self.hashes[key] = dict(mapping)
        return len(mapping)

    async def delete(self, *keys: str) -> int:
        if self.fail_delete:
            raise RedisError("redis unavailable")
        for key in keys:
            self.values.pop(key, None)
            self.hashes.pop(key, None)
        return len(keys)


class _EmailSenderStub:
    async def send_login_otp_email(self, to_email: str, code: str, expires_in_seconds: int) -> None:
        del to_email, code, expires_in_seconds

    async def send_action_otp_email(
        self,
        to_email: str,
        action: str,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        del to_email, action, code, expires_in_seconds


class _DBSessionStub:
    def __init__(self) -> None:
        self.commit_count = 0

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commit_count += 1


@dataclass
class _UserStub:
    id: object
    email: str
    role: str = "user"
    email_verified: bool = True
    mfa_enabled: bool = False
    is_active: bool = True
    deleted_at: datetime | None = None


def _service(
    *,
    jwt_service: _JWTStub | None = None,
    brute_force_service: _BruteForceStub | None = None,
    redis_client: _RedisStub | None = None,
) -> OTPService:
    return OTPService(
        jwt_service=jwt_service or _JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service or _BruteForceStub(),  # type: ignore[arg-type]
        redis_client=redis_client or _RedisStub(),  # type: ignore[arg-type]
        email_sender=_EmailSenderStub(),  # type: ignore[arg-type]
        otp_code_length=6,
        otp_ttl_seconds=600,
        otp_max_attempts=5,
        action_token_ttl_seconds=300,
        auth_service_audience="auth-service",
    )


@pytest.mark.asyncio
async def test_validate_and_require_action_token_cover_missing_invalid_and_mismatch() -> None:
    """Action-token validation handles missing, invalid, and mismatched claims."""
    jwt_service = _JWTStub()
    service = _service(jwt_service=jwt_service)

    assert (
        await service.validate_action_token_for_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token=None,
            expected_action="enable_otp",
            user_id="user-1",
        )
        is False
    )

    with pytest.raises(OTPServiceError) as exc_info:
        await service.require_action_token_for_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token=None,
            expected_action="enable_otp",
            user_id="user-1",
        )
    assert exc_info.value.code == "action_token_invalid"

    jwt_service.raise_error = TokenValidationError("bad", "invalid_token")
    with pytest.raises(OTPServiceError) as exc_info:
        await service.require_action_token_for_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="action",
            expected_action="enable_otp",
            user_id="user-1",
        )
    assert exc_info.value.code == "action_token_invalid"

    jwt_service.raise_error = None
    jwt_service.claims = {"sub": "user-2", "action": "disable_otp"}
    with pytest.raises(OTPServiceError):
        await service.require_action_token_for_user(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="action",
            expected_action="enable_otp",
            user_id="user-1",
        )


@pytest.mark.asyncio
async def test_enable_disable_and_issuance_helpers_fail_closed() -> None:
    """Enrollment toggles and issuance helpers enforce user validity and Redis failures."""
    redis_client = _RedisStub()
    service = _service(redis_client=redis_client)
    user = _UserStub(id=uuid4(), email="otp@example.com", email_verified=False)

    async def _get_user(**kwargs: object) -> _UserStub:
        return user

    service._get_user_by_id = _get_user  # type: ignore[assignment]

    with pytest.raises(OTPServiceError) as exc_info:
        await service.enable_email_otp(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id=str(user.id),
            action_token=None,
            require_action_token=False,
        )
    assert exc_info.value.code == "email_not_verified"

    user.email_verified = True
    db_session = _DBSessionStub()
    enabled = await service.enable_email_otp(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=str(user.id),
        action_token=None,
        require_action_token=False,
    )
    assert enabled.mfa_enabled is True
    assert db_session.commit_count == 1

    redis_client.hashes[service._login_otp_key(str(user.id))] = {"code_hash": "hash"}
    disabled = await service.disable_email_otp(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=str(user.id),
        action_token=None,
        require_action_token=False,
    )
    assert disabled.mfa_enabled is False
    assert service._login_otp_key(str(user.id)) not in redis_client.hashes

    redis_client.values[service._issuance_block_key("user-1")] = "1"
    redis_client.expirations[service._issuance_block_key("user-1")] = 120
    with pytest.raises(OTPServiceError) as exc_info:
        await service._ensure_issuance_not_blocked("user-1")
    assert exc_info.value.code == "otp_issuance_blocked"
    assert exc_info.value.headers["Retry-After"] == "120"

    redis_client.fail_get = True
    with pytest.raises(OTPServiceError) as exc_info:
        await service._ensure_issuance_not_blocked("user-2")
    assert exc_info.value.code == "session_expired"


@pytest.mark.asyncio
async def test_failed_counter_record_success_and_redis_hash_helpers() -> None:
    """Failure counters, suspicious-login mapping, and Redis hash helpers work as documented."""
    brute_force = _BruteForceStub()
    redis_client = _RedisStub()
    service = _service(brute_force_service=brute_force, redis_client=redis_client)

    blocked = False
    for _ in range(11):
        blocked = await service._increment_failed_counter("user-1")
    assert blocked is True
    assert redis_client.values[service._issuance_block_key("user-1")] == "1"

    brute_force.failed_decision = _Decision(locked=True, retry_after=60)
    with pytest.raises(OTPServiceError) as exc_info:
        await service._apply_shared_failed_attempt("user-1")
    assert exc_info.value.code == "account_locked"

    brute_force.success_decision = _Decision(suspicious=True, metadata={"reason": "new_ip"})
    suspicious = await service._record_successful_login(
        "user-1",
        client_ip="203.0.113.10",
        user_agent="pytest",
    )
    assert suspicious == {"reason": "new_ip"}

    redis_client.hashes["otp:action:user-1"] = {"attempt_count": "0"}
    assert await service._increment_hash_counter("otp:action:user-1", "attempt_count") == 1
    assert await service._get_hash("otp:action:user-1") == {"attempt_count": "1"}
    await service._store_hash("otp:action:user-2", {"code_hash": "hash"}, ttl_seconds=30)
    assert redis_client.hashes["otp:action:user-2"]["code_hash"] == "hash"
    await service._delete_keys("otp:action:user-2")
    assert "otp:action:user-2" not in redis_client.hashes
