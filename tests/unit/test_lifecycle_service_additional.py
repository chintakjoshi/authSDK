"""Additional unit tests for lifecycle service branches."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from redis.exceptions import RedisError

from app.core.jwt import TokenValidationError
from app.services.lifecycle_service import LifecycleService, LifecycleServiceError


@dataclass
class _UserRecord:
    id: object
    email: str
    password_hash: str | None = "hashed::password"
    role: str = "user"
    email_verified: bool = False
    email_otp_enabled: bool = False
    is_active: bool = True
    email_verify_token_hash: str | None = None
    email_verify_token_expires: datetime | None = None


class _JWTServiceStub:
    def __init__(self) -> None:
        self.raise_error: TokenValidationError | None = None

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
        return {"sub": "user-1", "jti": "jti-1", "auth_time": int(datetime.now(UTC).timestamp())}

    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return "verification-token"


class _SigningKeyServiceStub:
    async def get_verification_public_keys(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return {"kid": "public"}

    async def get_active_signing_key(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return type("Key", (), {"private_key_pem": "private", "kid": "kid-1"})()


class _UserServiceStub:
    def __init__(self) -> None:
        self.users_by_email: dict[str, _UserRecord] = {}

    async def get_user_by_email(self, db_session, email: str):  # type: ignore[no-untyped-def]
        del db_session
        return self.users_by_email.get(email)

    def hash_password(self, password: str) -> str:
        return f"hashed::{password}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        del password, password_hash
        return False


class _RedisStub:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_incr = False

    async def get(self, key: str) -> str | None:
        return self.values.get(key)

    async def incr(self, key: str) -> int:
        if self.fail_incr:
            raise RedisError("redis unavailable")
        self.values[key] = str(int(self.values.get(key, "0")) + 1)
        return int(self.values[key])

    async def expire(self, key: str, ttl: int) -> bool:
        del key, ttl
        return True


class _EmailSenderStub:
    def __init__(self) -> None:
        self.verification_links: list[str] = []

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        del to_email
        self.verification_links.append(verification_link)

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        del to_email, reset_link

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        del to_email


class _SessionServiceStub:
    async def validate_access_token_session(self, *, db_session, access_jti):  # type: ignore[no-untyped-def]
        del db_session, access_jti
        return uuid4()


class _DBSessionStub:
    def __init__(self, result: object | None = None) -> None:
        self.result = result
        self.added: list[object] = []
        self.flush_count = 0
        self.commit_count = 0

    def add(self, instance: object) -> None:
        self.added.append(instance)

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        return self

    def scalar_one_or_none(self):  # type: ignore[no-untyped-def]
        return self.result

    async def flush(self) -> None:
        self.flush_count += 1

    async def commit(self) -> None:
        self.commit_count += 1


def _service(
    *,
    jwt_service: _JWTServiceStub | None = None,
    user_service: _UserServiceStub | None = None,
    redis_client: _RedisStub | None = None,
    email_sender: _EmailSenderStub | None = None,
) -> LifecycleService:
    return LifecycleService(
        jwt_service=jwt_service or _JWTServiceStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        redis_client=redis_client or _RedisStub(),  # type: ignore[arg-type]
        email_sender=email_sender or _EmailSenderStub(),  # type: ignore[arg-type]
        email_verify_ttl_seconds=3600,
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        password_reset_ttl_seconds=1800,
        public_base_url="http://localhost:8000",
    )


@pytest.mark.asyncio
async def test_signup_password_rejects_invalid_or_duplicate_email() -> None:
    """Signup fails for empty emails and already-registered accounts."""
    user_service = _UserServiceStub()
    user_service.users_by_email["registered@example.com"] = _UserRecord(
        id=uuid4(),
        email="registered@example.com",
    )
    service = _service(user_service=user_service)

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.signup_password(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            email="  ",
            password="Password123!",
        )
    assert exc_info.value.code == "invalid_credentials"

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.signup_password(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            email="registered@example.com",
            password="Password123!",
        )
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_signup_password_success_sends_verification_and_commits() -> None:
    """Successful signup stores a user, issues a verify token, and sends email."""
    sender = _EmailSenderStub()
    service = _service(email_sender=sender)

    async def _issue_token(db_session, user_id: str):  # type: ignore[no-untyped-def]
        del db_session, user_id
        return "verify-token", datetime.now(UTC) + timedelta(hours=1)

    service._issue_email_verify_token = _issue_token  # type: ignore[assignment]
    db_session = _DBSessionStub()

    user = await service.signup_password(
        db_session=db_session,  # type: ignore[arg-type]
        email="new@example.com",
        password="Password123!",
    )

    assert user.email == "new@example.com"
    assert user.password_hash == "hashed::Password123!"
    assert sender.verification_links == [
        "http://localhost:8000/auth/verify-email?token=verify-token"
    ]
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_verify_email_token_blank_and_success_paths() -> None:
    """Email verification rejects blank tokens and clears token fields on success."""
    service = _service()
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.verify_email_token(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="   ",
        )
    assert exc_info.value.code == "invalid_verify_token"

    user = _UserRecord(
        id=uuid4(),
        email="verify@example.com",
        email_verify_token_hash=LifecycleService._hash_verification_token("verify-token"),
        email_verify_token_expires=datetime.now(UTC) + timedelta(minutes=5),
    )
    db_session = _DBSessionStub(result=user)

    async def _verify_jwt(**kwargs) -> dict[str, object]:  # type: ignore[no-untyped-def]
        return {"sub": str(user.id)}

    service._verify_email_jwt = _verify_jwt  # type: ignore[assignment]

    verified = await service.verify_email_token(
        db_session=db_session,  # type: ignore[arg-type]
        token="verify-token",
    )

    assert verified.email_verified is True
    assert verified.email_verify_token_hash is None
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_resend_verification_email_handles_invalid_states_and_rate_limit_backend_failure() -> (
    None
):
    """Resend verification rejects bad tokens, verified users, and Redis backend failures."""
    service = _service()
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.resend_verification_email(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id="not-a-uuid",
        )
    assert exc_info.value.code == "invalid_token"

    verified_user = _UserRecord(
        id=uuid4(),
        email="verified@example.com",
        email_verified=True,
    )
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.resend_verification_email(
            db_session=_DBSessionStub(result=verified_user),  # type: ignore[arg-type]
            user_id=str(verified_user.id),
        )
    assert exc_info.value.code == "already_verified"

    redis_client = _RedisStub()
    redis_client.fail_incr = True
    service = _service(redis_client=redis_client)
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service._enforce_resend_rate_limit("user-1")
    assert exc_info.value.code == "session_expired"


@pytest.mark.asyncio
async def test_request_verification_email_resend_hides_account_state_and_resends_unverified() -> (
    None
):
    """Public resend hides unknown/verified accounts and resends only for unverified users."""
    user_service = _UserServiceStub()
    sender = _EmailSenderStub()
    service = _service(user_service=user_service, email_sender=sender)

    missing = await service.request_verification_email_resend(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        email="missing@example.com",
    )
    assert missing is None
    assert sender.verification_links == []

    user_service.users_by_email["verified@example.com"] = _UserRecord(
        id=uuid4(),
        email="verified@example.com",
        email_verified=True,
    )
    verified = await service.request_verification_email_resend(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        email="verified@example.com",
    )
    assert verified is None
    assert sender.verification_links == []

    unverified_user = _UserRecord(
        id=uuid4(),
        email="pending@example.com",
        email_verified=False,
    )
    user_service.users_by_email[unverified_user.email] = unverified_user

    async def _issue_token(db_session, user_id: str):  # type: ignore[no-untyped-def]
        del db_session, user_id
        return "verify-token", datetime.now(UTC) + timedelta(hours=1)

    service._issue_email_verify_token = _issue_token  # type: ignore[assignment]
    db_session = _DBSessionStub()

    resent_user_id = await service.request_verification_email_resend(
        db_session=db_session,  # type: ignore[arg-type]
        email="pending@example.com",
    )

    assert resent_user_id == str(unverified_user.id)
    assert sender.verification_links == [
        "http://localhost:8000/auth/verify-email?token=verify-token"
    ]
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_verify_email_jwt_maps_expired_and_invalid_tokens() -> None:
    """Verification JWT failures normalize to invalid_verify_token."""
    jwt_service = _JWTServiceStub()
    jwt_service.raise_error = TokenValidationError("expired", "token_expired")
    service = _service(jwt_service=jwt_service)

    with pytest.raises(LifecycleServiceError) as exc_info:
        await service._verify_email_jwt(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="verify-token",
        )
    assert exc_info.value.code == "invalid_verify_token"
