"""Flow-oriented lifecycle service tests for remaining branches."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

import pytest

from app.core.sessions import SessionStateError
from app.services.lifecycle_service import LifecycleService, LifecycleServiceError


@dataclass
class _UserRecord:
    id: object
    email: str
    password_hash: str | None = "hashed::password"
    role: str = "user"
    email_verified: bool = True
    email_otp_enabled: bool = False
    is_active: bool = True
    password_reset_token_hash: str | None = None
    password_reset_token_expires: datetime | None = None
    deleted_at: datetime | None = None


class _JWTServiceStub:
    def verify_token(  # type: ignore[no-untyped-def]
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid=None,
        expected_audience=None,
    ):
        del token, expected_type, public_keys_by_kid, expected_audience
        return {"sub": "user-1", "jti": "access-jti", "scopes": ["orders:read"]}

    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return "jwt-token"


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
        self.verify_password_result = True
        self.verify_calls: list[tuple[str, str]] = []

    async def get_user_by_email(self, db_session, email: str):  # type: ignore[no-untyped-def]
        del db_session
        return self.users_by_email.get(email)

    def hash_password(self, password: str) -> str:
        return f"hashed::{password}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        self.verify_calls.append((password, password_hash))
        return self.verify_password_result


class _RedisStub:
    async def get(self, key: str) -> None:
        del key
        return None


class _EmailSenderStub:
    def __init__(self) -> None:
        self.reset_links: list[str] = []

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        del to_email, verification_link

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        del to_email
        self.reset_links.append(reset_link)

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        del to_email


class _SessionServiceStub:
    def __init__(self) -> None:
        self.reauth_error: SessionStateError | None = None

    async def validate_access_token_session(self, *, db_session, access_jti):  # type: ignore[no-untyped-def]
        del db_session, access_jti
        return uuid4()

    async def revoke_user_sessions(self, *, db_session, user_id, commit):  # type: ignore[no-untyped-def]
        del db_session, user_id, commit
        return []

    async def reauthenticate_session(
        self,
        *,
        db_session,
        current_access_jti,
        new_access_token,
        auth_time,
    ):  # type: ignore[no-untyped-def]
        del db_session, current_access_jti, new_access_token, auth_time
        if self.reauth_error is not None:
            raise self.reauth_error
        return uuid4()


@dataclass
class _Decision:
    locked: bool = False
    retry_after: int | None = None


class _BruteForceStub:
    def __init__(self) -> None:
        self.failed_decision = _Decision()
        self.ensure_error: Exception | None = None

    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id
        if self.ensure_error is not None:
            raise self.ensure_error

    async def record_failed_password_attempt(self, user_id: str, ip_address=None):  # type: ignore[no-untyped-def]
        del user_id, ip_address
        return self.failed_decision


class _TokenServiceStub:
    async def issue_access_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return type("AccessToken", (), {"access_token": "fresh-access-token"})()


class _DBSessionStub:
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


def _service(
    *,
    user_service: _UserServiceStub | None = None,
    email_sender: _EmailSenderStub | None = None,
    session_service: _SessionServiceStub | None = None,
    brute_force_service: _BruteForceStub | None = None,
) -> LifecycleService:
    return LifecycleService(
        jwt_service=_JWTServiceStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyServiceStub(),  # type: ignore[arg-type]
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        email_sender=email_sender or _EmailSenderStub(),  # type: ignore[arg-type]
        email_verify_ttl_seconds=3600,
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        password_reset_ttl_seconds=1800,
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service or _BruteForceStub(),  # type: ignore[arg-type]
        public_base_url="http://localhost:8000",
    )


@pytest.mark.asyncio
async def test_request_password_reset_and_validate_token_paths() -> None:
    """Password reset requests send mail for known users and validate issued tokens."""
    user_service = _UserServiceStub()
    user = _UserRecord(id=uuid4(), email="reset@example.com")
    user_service.users_by_email[user.email] = user
    sender = _EmailSenderStub()
    service = _service(user_service=user_service, email_sender=sender)
    db_session = _DBSessionStub()

    user_id = await service.request_password_reset(
        db_session=db_session,  # type: ignore[arg-type]
        email=user.email,
    )
    assert user_id == str(user.id)
    assert user.password_reset_token_hash is not None
    assert sender.reset_links

    async def _lookup(**kwargs: object) -> _UserRecord | None:
        return user

    service._get_user_by_password_reset_token = _lookup  # type: ignore[assignment]
    await service.validate_password_reset_token(
        db_session=db_session,  # type: ignore[arg-type]
        token="reset-token",
    )

    async def _missing(**kwargs: object) -> None:
        return None

    service._get_user_by_password_reset_token = _missing  # type: ignore[assignment]
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.validate_password_reset_token(
            db_session=db_session,  # type: ignore[arg-type]
            token="reset-token",
        )
    assert exc_info.value.code == "invalid_reset_token"


@pytest.mark.asyncio
async def test_reauthenticate_rejects_invalid_states_and_succeeds() -> None:
    """Reauthentication covers missing claims, missing users, lockout, and success."""
    user = _UserRecord(id=uuid4(), email="reauth@example.com", password_hash="hashed::password")
    user_service = _UserServiceStub()
    brute_force = _BruteForceStub()
    session_service = _SessionServiceStub()
    service = _service(
        user_service=user_service,
        session_service=session_service,
        brute_force_service=brute_force,
    )

    async def _validate(**kwargs: object) -> dict[str, object]:
        return {"sub": "", "jti": ""}

    service.validate_access_token = _validate  # type: ignore[assignment]
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.reauthenticate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            access_token="access",
            password="Password123!",
        )
    assert exc_info.value.code == "invalid_token"

    async def _claims(**kwargs: object) -> dict[str, object]:
        return {"sub": str(user.id), "jti": "access-jti", "email_otp_enabled": False, "scopes": []}

    async def _missing_user(**kwargs: object) -> None:
        return None

    service.validate_access_token = _claims  # type: ignore[assignment]
    service._get_user_by_id = _missing_user  # type: ignore[assignment]
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.reauthenticate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            access_token="access",
            password="Password123!",
        )
    assert exc_info.value.code == "invalid_token"

    async def _found_user(**kwargs: object) -> _UserRecord:
        return user

    service._get_user_by_id = _found_user  # type: ignore[assignment]
    user_service.verify_password_result = False
    brute_force.failed_decision = _Decision(locked=False)
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.reauthenticate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            access_token="access",
            password="bad-password",
        )
    assert exc_info.value.code == "invalid_credentials"

    brute_force.failed_decision = _Decision(locked=True, retry_after=60)
    with pytest.raises(LifecycleServiceError) as exc_info:
        await service.reauthenticate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            access_token="access",
            password="bad-password",
        )
    assert exc_info.value.code == "account_locked"

    user_service.verify_password_result = True
    token = await service.reauthenticate(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        access_token="access",
        password="Password123!",
    )
    assert token == "fresh-access-token"
