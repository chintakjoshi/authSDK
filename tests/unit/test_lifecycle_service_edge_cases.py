"""Additional lifecycle-service edge tests for coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.jwt import TokenValidationError
from app.core.sessions import SessionStateError
from app.services.brute_force_service import BruteForceProtectionError
from app.services.lifecycle_service import (
    LifecycleService,
    LifecycleServiceError,
    MailhogVerificationEmailSender,
)


class _JWTStub:
    def __init__(self) -> None:
        self.error: TokenValidationError | None = None

    def verify_token(self, token: str, expected_type: str, public_keys_by_kid=None):  # type: ignore[no-untyped-def]
        del token, expected_type, public_keys_by_kid
        if self.error is not None:
            raise self.error
        return {
            "sub": "user-1",
            "jti": "access-jti",
            "auth_time": int(datetime.now(UTC).timestamp()),
        }

    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return "issued-token"


class _SigningKeyStub:
    async def get_verification_public_keys(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return {"kid": "public"}

    async def get_active_signing_key(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return SimpleNamespace(private_key_pem="private", kid="kid-1")


class _UserServiceStub:
    def __init__(self) -> None:
        self.user_by_email: dict[str, object] = {}
        self.verify_password_result = True

    async def get_user_by_email(self, db_session, email: str):  # type: ignore[no-untyped-def]
        del db_session
        return self.user_by_email.get(email)

    def hash_password(self, password: str) -> str:
        return f"hashed::{password}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        del password, password_hash
        return self.verify_password_result


class _RedisStub:
    async def get(self, key: str) -> None:
        del key
        return None

    async def incr(self, key: str) -> int:
        del key
        return 1

    async def expire(self, key: str, ttl: int) -> bool:
        del key, ttl
        return True


class _EmailSenderStub:
    def __init__(self) -> None:
        self.raise_on_verify = False
        self.raise_on_reset = False
        self.raise_on_confirmation = False

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        del to_email, verification_link
        if self.raise_on_verify:
            raise RuntimeError("smtp down")

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        del to_email, reset_link
        if self.raise_on_reset:
            raise RuntimeError("smtp down")

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        del to_email
        if self.raise_on_confirmation:
            raise RuntimeError("smtp down")


class _SessionStub:
    def __init__(self) -> None:
        self.revoke_error: SessionStateError | None = None
        self.reauth_error: SessionStateError | None = None

    async def validate_access_token_session(self, *, db_session, access_jti):  # type: ignore[no-untyped-def]
        del db_session, access_jti
        return uuid4()

    async def revoke_user_sessions(self, **kwargs: object) -> list[object]:
        if self.revoke_error is not None:
            raise self.revoke_error
        return []

    async def reauthenticate_session(self, **kwargs: object) -> object:
        if self.reauth_error is not None:
            raise self.reauth_error
        return uuid4()


class _BruteForceStub:
    def __init__(self) -> None:
        self.ensure_error: Exception | None = None
        self.failed_error: Exception | None = None

    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id
        if self.ensure_error is not None:
            raise self.ensure_error

    async def record_failed_password_attempt(self, user_id: str, ip_address=None):  # type: ignore[no-untyped-def]
        del user_id, ip_address
        if self.failed_error is not None:
            raise self.failed_error
        return SimpleNamespace(locked=False, retry_after=None)


class _TokenServiceStub:
    async def issue_access_token(self, **kwargs: object) -> object:
        del kwargs
        return SimpleNamespace(access_token="fresh-access-token")


class _DBSessionStub:
    def __init__(self, result: object | None = None, *, fail_flush: bool = False) -> None:
        self.result = result
        self.fail_flush = fail_flush
        self.added: list[object] = []
        self.commit_count = 0
        self.rollback_count = 0

    def add(self, instance: object) -> None:
        self.added.append(instance)

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        return self

    def scalar_one_or_none(self):  # type: ignore[no-untyped-def]
        return self.result

    async def flush(self) -> None:
        if self.fail_flush:
            raise RuntimeError("flush failed")

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1


def _service(
    *,
    jwt_service: _JWTStub | None = None,
    user_service: _UserServiceStub | None = None,
    email_sender: _EmailSenderStub | None = None,
    session_service: _SessionStub | None = None,
    brute_force_service: _BruteForceStub | None = None,
    token_service: _TokenServiceStub | None = None,
) -> LifecycleService:
    return LifecycleService(
        jwt_service=jwt_service or _JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        email_sender=email_sender or _EmailSenderStub(),  # type: ignore[arg-type]
        email_verify_ttl_seconds=3600,
        session_service=session_service,  # type: ignore[arg-type]
        password_reset_ttl_seconds=1800,
        token_service=token_service,  # type: ignore[arg-type]
        brute_force_service=brute_force_service,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_mailhog_sender_covers_to_thread_and_smtp(monkeypatch) -> None:
    """Lifecycle Mailhog sender builds the expected SMTP messages."""
    sender = MailhogVerificationEmailSender(
        host="mailhog", port=1025, email_from="from@example.com"
    )
    messages: list[object] = []

    async def _fake_to_thread(func, **kwargs):  # type: ignore[no-untyped-def]
        return func(**kwargs)

    class _SMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            assert host == "mailhog"
            assert port == 1025
            assert timeout == 10

        def __enter__(self) -> _SMTP:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            return None

        def send_message(self, message) -> None:  # type: ignore[no-untyped-def]
            messages.append(message)

    monkeypatch.setattr("app.services.lifecycle_service.asyncio.to_thread", _fake_to_thread)
    monkeypatch.setattr("app.services.lifecycle_service.smtplib.SMTP", _SMTP)
    await sender.send_verification_email("user@example.com", "https://verify.example/token")
    await sender.send_password_reset_confirmation_email("user@example.com")
    assert len(messages) == 2
    assert messages[0]["Subject"] == "Verify your email"
    assert messages[1]["Subject"] == "Your password has been reset"


@pytest.mark.asyncio
async def test_signup_verify_and_resend_cover_rollbacks_and_invalid_paths() -> None:
    """Lifecycle signup/verify/resend cover rollback and invalid-token branches."""
    email_sender = _EmailSenderStub()
    email_sender.raise_on_verify = True
    service = _service(email_sender=email_sender)
    db_session = _DBSessionStub()
    with pytest.raises(RuntimeError):
        await service.signup_password(
            db_session=db_session,  # type: ignore[arg-type]
            email="user@example.com",
            password="Password123!",
        )
    assert db_session.rollback_count == 1

    service = _service()
    with pytest.raises(LifecycleServiceError, match="Invalid verification token"):
        await service.verify_email_token(
            db_session=_DBSessionStub(result=None),  # type: ignore[arg-type]
            token="verify-token",
        )

    user = SimpleNamespace(
        id=uuid4(),
        email="user@example.com",
        email_verified=False,
        email_verify_token_hash=LifecycleService._hash_verification_token("verify-token"),
        email_verify_token_expires=datetime.now(UTC) + timedelta(minutes=5),
    )
    db_session = _DBSessionStub(result=user, fail_flush=True)

    async def _verify_email(**kwargs: object) -> dict[str, object]:
        return {"sub": str(user.id)}

    service._verify_email_jwt = _verify_email  # type: ignore[assignment]
    with pytest.raises(RuntimeError):
        await service.verify_email_token(
            db_session=db_session,  # type: ignore[arg-type]
            token="verify-token",
        )
    assert db_session.rollback_count == 1

    with pytest.raises(LifecycleServiceError, match="Invalid token"):
        await service.resend_verification_email(
            db_session=_DBSessionStub(result=None),  # type: ignore[arg-type]
            user_id=str(uuid4()),
        )


@pytest.mark.asyncio
async def test_password_reset_and_reauth_cover_runtime_and_mapped_errors() -> None:
    """Lifecycle reset and reauth helpers cover runtime requirements and mapped failures."""
    user_service = _UserServiceStub()
    user = SimpleNamespace(
        id=uuid4(),
        email="reset@example.com",
        password_hash="hashed::password",
        role="user",
        email_verified=True,
        email_otp_enabled=False,
        password_reset_token_hash="hash",
        password_reset_token_expires=datetime.now(UTC) + timedelta(minutes=5),
    )
    user_service.user_by_email[user.email] = user
    email_sender = _EmailSenderStub()
    email_sender.raise_on_reset = True
    service = _service(user_service=user_service, email_sender=email_sender)
    with pytest.raises(RuntimeError):
        await service.request_password_reset(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            email=user.email,
        )

    service = _service(session_service=None)

    async def _lookup_reset_user(**kwargs: object) -> object:
        return user

    service._get_user_by_password_reset_token = _lookup_reset_user  # type: ignore[assignment]
    with pytest.raises(RuntimeError, match="requires session_service"):
        await service.complete_password_reset(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="reset-token",
            new_password="Password123!",
        )

    session_service = _SessionStub()
    session_service.revoke_error = SessionStateError("expired", "session_expired", 401)
    service = _service(session_service=session_service)
    service._get_user_by_password_reset_token = _lookup_reset_user  # type: ignore[assignment]
    with pytest.raises(LifecycleServiceError, match="expired"):
        await service.complete_password_reset(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            token="reset-token",
            new_password="Password123!",
        )

    brute_force = _BruteForceStub()
    token_service = _TokenServiceStub()
    service = _service(
        user_service=user_service,
        session_service=_SessionStub(),
        brute_force_service=brute_force,
        token_service=token_service,
    )

    async def _otp_claims(**kwargs: object) -> dict[str, object]:
        return {
            "sub": str(user.id),
            "jti": "access-jti",
            "email_otp_enabled": True,
            "scopes": [],
        }

    async def _lookup_user(**kwargs: object) -> object:
        return user

    service.validate_access_token = _otp_claims  # type: ignore[assignment]
    service._get_user_by_id = _lookup_user  # type: ignore[assignment]
    with pytest.raises(LifecycleServiceError, match="OTP required"):
        await service.reauthenticate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            access_token="access",
            password="Password123!",
        )

    async def _normal_claims(**kwargs: object) -> dict[str, object]:
        return {
            "sub": str(user.id),
            "jti": "access-jti",
            "email_otp_enabled": False,
            "scopes": [],
        }

    service.validate_access_token = _normal_claims  # type: ignore[assignment]
    brute_force.ensure_error = BruteForceProtectionError("locked", "account_locked", 401)
    with pytest.raises(LifecycleServiceError, match="locked"):
        await service.reauthenticate(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            access_token="access",
            password="Password123!",
        )
