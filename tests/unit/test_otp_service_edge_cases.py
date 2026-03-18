"""Additional OTP-service edge tests for coverage."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.jwt import TokenValidationError
from app.services.brute_force_service import BruteForceProtectionError
from app.services.otp_service import MailhogOTPEmailSender, OTPService, OTPServiceError
from app.services.token_service import TokenPair


class _JWTStub:
    def __init__(self) -> None:
        self.error: TokenValidationError | None = None

    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return "issued-jwt"

    def verify_token(  # type: ignore[no-untyped-def]
        self,
        token: str,
        expected_type: str,
        public_keys_by_kid=None,
        expected_audience=None,
    ):
        del token, expected_type, public_keys_by_kid, expected_audience
        if self.error is not None:
            raise self.error
        return {"sub": "user-1", "jti": "access-jti", "type": "access"}


class _SigningKeyStub:
    async def get_verification_public_keys(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return {"kid": "public"}

    async def get_active_signing_key(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return SimpleNamespace(private_key_pem="private", kid="kid-1")


class _TokenServiceStub:
    async def issue_token_pair(self, **kwargs: object) -> TokenPair:
        return TokenPair(access_token="access-token", refresh_token="refresh-token")


class _SessionStub:
    async def validate_access_token_session(self, *, db_session, access_jti):  # type: ignore[no-untyped-def]
        del db_session, access_jti
        return uuid4()

    async def create_login_session(self, **kwargs: object) -> object:
        return uuid4()


class _BruteForceStub:
    def __init__(self) -> None:
        self.ensure_error: Exception | None = None
        self.failed_error: Exception | None = None
        self.success_error: Exception | None = None

    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id
        if self.ensure_error is not None:
            raise self.ensure_error

    async def record_failed_otp_attempt(self, user_id: str) -> object:
        del user_id
        if self.failed_error is not None:
            raise self.failed_error
        return SimpleNamespace(locked=False, retry_after=None)

    async def record_successful_login(self, user_id: str, ip_address=None, user_agent=None) -> object:  # type: ignore[no-untyped-def]
        del user_id, ip_address, user_agent
        if self.success_error is not None:
            raise self.success_error
        return SimpleNamespace(suspicious=False, metadata={})


class _RedisStub:
    async def get(self, key: str) -> None:
        del key
        return None

    async def ttl(self, key: str) -> int:
        del key
        return -2

    async def incr(self, key: str) -> int:
        del key
        return 1

    async def expire(self, key: str, ttl: int) -> bool:
        del key, ttl
        return True

    async def set(self, key: str, value: str, *, ex: int, nx: bool) -> bool:  # type: ignore[no-untyped-def]
        del key, value, ex, nx
        return True

    async def hincrby(self, key: str, field: str, amount: int) -> int:
        del key, field, amount
        return 1

    async def hgetall(self, key: str) -> dict[str, str]:
        del key
        return {}

    async def hset(self, key: str, mapping: dict[str, str]) -> int:
        del key, mapping
        return 1

    async def delete(self, *keys: str) -> int:
        del keys
        return 1


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


def _service(
    *,
    jwt_service: _JWTStub | None = None,
    brute_force_service: _BruteForceStub | None = None,
) -> OTPService:
    return OTPService(
        jwt_service=jwt_service or _JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionStub(),  # type: ignore[arg-type]
        brute_force_service=brute_force_service or _BruteForceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        email_sender=_EmailSenderStub(),  # type: ignore[arg-type]
        otp_code_length=6,
        otp_ttl_seconds=600,
        otp_max_attempts=5,
        action_token_ttl_seconds=300,
        auth_service_audience="auth-service",
    )


@pytest.mark.asyncio
async def test_mailhog_sender_and_validate_access_token_cover_protocol_edges(monkeypatch) -> None:
    """OTP Mailhog sender and access-token validation cover SMTP and invalid-token branches."""
    sender = MailhogOTPEmailSender(host="mailhog", port=1025, email_from="from@example.com")
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

    monkeypatch.setattr("app.services.otp_service.asyncio.to_thread", _fake_to_thread)
    monkeypatch.setattr("app.services.otp_service.smtplib.SMTP", _SMTP)
    await sender.send_login_otp_email("user@example.com", "123456", 300)
    await sender.send_action_otp_email("user@example.com", "enable_otp", "123456", 300)
    assert len(messages) == 2
    assert messages[0]["Subject"] == "Your login verification code"

    jwt_service = _JWTStub()
    jwt_service.error = TokenValidationError("bad", "invalid_token")
    with pytest.raises(OTPServiceError, match="Invalid token"):
        await _service(jwt_service=jwt_service).validate_access_token(
            db_session=object(),  # type: ignore[arg-type]
            token="bad-token",
        )


@pytest.mark.asyncio
async def test_otp_flow_edges_cover_invalid_users_failures_and_dual_gate() -> None:
    """OTP service covers invalid challenge state, resend errors, action failures, and helper returns."""
    service = _service()

    async def _challenge_claims(db_session, challenge_token):  # type: ignore[no-untyped-def]
        del db_session, challenge_token
        return {"sub": ""}

    service._validate_challenge_token = _challenge_claims  # type: ignore[assignment]
    with pytest.raises(OTPServiceError, match="Invalid token"):
        await service.verify_login_code(
            db_session=object(),  # type: ignore[arg-type]
            challenge_token="challenge",
            code="123456",
        )

    async def _user_claims(db_session, challenge_token):  # type: ignore[no-untyped-def]
        del db_session, challenge_token
        return {"sub": "user-1"}

    async def _expired(key: str) -> None:
        del key
        return None

    service._validate_challenge_token = _user_claims  # type: ignore[assignment]
    service._get_hash = _expired  # type: ignore[assignment]
    with pytest.raises(OTPServiceError, match="OTP expired"):
        await service.resend_login_code(
            db_session=object(),  # type: ignore[arg-type]
            challenge_token="challenge",
        )

    async def _existing_hash(key: str) -> dict[str, str]:
        del key
        return {"code_hash": "hash"}

    async def _rate_limited(*args, **kwargs):  # type: ignore[no-untyped-def]
        return 4

    service._get_hash = _existing_hash  # type: ignore[assignment]
    service._increment_counter = _rate_limited  # type: ignore[assignment]
    with pytest.raises(OTPServiceError, match="Rate limit exceeded"):
        await service.resend_login_code(
            db_session=object(),  # type: ignore[arg-type]
            challenge_token="challenge",
        )

    async def _missing_user(**kwargs: object) -> None:
        return None

    service._get_user_by_id = _missing_user  # type: ignore[assignment]
    with pytest.raises(OTPServiceError, match="Invalid token"):
        await service.request_action_code(
            db_session=object(),  # type: ignore[arg-type]
            user_id="user-1",
            action="enable_otp",
        )

    user = SimpleNamespace(id=uuid4(), email="user@example.com", email_verified=False)

    async def _unverified_user(**kwargs: object) -> object:
        return user

    service._get_user_by_id = _unverified_user  # type: ignore[assignment]
    with pytest.raises(OTPServiceError, match="not verified"):
        await service.request_action_code(
            db_session=object(),  # type: ignore[arg-type]
            user_id="user-1",
            action="enable_otp",
        )

    async def _action_payload(key: str) -> dict[str, str]:
        del key
        return {"code_hash": "bad-hash", "action": "enable_otp"}

    async def _attempts(*args, **kwargs):  # type: ignore[no-untyped-def]
        return 1

    async def _failed(*args, **kwargs):  # type: ignore[no-untyped-def]
        return True

    service._get_hash = _action_payload  # type: ignore[assignment]
    service._increment_hash_counter = _attempts  # type: ignore[assignment]

    async def _shared_failed(user_id: str) -> None:
        del user_id

    service._apply_shared_failed_attempt = _shared_failed  # type: ignore[assignment]
    service._increment_failed_counter = _failed  # type: ignore[assignment]
    with pytest.raises(OTPServiceError) as exc_info:
        await service.verify_action_code(
            db_session=object(),  # type: ignore[arg-type]
            user_id="user-1",
            code="123456",
            action="enable_otp",
        )
    assert exc_info.value.audit_events == ("otp.failed", "otp.excessive_failures")

    assert (
        await service.validate_action_token_for_user(
            db_session=object(),  # type: ignore[arg-type]
            token=None,
            expected_action="enable_otp",
            user_id="user-1",
        )
        is False
    )


@pytest.mark.asyncio
async def test_otp_reauth_helpers_cover_backend_and_runtime_errors() -> None:
    """OTP helpers cover lock/failure mappings and invalid action-token claims."""
    brute_force = _BruteForceStub()
    brute_force.ensure_error = BruteForceProtectionError("locked", "account_locked", 401)
    with pytest.raises(OTPServiceError, match="locked"):
        await _service(brute_force_service=brute_force)._ensure_not_locked("user-1")

    brute_force = _BruteForceStub()
    brute_force.failed_error = BruteForceProtectionError("backend", "session_expired", 503)
    with pytest.raises(OTPServiceError, match="backend"):
        await _service(brute_force_service=brute_force)._apply_shared_failed_attempt("user-1")

    brute_force = _BruteForceStub()
    brute_force.success_error = BruteForceProtectionError("backend", "session_expired", 503)
    with pytest.raises(OTPServiceError, match="backend"):
        await _service(brute_force_service=brute_force)._record_successful_login(
            "user-1",
            client_ip=None,
            user_agent=None,
        )

    service = _service()
    with pytest.raises(OTPServiceError, match="Invalid action token"):
        await service._validate_action_token(
            db_session=object(),  # type: ignore[arg-type]
            token="bad-token",
            expected_action="enable_otp",
            user_id="not-a-uuid",
        )
