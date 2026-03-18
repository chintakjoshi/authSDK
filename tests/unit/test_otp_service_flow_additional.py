"""Flow-oriented OTP service tests for remaining fail-closed branches."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest

from app.core.otp import hash_otp
from app.services.otp_service import OTPService, OTPServiceError
from app.services.token_service import TokenPair


class _JWTStub:
    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        return "issued-jwt"


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
    async def ensure_not_locked(self, user_id: str) -> None:
        del user_id

    async def record_failed_otp_attempt(self, user_id: str) -> _Decision:
        del user_id
        return _Decision()

    async def record_successful_login(
        self, user_id: str, ip_address=None, user_agent=None
    ) -> _Decision:  # type: ignore[no-untyped-def]
        del user_id, ip_address, user_agent
        return _Decision()


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
    def __init__(self) -> None:
        self.login_messages: list[tuple[str, str]] = []
        self.action_messages: list[tuple[str, str, str]] = []

    async def send_login_otp_email(self, to_email: str, code: str, expires_in_seconds: int) -> None:
        del expires_in_seconds
        self.login_messages.append((to_email, code))

    async def send_action_otp_email(
        self,
        to_email: str,
        action: str,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        del expires_in_seconds
        self.action_messages.append((to_email, action, code))


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
    email_otp_enabled: bool = True


def _service(email_sender: _EmailSenderStub | None = None) -> OTPService:
    return OTPService(
        jwt_service=_JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=_SessionServiceStub(),  # type: ignore[arg-type]
        brute_force_service=_BruteForceStub(),  # type: ignore[arg-type]
        redis_client=_RedisStub(),  # type: ignore[arg-type]
        email_sender=email_sender or _EmailSenderStub(),  # type: ignore[arg-type]
        otp_code_length=6,
        otp_ttl_seconds=600,
        otp_max_attempts=5,
        action_token_ttl_seconds=300,
        auth_service_audience="auth-service",
    )


@pytest.mark.asyncio
async def test_start_login_challenge_and_resend_login_code_success_paths() -> None:
    """Login OTP challenge issuance and resend return the documented payloads."""
    sender = _EmailSenderStub()
    service = _service(email_sender=sender)
    user = _UserStub(id=uuid4(), email="otp@example.com")

    async def _no_block(user_id: str) -> None:
        return None

    async def _store_hash(key: str, payload: dict[str, str], *, ttl_seconds: int) -> None:
        assert key.startswith("otp:login:")
        assert payload["attempt_count"] == "0"
        assert ttl_seconds == 600

    service._ensure_issuance_not_blocked = _no_block  # type: ignore[assignment]
    service._store_hash = _store_hash  # type: ignore[assignment]
    challenge = await service.start_login_challenge(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        user=user,  # type: ignore[arg-type]
    )
    assert challenge.user_id == str(user.id)
    assert challenge.challenge_token == "issued-jwt"
    assert sender.login_messages

    async def _challenge_claims(db_session, token: str) -> dict[str, object]:  # type: ignore[no-untyped-def]
        del db_session, token
        return {"sub": str(user.id)}

    async def _hash_payload(key: str) -> dict[str, str]:
        return {"code_hash": "hash"}

    async def _count(key: str, *, ttl_seconds: int) -> int:
        return 1

    async def _get_user(**kwargs: object) -> _UserStub:
        return user

    service._validate_challenge_token = _challenge_claims  # type: ignore[assignment]
    service._get_hash = _hash_payload  # type: ignore[assignment]
    service._increment_counter = _count  # type: ignore[assignment]
    service._get_user_by_id = _get_user  # type: ignore[assignment]
    resent_user_id = await service.resend_login_code(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        challenge_token="challenge-token",
    )
    assert resent_user_id == str(user.id)


@pytest.mark.asyncio
async def test_verify_login_code_and_action_code_reject_invalid_states() -> None:
    """OTP verification rejects expired, mismatched, and exhausted challenges."""
    service = _service()
    user = _UserStub(id=uuid4(), email="otp@example.com")

    async def _challenge_claims(db_session, token: str) -> dict[str, object]:  # type: ignore[no-untyped-def]
        del db_session, token
        return {"sub": str(user.id)}

    async def _empty_hash(key: str) -> dict[str, str] | None:
        return None

    service._validate_challenge_token = _challenge_claims  # type: ignore[assignment]
    service._get_hash = _empty_hash  # type: ignore[assignment]
    with pytest.raises(OTPServiceError) as exc_info:
        await service.verify_login_code(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            challenge_token="challenge-token",
            code="123456",
        )
    assert exc_info.value.code == "otp_expired"

    async def _action_payload(key: str) -> dict[str, str]:
        return {"code_hash": "hash", "action": "disable_otp"}

    service._get_hash = _action_payload  # type: ignore[assignment]
    with pytest.raises(OTPServiceError) as exc_info:
        await service.verify_action_code(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id=str(user.id),
            code="123456",
            action="enable_otp",
        )
    assert exc_info.value.code == "otp_action_mismatch"

    async def _attempts(key: str, field: str) -> int:
        return 6

    async def _delete(*keys: str) -> None:
        return None

    async def _shared_failed(user_id: str) -> None:
        return None

    async def _matching_action(key: str) -> dict[str, str]:
        return {"code_hash": "hash", "action": "enable_otp"}

    service._get_hash = _matching_action  # type: ignore[assignment]
    service._increment_hash_counter = _attempts  # type: ignore[assignment]
    service._delete_keys = _delete  # type: ignore[assignment]
    service._apply_shared_failed_attempt = _shared_failed  # type: ignore[assignment]
    with pytest.raises(OTPServiceError) as exc_info:
        await service.verify_action_code(
            db_session=_DBSessionStub(),  # type: ignore[arg-type]
            user_id=str(user.id),
            code="123456",
            action="enable_otp",
        )
    assert exc_info.value.code == "otp_max_attempts_exceeded"


@pytest.mark.asyncio
async def test_request_action_code_and_verify_action_code_success_paths() -> None:
    """Action OTP issuance and verification succeed for verified users."""
    sender = _EmailSenderStub()
    service = _service(email_sender=sender)
    user = _UserStub(id=uuid4(), email="action@example.com", email_verified=True)

    async def _get_user(**kwargs: object) -> _UserStub:
        return user

    async def _no_block(user_id: str) -> None:
        return None

    async def _store_hash(key: str, payload: dict[str, str], *, ttl_seconds: int) -> None:
        assert payload["action"] == "enable_otp"

    service._get_user_by_id = _get_user  # type: ignore[assignment]
    service._ensure_issuance_not_blocked = _no_block  # type: ignore[assignment]
    service._store_hash = _store_hash  # type: ignore[assignment]
    issued = await service.request_action_code(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        user_id=str(user.id),
        action="enable_otp",
    )
    assert issued.action == "enable_otp"
    assert sender.action_messages

    async def _matching_action(key: str) -> dict[str, str]:
        return {"code_hash": hash_otp("123456"), "action": "enable_otp"}

    async def _attempts(key: str, field: str) -> int:
        return 1

    async def _delete(*keys: str) -> None:
        return None

    service._get_hash = _matching_action  # type: ignore[assignment]
    service._increment_hash_counter = _attempts  # type: ignore[assignment]
    service._delete_keys = _delete  # type: ignore[assignment]
    verified = await service.verify_action_code(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        user_id=str(user.id),
        code="123456",
        action="enable_otp",
    )
    assert verified.action_token == "issued-jwt"
