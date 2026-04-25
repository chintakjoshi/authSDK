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


class _AsyncJWTStub(_JWTStub):
    def __init__(self) -> None:
        self.async_calls: list[dict[str, object]] = []

    async def issue_token_async(self, **kwargs: object) -> str:
        self.async_calls.append(dict(kwargs))
        return f"issued-{kwargs['token_type']}"

    def issue_token(self, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("OTPService should use issue_token_async when available")


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
    def __init__(self) -> None:
        self.create_calls: list[dict[str, object]] = []

    async def validate_access_token_session(self, *, db_session, access_jti):  # type: ignore[no-untyped-def]
        del db_session, access_jti
        return uuid4()

    async def create_login_session(self, **kwargs: object) -> object:
        self.create_calls.append(dict(kwargs))
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
    mfa_enabled: bool = True


def _service(
    *,
    email_sender: _EmailSenderStub | None = None,
    jwt_service: _JWTStub | None = None,
    session_service: _SessionServiceStub | None = None,
) -> OTPService:
    return OTPService(
        jwt_service=jwt_service or _JWTStub(),  # type: ignore[arg-type]
        signing_key_service=_SigningKeyStub(),  # type: ignore[arg-type]
        token_service=_TokenServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
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
    stored_hashes: list[str] = []

    async def _no_block(user_id: str) -> None:
        return None

    async def _store_hash(key: str, payload: dict[str, str], *, ttl_seconds: int) -> None:
        assert key.startswith("otp:login:")
        assert payload["attempt_count"] == "0"
        stored_hashes.append(payload["code_hash"])
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
    assert stored_hashes[0] == hash_otp(sender.login_messages[0][1])

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
    assert stored_hashes[1] == hash_otp(sender.login_messages[1][1])


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


@pytest.mark.asyncio
async def test_verify_login_code_passes_suspicious_flags_to_session_creation() -> None:
    """OTP-backed login persists suspicious-session flags onto the created session."""
    session_service = _SessionServiceStub()
    service = _service(session_service=session_service)
    user = _UserStub(id=uuid4(), email="otp@example.com", email_verified=True)

    async def _challenge_claims(db_session, token: str) -> dict[str, object]:  # type: ignore[no-untyped-def]
        del db_session, token
        return {"sub": str(user.id)}

    async def _otp_payload(key: str) -> dict[str, str]:
        del key
        return {"code_hash": hash_otp("123456")}

    async def _attempts(key: str, field: str) -> int:
        del key, field
        return 1

    async def _delete(*keys: str) -> None:
        del keys
        return None

    async def _get_user(**kwargs: object) -> _UserStub:
        del kwargs
        return user

    async def _record_successful_login(**kwargs: object) -> dict[str, object]:
        del kwargs
        return {"new_ip": True, "new_user_agent": True, "prior_failures": 4}

    service._validate_challenge_token = _challenge_claims  # type: ignore[assignment]
    service._get_hash = _otp_payload  # type: ignore[assignment]
    service._increment_hash_counter = _attempts  # type: ignore[assignment]
    service._delete_keys = _delete  # type: ignore[assignment]
    service._get_user_by_id = _get_user  # type: ignore[assignment]
    service._record_successful_login = _record_successful_login  # type: ignore[assignment]

    verified = await service.verify_login_code(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        challenge_token="challenge-token",
        code="123456",
        client_ip="203.0.113.10",
        user_agent="pytest-agent",
    )

    assert verified.suspicious_login == {
        "new_ip": True,
        "new_user_agent": True,
        "prior_failures": 4,
    }
    assert session_service.create_calls[0]["is_suspicious"] is True
    assert session_service.create_calls[0]["suspicious_reasons"] == [
        "new_ip",
        "new_user_agent",
        "prior_failures",
    ]


@pytest.mark.asyncio
async def test_otp_issue_paths_prefer_async_jwt_helper_when_available() -> None:
    """OTP challenge and action-token issuance should use the async JWT helper when present."""
    sender = _EmailSenderStub()
    jwt_service = _AsyncJWTStub()
    service = _service(email_sender=sender, jwt_service=jwt_service)
    user = _UserStub(id=uuid4(), email="otp@example.com", email_verified=True)

    async def _no_block(user_id: str) -> None:
        del user_id
        return None

    async def _store_hash(key: str, payload: dict[str, str], *, ttl_seconds: int) -> None:
        del key, payload, ttl_seconds
        return None

    service._ensure_issuance_not_blocked = _no_block  # type: ignore[assignment]
    service._store_hash = _store_hash  # type: ignore[assignment]

    challenge = await service.start_login_challenge(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        user=user,  # type: ignore[arg-type]
    )

    async def _matching_action(key: str) -> dict[str, str]:
        del key
        return {"code_hash": hash_otp("123456"), "action": "enable_otp"}

    async def _attempts(key: str, field: str) -> int:
        del key, field
        return 1

    async def _delete(*keys: str) -> None:
        del keys
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

    assert challenge.challenge_token == "issued-otp_challenge"
    assert verified.action_token == "issued-action_token"
    assert [call["token_type"] for call in jwt_service.async_calls] == [
        "otp_challenge",
        "action_token",
    ]
