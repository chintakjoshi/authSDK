"""Integration tests for email OTP login and action flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy import select

from app.config import get_settings
from app.core.jwt import get_jwt_service
from app.core.sessions import get_redis_client, get_session_service
from app.core.signing_keys import get_signing_key_service
from app.models.user import User
from app.schemas.otp import OTPAction
from app.services.brute_force_service import get_brute_force_service
from app.services.otp_service import OTPService, get_otp_service
from app.services.token_service import get_token_service


@dataclass
class _CapturedOTPMessage:
    """Captured OTP email payload."""

    kind: str
    code: str
    to_email: str
    action: OTPAction | None = None


@dataclass
class _CapturingOTPEmailSender:
    """In-memory OTP sender for integration assertions."""

    messages: list[_CapturedOTPMessage] = field(default_factory=list)

    async def send_login_otp_email(self, to_email: str, code: str, expires_in_seconds: int) -> None:
        del expires_in_seconds
        self.messages.append(_CapturedOTPMessage(kind="login", code=code, to_email=to_email))

    async def send_action_otp_email(
        self,
        to_email: str,
        action: OTPAction,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        del expires_in_seconds
        self.messages.append(
            _CapturedOTPMessage(kind="action", code=code, to_email=to_email, action=action)
        )

    def latest_code(self, kind: str, action: OTPAction | None = None) -> str:
        """Return the most recent OTP code matching the requested message kind."""
        for message in reversed(self.messages):
            if message.kind == kind and message.action == action:
                return message.code
        raise AssertionError(f"No captured OTP message for kind={kind!r} action={action!r}")


def _build_otp_service(sender: _CapturingOTPEmailSender) -> OTPService:
    """Build OTP service with captured sender and real infra dependencies."""
    settings = get_settings()
    return OTPService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        token_service=get_token_service(),
        session_service=get_session_service(),
        brute_force_service=get_brute_force_service(),
        redis_client=get_redis_client(),
        email_sender=sender,
        otp_code_length=settings.email.otp_code_length,
        otp_ttl_seconds=settings.email.otp_ttl_seconds,
        otp_max_attempts=settings.email.otp_max_attempts,
        action_token_ttl_seconds=settings.email.action_token_ttl_seconds,
    )


async def _set_user_flags(
    db_session,
    user_id: UUID,
    *,
    email_verified: bool,
    email_otp_enabled: bool,
) -> User:
    """Update one user's OTP-related verification flags."""
    user = (await db_session.execute(select(User).where(User.id == user_id))).scalar_one()
    user.email_verified = email_verified
    user.email_otp_enabled = email_otp_enabled
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_login_with_email_otp_happy_path(app_factory, user_factory, db_session) -> None:
    """OTP-enabled logins return a challenge and complete only after code verification."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    app.dependency_overrides[get_otp_service] = lambda: _build_otp_service(sender)

    user = await user_factory("otp-login@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        user.id,
        email_verified=True,
        email_otp_enabled=True,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "otp-login@example.com", "password": "Password123!"},
        )
        assert login.status_code == 200
        payload = login.json()
        assert payload["otp_required"] is True
        assert "access_token" not in payload
        assert payload["masked_email"] == "o********@example.com"

        verify = await client.post(
            "/auth/otp/verify/login",
            json={
                "challenge_token": payload["challenge_token"],
                "code": sender.latest_code("login"),
            },
        )
        assert verify.status_code == 200
        verified_payload = verify.json()
        assert verified_payload["access_token"]
        assert verified_payload["refresh_token"]

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_login_otp_enforces_invalid_and_max_attempt_paths(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Wrong login OTPs preserve the challenge until the max-attempt threshold is crossed."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    app.dependency_overrides[get_otp_service] = lambda: _build_otp_service(sender)

    user = await user_factory("otp-fail@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        user.id,
        email_verified=True,
        email_otp_enabled=True,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "otp-fail@example.com", "password": "Password123!"},
        )
        challenge_token = login.json()["challenge_token"]
        wrong_code = "999999" if sender.latest_code("login") != "999999" else "000000"

        for _ in range(4):
            invalid = await client.post(
                "/auth/otp/verify/login",
                json={"challenge_token": challenge_token, "code": wrong_code},
            )
            assert invalid.status_code == 401
            assert invalid.json()["code"] == "invalid_otp"

        locked = await client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": wrong_code},
        )
        assert locked.status_code == 401
        assert locked.json()["code"] == "account_locked"
        assert locked.headers["retry-after"] == "60"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_login_otp_resend_replaces_active_code(app_factory, user_factory, db_session) -> None:
    """Resending login OTP replaces the active code while keeping the same challenge token."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    app.dependency_overrides[get_otp_service] = lambda: _build_otp_service(sender)

    user = await user_factory("otp-resend@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        user.id,
        email_verified=True,
        email_otp_enabled=True,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "otp-resend@example.com", "password": "Password123!"},
        )
        challenge_token = login.json()["challenge_token"]
        first_code = sender.latest_code("login")

        resend = await client.post(
            "/auth/otp/resend/login",
            json={"challenge_token": challenge_token},
        )
        assert resend.status_code == 200
        second_code = sender.latest_code("login")
        if second_code == first_code:
            resend = await client.post(
                "/auth/otp/resend/login",
                json={"challenge_token": challenge_token},
            )
            assert resend.status_code == 200
            second_code = sender.latest_code("login")

        old_code = await client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": first_code},
        )
        assert old_code.status_code == 401
        assert old_code.json()["code"] == "invalid_otp"

        new_code = await client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": second_code},
        )
        assert new_code.status_code == 200
        assert new_code.json()["access_token"]

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_action_otp_enables_and_disables_login_otp(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Fresh auth can enable OTP, while OTP-enabled users still require the OTP gate."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    app.dependency_overrides[get_otp_service] = lambda: _build_otp_service(sender)

    user = await user_factory("action-otp@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        user.id,
        email_verified=True,
        email_otp_enabled=False,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "action-otp@example.com", "password": "Password123!"},
        )
        access_token = login.json()["access_token"]
        headers = {"authorization": f"Bearer {access_token}"}

        enable = await client.post("/auth/otp/enable", headers=headers)
        assert enable.status_code == 200
        assert enable.json() == {"email_otp_enabled": True}

        request_enable = await client.post(
            "/auth/otp/request/action",
            json={"action": "enable_otp"},
            headers=headers,
        )
        assert request_enable.status_code == 200

        verify_enable = await client.post(
            "/auth/otp/verify/action",
            json={"action": "enable_otp", "code": sender.latest_code("action", "enable_otp")},
            headers=headers,
        )
        assert verify_enable.status_code == 200
        enable_action_token = verify_enable.json()["action_token"]

        enable_with_action = await client.post(
            "/auth/otp/enable",
            headers={**headers, "x-action-token": enable_action_token},
        )
        assert enable_with_action.status_code == 200
        assert enable_with_action.json() == {"email_otp_enabled": True}

        login_with_otp = await client.post(
            "/auth/login",
            json={"email": "action-otp@example.com", "password": "Password123!"},
        )
        assert login_with_otp.status_code == 200
        assert login_with_otp.json()["otp_required"] is True
        challenge_token = login_with_otp.json()["challenge_token"]

        verified_login = await client.post(
            "/auth/otp/verify/login",
            json={"challenge_token": challenge_token, "code": sender.latest_code("login")},
        )
        assert verified_login.status_code == 200
        otp_access_token = verified_login.json()["access_token"]
        otp_headers = {"authorization": f"Bearer {otp_access_token}"}

        disable_without_action = await client.post("/auth/otp/disable", headers=otp_headers)
        assert disable_without_action.status_code == 403
        assert disable_without_action.json()["code"] == "otp_required"
        assert disable_without_action.headers["x-otp-required"] == "true"
        assert disable_without_action.headers["x-otp-action"] == "disable_otp"

        request_disable = await client.post(
            "/auth/otp/request/action",
            json={"action": "disable_otp"},
            headers=otp_headers,
        )
        assert request_disable.status_code == 200

        verify_disable = await client.post(
            "/auth/otp/verify/action",
            json={"action": "disable_otp", "code": sender.latest_code("action", "disable_otp")},
            headers=otp_headers,
        )
        assert verify_disable.status_code == 200

        disable = await client.post(
            "/auth/otp/disable",
            headers={**otp_headers, "x-action-token": verify_disable.json()["action_token"]},
        )
        assert disable.status_code == 200
        assert disable.json() == {"email_otp_enabled": False}

        login_after_disable = await client.post(
            "/auth/login",
            json={"email": "action-otp@example.com", "password": "Password123!"},
        )
        assert login_after_disable.status_code == 200
        assert login_after_disable.json()["access_token"]

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_action_otp_request_requires_verified_email(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Users with unverified email cannot start the action OTP flow for enrollment."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    app.dependency_overrides[get_otp_service] = lambda: _build_otp_service(sender)

    user = await user_factory("unverified-action@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        user.id,
        email_verified=False,
        email_otp_enabled=False,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "unverified-action@example.com", "password": "Password123!"},
        )
        access_token = login.json()["access_token"]
        request_action = await client.post(
            "/auth/otp/request/action",
            json={"action": "enable_otp"},
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert request_action.status_code == 400
    assert request_action.json()["code"] == "email_not_verified"
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_enable_otp_requires_reauth_when_auth_time_is_stale(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Non-OTP users fall back to password reauth when auth_time is stale."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    app.dependency_overrides[get_otp_service] = lambda: _build_otp_service(sender)

    user = await user_factory("reauth-enable@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        user.id,
        email_verified=True,
        email_otp_enabled=False,
    )
    active_key = await get_signing_key_service().get_active_signing_key(db_session)
    await db_session.rollback()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "reauth-enable@example.com", "password": "Password123!"},
        )
        assert login.status_code == 200
        current_access_token = login.json()["access_token"]
        current_claims = get_jwt_service().verify_token(
            current_access_token, expected_type="access"
        )
        stale_access_token = jwt.encode(
            {
                **current_claims,
                "iat": int((datetime.now(UTC) - timedelta(minutes=10)).timestamp()),
                "auth_time": int((datetime.now(UTC) - timedelta(minutes=10)).timestamp()),
                "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            },
            active_key.private_key_pem,
            algorithm="RS256",
            headers={"kid": active_key.kid},
        )

        missing_reauth = await client.post(
            "/auth/otp/enable",
            headers={"authorization": f"Bearer {stale_access_token}"},
        )
        assert missing_reauth.status_code == 403
        assert missing_reauth.json()["code"] == "reauth_required"
        assert missing_reauth.headers["x-reauth-required"] == "true"

        reauth = await client.post(
            "/auth/reauth",
            json={"password": "Password123!"},
            headers={"authorization": f"Bearer {stale_access_token}"},
        )
        assert reauth.status_code == 200
        fresh_access_token = reauth.json()["access_token"]

        enable = await client.post(
            "/auth/otp/enable",
            headers={"authorization": f"Bearer {fresh_access_token}"},
        )
        assert enable.status_code == 200
        assert enable.json() == {"email_otp_enabled": True}

    app.dependency_overrides.clear()
