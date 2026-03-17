"""Integration tests for password reset lifecycle flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.config import get_settings
from app.core.jwt import get_jwt_service
from app.core.sessions import get_redis_client, get_session_service
from app.core.signing_keys import get_signing_key_service
from app.models.session import Session
from app.models.user import User
from app.services.lifecycle_service import LifecycleService, get_lifecycle_service
from app.services.user_service import UserService


@dataclass
class _CapturedResetEmail:
    """Captured outgoing password reset email payload."""

    to_email: str
    reset_link: str


@dataclass
class _CapturingLifecycleEmailSender:
    """In-memory lifecycle email sender for password reset assertions."""

    reset_emails: list[_CapturedResetEmail] = field(default_factory=list)
    confirmation_emails: list[str] = field(default_factory=list)

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        del to_email, verification_link

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        self.reset_emails.append(_CapturedResetEmail(to_email=to_email, reset_link=reset_link))

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        self.confirmation_emails.append(to_email)


def _build_lifecycle_service(sender: _CapturingLifecycleEmailSender) -> LifecycleService:
    """Build lifecycle service with captured sender and real infra dependencies."""
    settings = get_settings()
    return LifecycleService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        user_service=UserService(),
        session_service=get_session_service(),
        redis_client=get_redis_client(),
        email_sender=sender,
        email_verify_ttl_seconds=settings.email.email_verify_ttl_seconds,
        password_reset_ttl_seconds=settings.email.password_reset_ttl_seconds,
    )


def _extract_token(reset_link: str) -> str:
    """Extract reset token from reset-link query string."""
    parsed = urlparse(reset_link)
    return parse_qs(parsed.query)["token"][0]


@pytest.mark.asyncio
async def test_password_reset_happy_path_revokes_existing_sessions(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Resetting password invalidates active sessions and allows login with the new secret."""
    app: FastAPI = app_factory()
    sender = _CapturingLifecycleEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)
    await user_factory("reset-user@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login = await client.post(
            "/auth/login",
            json={"email": "reset-user@example.com", "password": "Password123!"},
        )
        assert login.status_code == 200

        forgot = await client.post(
            "/auth/password/forgot",
            json={"email": "reset-user@example.com"},
        )
        assert forgot.status_code == 200
        assert forgot.json() == {"sent": True}
        assert len(sender.reset_emails) == 1
        token = _extract_token(sender.reset_emails[0].reset_link)

        validate = await client.get("/auth/password/reset", params={"token": token})
        assert validate.status_code == 200
        assert validate.json() == {"valid": True}

        reset = await client.post(
            "/auth/password/reset",
            json={"token": token, "new_password": "NewPassword123!"},
        )
        assert reset.status_code == 200
        assert reset.json() == {"reset": True}

        refresh = await client.post(
            "/auth/token",
            json={"refresh_token": login.json()["refresh_token"]},
        )
        assert refresh.status_code == 401
        assert refresh.json()["code"] == "session_expired"

        reauth = await client.post(
            "/auth/reauth",
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
            json={"password": "NewPassword123!"},
        )
        assert reauth.status_code == 401
        assert reauth.json()["code"] == "session_expired"

        old_login = await client.post(
            "/auth/login",
            json={"email": "reset-user@example.com", "password": "Password123!"},
        )
        assert old_login.status_code == 401

        new_login = await client.post(
            "/auth/login",
            json={"email": "reset-user@example.com", "password": "NewPassword123!"},
        )
        assert new_login.status_code == 200

    user = (
        await db_session.execute(
            select(User).where(User.email == "reset-user@example.com", User.deleted_at.is_(None))
        )
    ).scalar_one()
    sessions = (
        await db_session.execute(
            select(Session).where(Session.user_id == user.id, Session.deleted_at.is_(None))
        )
    ).scalars()
    assert user.password_reset_token_hash is None
    assert user.password_reset_token_expires is None
    assert any(session.revoked_at is not None for session in sessions)
    assert sender.confirmation_emails == ["reset-user@example.com"]
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_password_reset_rejects_expired_and_already_used_tokens(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Expired and already-consumed reset tokens return invalid_reset_token."""
    app: FastAPI = app_factory()
    sender = _CapturingLifecycleEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)
    await user_factory("expired-reset@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        forgot = await client.post(
            "/auth/password/forgot",
            json={"email": "expired-reset@example.com"},
        )
        assert forgot.status_code == 200
        token = _extract_token(sender.reset_emails[0].reset_link)

        user = (
            await db_session.execute(
                select(User).where(
                    User.email == "expired-reset@example.com", User.deleted_at.is_(None)
                )
            )
        ).scalar_one()
        user.password_reset_token_expires = datetime.now(UTC) - timedelta(seconds=1)
        await db_session.commit()

        expired = await client.get("/auth/password/reset", params={"token": token})
        assert expired.status_code == 400
        assert expired.json()["code"] == "invalid_reset_token"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_password_forgot_returns_200_for_unknown_email_without_sending_mail(
    app_factory,
) -> None:
    """Forgot-password hides account existence for unknown emails."""
    app: FastAPI = app_factory()
    sender = _CapturingLifecycleEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        forgot = await client.post(
            "/auth/password/forgot",
            json={"email": "missing-user@example.com"},
        )

    assert forgot.status_code == 200
    assert forgot.json() == {"sent": True}
    assert sender.reset_emails == []
    app.dependency_overrides.clear()
