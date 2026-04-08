"""Integration tests for signup email verification lifecycle flows."""

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
from app.core.sessions import get_redis_client
from app.core.signing_keys import get_signing_key_service
from app.models.session import Session
from app.models.user import User
from app.services.lifecycle_service import LifecycleService, get_lifecycle_service
from app.services.user_service import UserService


@dataclass
class _CapturedEmail:
    """Captured outgoing verification email payload."""

    to_email: str
    verification_link: str


@dataclass
class _CapturingEmailSender:
    """In-memory verification email sender for integration assertions."""

    messages: list[_CapturedEmail] = field(default_factory=list)

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        self.messages.append(_CapturedEmail(to_email=to_email, verification_link=verification_link))


def _build_lifecycle_service(sender: _CapturingEmailSender) -> LifecycleService:
    """Build lifecycle service with captured email sender and real infra dependencies."""
    settings = get_settings()
    return LifecycleService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        user_service=UserService(),
        redis_client=get_redis_client(),
        email_sender=sender,
        email_verify_ttl_seconds=settings.email.email_verify_ttl_seconds,
        public_base_url=str(settings.email.public_base_url),
    )


def _extract_token(verification_link: str) -> str:
    """Extract query token from verification link path."""
    parsed = urlparse(verification_link)
    return parse_qs(parsed.query)["token"][0]


@pytest.mark.asyncio
async def test_verify_email_happy_path_marks_user_verified(app_factory, db_session) -> None:
    """Signup sends a verification email and consuming the link verifies the account."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "verify@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201
        assert signup.json() == {"accepted": True}
        assert len(sender.messages) == 1
        assert sender.messages[0].verification_link.startswith(
            "http://localhost:8000/auth/verify-email?token="
        )
        token = _extract_token(sender.messages[0].verification_link)

        verify = await client.get("/auth/verify-email", params={"token": token})
        assert verify.status_code == 200
        assert verify.json() == {"verified": True}

    user = (
        await db_session.execute(
            select(User).where(User.email == "verify@example.com", User.deleted_at.is_(None))
        )
    ).scalar_one()
    assert user.email_verified is True
    assert user.email_verify_token_hash is None
    assert user.email_verify_token_expires is None
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_signup_hides_duplicate_email_state(app_factory, db_session) -> None:
    """Duplicate signup returns the same public response and does not create a second user."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        first = await client.post(
            "/auth/signup",
            json={"email": "duplicate@example.com", "password": "Password123!"},
        )
        second = await client.post(
            "/auth/signup",
            json={"email": "duplicate@example.com", "password": "Password123!"},
        )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json() == {"accepted": True}
    assert second.json() == {"accepted": True}
    assert len(sender.messages) == 1

    users = (
        (
            await db_session.execute(
                select(User).where(User.email == "duplicate@example.com", User.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert len(users) == 1
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_signup_and_public_resend_reject_invalid_email_payloads(app_factory) -> None:
    """Lifecycle email endpoints reject malformed email addresses with a 422 contract response."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "not-an-email", "password": "Password123!"},
        )
        resend = await client.post(
            "/auth/verify-email/resend/request",
            json={"email": "still-not-an-email"},
        )

    assert signup.status_code == 422
    assert signup.json()["code"] == "invalid_credentials"
    assert signup.json()["detail"].startswith("Invalid request payload")
    assert resend.status_code == 422
    assert resend.json()["code"] == "invalid_credentials"
    assert resend.json()["detail"].startswith("Invalid request payload")


@pytest.mark.asyncio
async def test_verify_email_rejects_expired_link_with_invalid_verify_token(
    app_factory, db_session
) -> None:
    """Expired verification links return invalid_verify_token."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "expired@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201
        token = _extract_token(sender.messages[0].verification_link)

        user = (
            await db_session.execute(
                select(User).where(User.email == "expired@example.com", User.deleted_at.is_(None))
            )
        ).scalar_one()
        user.email_verify_token_expires = datetime.now(UTC) - timedelta(seconds=1)
        await db_session.commit()

        verify = await client.get("/auth/verify-email", params={"token": token})
        assert verify.status_code == 400
        assert verify.json()["code"] == "invalid_verify_token"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_verify_email_rejects_already_used_link(app_factory) -> None:
    """Single-use verification links are invalid after first successful consumption."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "single-use@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201
        token = _extract_token(sender.messages[0].verification_link)

        first = await client.get("/auth/verify-email", params={"token": token})
        assert first.status_code == 200

        second = await client.get("/auth/verify-email", params={"token": token})
        assert second.status_code == 400
        assert second.json()["code"] == "invalid_verify_token"

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_signup_login_requires_email_verification(app_factory, db_session) -> None:
    """New password users cannot log in until they verify their email."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "resend@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201

        login = await client.post(
            "/auth/login",
            json={"email": "resend@example.com", "password": "Password123!"},
        )
        assert login.status_code == 400
        assert login.json() == {
            "detail": "Email is not verified.",
            "code": "email_not_verified",
        }

    user = (
        await db_session.execute(
            select(User).where(User.email == "resend@example.com", User.deleted_at.is_(None))
        )
    ).scalar_one()
    sessions = (
        (
            await db_session.execute(
                select(Session).where(Session.user_id == user.id, Session.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert sessions == []
    assert len(sender.messages) == 1
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_public_resend_verification_email_resends_for_unverified_user(app_factory) -> None:
    """Public resend issues a fresh verification link for an unverified account."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "pending@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201
        assert len(sender.messages) == 1

        resend = await client.post(
            "/auth/verify-email/resend/request",
            json={"email": "pending@example.com"},
        )
        assert resend.status_code == 200
        assert resend.json() == {"sent": True}
        assert len(sender.messages) == 2
        assert sender.messages[-1].verification_link.startswith(
            "http://localhost:8000/auth/verify-email?token="
        )

        token = _extract_token(sender.messages[-1].verification_link)
        verify = await client.get("/auth/verify-email", params={"token": token})
        assert verify.status_code == 200
        assert verify.json() == {"verified": True}

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_resend_rotates_verification_link_and_only_latest_link_succeeds(
    app_factory,
    db_session,
) -> None:
    """A resend replaces the previous verification token and login succeeds after verification."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "rotate@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201

        first_token = _extract_token(sender.messages[0].verification_link)
        resend = await client.post(
            "/auth/verify-email/resend/request",
            json={"email": "rotate@example.com"},
        )
        assert resend.status_code == 200
        second_token = _extract_token(sender.messages[-1].verification_link)
        assert second_token != first_token

        stale_verify = await client.get("/auth/verify-email", params={"token": first_token})
        assert stale_verify.status_code == 400
        assert stale_verify.json()["code"] == "invalid_verify_token"

        fresh_verify = await client.get("/auth/verify-email", params={"token": second_token})
        assert fresh_verify.status_code == 200
        assert fresh_verify.json() == {"verified": True}

        login = await client.post(
            "/auth/login",
            json={"email": "rotate@example.com", "password": "Password123!"},
        )
        assert login.status_code == 200
        assert "access_token" in login.json()

    user = (
        await db_session.execute(
            select(User).where(User.email == "rotate@example.com", User.deleted_at.is_(None))
        )
    ).scalar_one()
    assert user.email_verified is True
    assert user.email_verify_token_hash is None
    assert user.email_verify_token_expires is None
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_public_resend_hides_unknown_and_verified_account_state(app_factory) -> None:
    """Public resend returns the same success response for missing and already-verified emails."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        missing = await client.post(
            "/auth/verify-email/resend/request",
            json={"email": "missing-user@example.com"},
        )
        assert missing.status_code == 200
        assert missing.json() == {"sent": True}
        assert sender.messages == []

        signup = await client.post(
            "/auth/signup",
            json={"email": "verified-again@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201
        token = _extract_token(sender.messages[0].verification_link)

        verify = await client.get("/auth/verify-email", params={"token": token})
        assert verify.status_code == 200
        assert len(sender.messages) == 1

        verified = await client.post(
            "/auth/verify-email/resend/request",
            json={"email": "verified-again@example.com"},
        )
        assert verified.status_code == 200
        assert verified.json() == {"sent": True}
        assert len(sender.messages) == 1

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_public_resend_verification_email_rate_limit_is_enforced(app_factory) -> None:
    """Public resend endpoint allows 3 requests per hour and blocks the 4th."""
    app: FastAPI = app_factory()
    sender = _CapturingEmailSender()
    app.dependency_overrides[get_lifecycle_service] = lambda: _build_lifecycle_service(sender)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "rate-limit@example.com", "password": "Password123!"},
        )
        assert signup.status_code == 201

        for _ in range(3):
            resend = await client.post(
                "/auth/verify-email/resend/request",
                json={"email": "rate-limit@example.com"},
            )
            assert resend.status_code == 200
            assert resend.json() == {"sent": True}

        limited = await client.post(
            "/auth/verify-email/resend/request",
            json={"email": "rate-limit@example.com"},
        )
        assert limited.status_code == 429
        assert limited.json()["code"] == "rate_limited"

    assert len(sender.messages) == 4
    app.dependency_overrides.clear()
