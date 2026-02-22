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
        assert signup.json()["email_verified"] is False
        assert len(sender.messages) == 1
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
async def test_verify_email_resend_rate_limit_enforced_per_user(app_factory) -> None:
    """Resend endpoint allows 3 requests per hour and blocks the 4th."""
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
        assert login.status_code == 200
        access_token = login.json()["access_token"]
        headers = {"authorization": f"Bearer {access_token}"}

        for _ in range(3):
            resend = await client.post("/auth/verify-email/resend", headers=headers)
            assert resend.status_code == 200
            assert resend.json() == {"sent": True}

        limited = await client.post("/auth/verify-email/resend", headers=headers)
        assert limited.status_code == 429
        assert limited.json()["code"] == "rate_limited"

    assert len(sender.messages) == 4
    app.dependency_overrides.clear()
