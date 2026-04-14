"""Integration tests for GDPR erasure flows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.config import get_settings
from app.core.jwt import get_jwt_service
from app.core.sessions import get_redis_client, get_session_service
from app.core.signing_keys import get_signing_key_service
from app.db.session import get_session_factory
from app.models.api_key import APIKey
from app.models.audit_event import AuditEvent
from app.models.session import Session
from app.models.user import User, UserIdentity
from app.models.webhook_delivery import WebhookDelivery
from app.services.admin_service import AdminService, get_admin_service
from app.services.api_key_service import get_api_key_service
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import get_brute_force_service
from app.services.erasure_service import get_erasure_service
from app.services.m2m_service import get_m2m_service
from app.services.otp_service import OTPService, get_otp_service
from app.services.token_service import get_token_service
from app.services.user_service import UserService
from app.services.webhook_service import (
    WebhookSendResult,
    WebhookService,
    get_webhook_service,
)


@dataclass
class _CapturedOTPMessage:
    """Captured OTP email payload."""

    kind: str
    code: str
    to_email: str
    action: str | None = None


@dataclass
class _CapturingOTPEmailSender:
    """In-memory OTP sender for GDPR erasure assertions."""

    messages: list[_CapturedOTPMessage] = field(default_factory=list)

    async def send_login_otp_email(self, to_email: str, code: str, expires_in_seconds: int) -> None:
        del expires_in_seconds
        self.messages.append(_CapturedOTPMessage(kind="login", code=code, to_email=to_email))

    async def send_action_otp_email(
        self,
        to_email: str,
        action: str,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        del expires_in_seconds
        self.messages.append(
            _CapturedOTPMessage(kind="action", code=code, to_email=to_email, action=action)
        )

    def latest_code(self, kind: str, action: str | None = None) -> str:
        """Return the newest OTP code matching the requested kind/action."""
        for message in reversed(self.messages):
            if message.kind == kind and message.action == action:
                return message.code
        raise AssertionError(f"No OTP captured for kind={kind!r} action={action!r}")


@dataclass
class _FakeQueue:
    """Queue stub that records enqueued delivery IDs."""

    enqueued: list[str] = field(default_factory=list)

    def enqueue(self, func: str, *args: object, **kwargs: object) -> object:
        del func, kwargs
        self.enqueued.append(str(args[0]))
        return object()


@dataclass
class _FakeScheduler:
    """Scheduler stub that records delayed delivery IDs."""

    scheduled: list[str] = field(default_factory=list)

    def enqueue_at(self, scheduled_time, func: str, *args: object, **kwargs: object) -> object:  # type: ignore[no-untyped-def]
        del scheduled_time, func, kwargs
        self.scheduled.append(str(args[0]))
        return object()


@dataclass
class _FakeSender:
    """Webhook sender stub for erasure tests."""

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        del url, payload, secret
        return WebhookSendResult(status_code=200, body="ok", delivered=True)


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
        auth_service_audience=settings.app.service,
    )


def _build_webhook_service() -> WebhookService:
    """Build webhook service with fake queueing collaborators."""
    return WebhookService(
        session_factory=get_session_factory(),
        sender=_FakeSender(),
        queue=_FakeQueue(),
        scheduler=_FakeScheduler(),
        audit_service=AuditService(),
        response_body_max_chars=1000,
        secret_encryption_key="gdpr-webhook-secret",
        encryption_fallback_seed="gdpr-webhook-seed",
    )


def _build_admin_service(*, otp_service: OTPService) -> AdminService:
    """Build admin service using the overridden OTP dependency for action-token checks."""
    return AdminService(
        user_service=UserService(),
        session_service=get_session_service(),
        otp_service=otp_service,
        brute_force_service=get_brute_force_service(),
        api_key_service=get_api_key_service(),
        m2m_service=get_m2m_service(),
        webhook_service=get_webhook_service(),
        audit_service=get_audit_service(),
        signing_key_service=get_signing_key_service(),
        erasure_service=get_erasure_service(),
        enable_retention_purge=False,
        audit_log_retention_days=90,
        session_log_retention_days=30,
    )


async def _set_user_flags(
    db_session,
    user_id: UUID,
    *,
    email_verified: bool,
    email_otp_enabled: bool,
    role: str | None = None,
) -> User:
    """Update one user's verification, OTP, and optional role flags."""
    user = (await db_session.execute(select(User).where(User.id == user_id))).scalar_one()
    user.email_verified = email_verified
    user.email_otp_enabled = email_otp_enabled
    if role is not None:
        user.role = role
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def _login_with_optional_otp(
    client: AsyncClient,
    *,
    email: str,
    password: str,
    sender: _CapturingOTPEmailSender,
) -> dict[str, Any]:
    """Login and complete OTP when required."""
    login = await client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    payload = login.json()
    if payload.get("otp_required"):
        verify = await client.post(
            "/auth/otp/verify/login",
            json={
                "challenge_token": payload["challenge_token"],
                "code": sender.latest_code("login"),
            },
        )
        assert verify.status_code == 200
        payload = verify.json()
    return payload


@pytest.mark.asyncio
async def test_self_service_erasure_revokes_sessions_cleans_otp_and_scrubs_pii(
    app_factory,
    user_factory,
    api_key_row_factory,
    db_session,
) -> None:
    """Self-service erasure anonymizes the account and invalidates all remaining access."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    otp_service = _build_otp_service(sender)
    webhook_service = _build_webhook_service()
    app.dependency_overrides[get_otp_service] = lambda: otp_service
    app.dependency_overrides[get_webhook_service] = lambda: webhook_service

    user = await user_factory("erase-me@example.com", "Password123!")
    user_id = user.id
    await _set_user_flags(
        db_session,
        user_id,
        email_verified=True,
        email_otp_enabled=True,
    )
    identity = UserIdentity(
        user_id=user_id,
        provider="google",
        provider_user_id="google-user-1",
        email="erase-me@example.com",
    )
    db_session.add(identity)
    await db_session.commit()
    api_key = await api_key_row_factory("sk_user_owned_gdpr_key", "orders:read", user_id, None)
    api_key_id = api_key.id
    await webhook_service.register_endpoint(
        db_session=db_session,
        name="GDPR Hook",
        url="https://example.com/gdpr",
        secret="super-secret-hook",
        events=["user.erased"],
    )

    redis_client = get_redis_client()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_payload = await _login_with_optional_otp(
            client,
            email="erase-me@example.com",
            password="Password123!",
            sender=sender,
        )
        access_token = str(login_payload["access_token"])
        refresh_token = str(login_payload["refresh_token"])
        headers = {"authorization": f"Bearer {access_token}"}

        request_action = await client.post(
            "/auth/otp/request/action",
            json={"action": "erase_account"},
            headers=headers,
        )
        assert request_action.status_code == 200

        verify_action = await client.post(
            "/auth/otp/verify/action",
            json={"action": "erase_account", "code": sender.latest_code("action", "erase_account")},
            headers=headers,
        )
        assert verify_action.status_code == 200
        action_token = verify_action.json()["action_token"]

        await redis_client.hset(
            f"otp:login:{user_id}",
            mapping={"code_hash": "hash", "attempt_count": "0"},
        )
        await redis_client.hset(
            f"otp:action:{user_id}",
            mapping={"code_hash": "hash", "attempt_count": "0", "action": "erase_account"},
        )
        await redis_client.set(f"otp_failed:{user_id}", "12")
        await redis_client.set(f"otp_issuance_blocked:{user_id}", "1")
        await redis_client.set(f"otp_resend_login:{user_id}", "1")

        erased = await client.post(
            "/auth/users/me/erase",
            headers={**headers, "x-action-token": action_token},
        )
        assert erased.status_code == 200
        assert erased.json() == {"erased": True, "user_id": str(user_id)}

        refresh = await client.post("/auth/token", json={"refresh_token": refresh_token})
        assert refresh.status_code == 401
        assert refresh.json()["code"] == "session_expired"

        stale_access = await client.post(
            "/auth/otp/request/action",
            json={"action": "enable_otp"},
            headers=headers,
        )
        assert stale_access.status_code == 401
        assert stale_access.json()["code"] == "session_expired"

    db_session.expire_all()
    erased_user = (await db_session.execute(select(User).where(User.id == user_id))).scalar_one()
    assert erased_user.email == f"deleted_{user_id}@erased.invalid"
    assert erased_user.password_hash is None
    assert erased_user.is_active is False
    assert erased_user.email_verified is False
    assert erased_user.email_otp_enabled is False
    assert erased_user.email_verify_token_hash is None
    assert erased_user.email_verify_token_expires is None
    assert erased_user.password_reset_token_hash is None
    assert erased_user.password_reset_token_expires is None
    assert erased_user.deleted_at is not None

    identities = (
        await db_session.execute(select(UserIdentity).where(UserIdentity.user_id == user_id))
    ).scalars()
    assert list(identities) == []

    sessions = (
        (await db_session.execute(select(Session).where(Session.user_id == user_id)))
        .scalars()
        .all()
    )
    assert sessions
    assert all(session.revoked_at is not None for session in sessions)

    refreshed_api_key = (
        await db_session.execute(select(APIKey).where(APIKey.id == api_key_id))
    ).scalar_one()
    assert refreshed_api_key.revoked_at is not None

    for key in (
        f"otp:login:{user_id}",
        f"otp:action:{user_id}",
        f"otp_failed:{user_id}",
        f"otp_issuance_blocked:{user_id}",
        f"otp_resend_login:{user_id}",
    ):
        assert await redis_client.exists(key) == 0

    audit_rows = (
        (await db_session.execute(select(AuditEvent).order_by(AuditEvent.created_at.asc())))
        .scalars()
        .all()
    )
    assert any(row.event_type == "user.erased" for row in audit_rows)
    assert all("erase-me@example.com" not in str(row.event_metadata) for row in audit_rows)

    delivery = (
        await db_session.execute(
            select(WebhookDelivery).where(WebhookDelivery.event_type == "user.erased")
        )
    ).scalar_one()
    assert delivery.payload["data"]["user_id"] == str(user_id)

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_erased_email_can_be_registered_again(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Erasing an account frees the original email for a subsequent signup."""
    app: FastAPI = app_factory()
    user = await user_factory("re-register@example.com", "Password123!")
    erased_user_id = user.id

    erasure_service = get_erasure_service()
    result = await erasure_service.erase_user(db_session=db_session, user_id=erased_user_id)

    assert result.anonymized_email == f"deleted_{erased_user_id}@erased.invalid"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        signup = await client.post(
            "/auth/signup",
            json={"email": "re-register@example.com", "password": "NewPassword123!"},
        )

    assert signup.status_code == 201
    assert signup.json() == {"accepted": True}

    db_session.expire_all()
    active_users = (
        (
            await db_session.execute(
                select(User).where(
                    User.email == "re-register@example.com",
                    User.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    erased_user = (await db_session.execute(select(User).where(User.id == erased_user_id))).scalar_one()

    assert len(active_users) == 1
    assert active_users[0].id != erased_user_id
    assert erased_user.email == f"deleted_{erased_user_id}@erased.invalid"
    assert erased_user.deleted_at is not None


@pytest.mark.asyncio
async def test_admin_erasure_requires_action_token_and_is_idempotent(
    app_factory,
    user_factory,
    db_session,
) -> None:
    """Admin erasure requires the dedicated action token and returns already_erased on repeat."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    otp_service = _build_otp_service(sender)
    app.dependency_overrides[get_otp_service] = lambda: otp_service
    app.dependency_overrides[get_admin_service] = lambda: _build_admin_service(
        otp_service=otp_service
    )

    admin = await user_factory("admin-eraser@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        admin.id,
        email_verified=True,
        email_otp_enabled=False,
        role="admin",
    )
    target = await user_factory("target-erased@example.com", "Password123!")
    await _set_user_flags(
        db_session,
        target.id,
        email_verified=True,
        email_otp_enabled=False,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_payload = await _login_with_optional_otp(
            client,
            email="admin-eraser@example.com",
            password="Password123!",
            sender=sender,
        )
        access_token = str(login_payload["access_token"])
        headers = {"authorization": f"Bearer {access_token}"}

        missing_token = await client.delete(f"/admin/users/{target.id}/erase", headers=headers)
        assert missing_token.status_code == 403
        assert missing_token.json()["code"] == "action_token_invalid"
        assert missing_token.headers["x-otp-required"] == "true"
        assert missing_token.headers["x-otp-action"] == "admin_erase_user"

        request_action = await client.post(
            "/auth/otp/request/action",
            json={"action": "admin_erase_user"},
            headers=headers,
        )
        assert request_action.status_code == 200

        verify_action = await client.post(
            "/auth/otp/verify/action",
            json={
                "action": "admin_erase_user",
                "code": sender.latest_code("action", "admin_erase_user"),
            },
            headers=headers,
        )
        assert verify_action.status_code == 200
        action_token = verify_action.json()["action_token"]

        erased = await client.delete(
            f"/admin/users/{target.id}/erase",
            headers={**headers, "x-action-token": action_token},
        )
        assert erased.status_code == 200
        assert erased.json()["erased_user_id"] == str(target.id)

        repeated = await client.delete(
            f"/admin/users/{target.id}/erase",
            headers={**headers, "x-action-token": action_token},
        )
        assert repeated.status_code == 409
        assert repeated.json()["code"] == "already_erased"

    app.dependency_overrides.clear()
