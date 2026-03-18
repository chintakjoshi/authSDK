"""Integration tests for admin API routes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt

from app.config import get_settings
from app.core.jwt import get_jwt_service
from app.core.sessions import get_redis_client, get_session_service
from app.core.signing_keys import get_signing_key_service
from app.db.session import get_session_factory
from app.models.user import User
from app.models.webhook_delivery import WebhookDelivery, WebhookDeliveryStatus
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
    """In-memory OTP sender for integration assertions."""

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
        """Return the most recent OTP code matching the requested message kind."""
        for message in reversed(self.messages):
            if message.kind == kind and message.action == action:
                return message.code
        raise AssertionError(f"No captured OTP message for kind={kind!r} action={action!r}")


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
    """Sender stub for webhook admin tests."""

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
        secret_encryption_key="admin-webhook-secret",
        encryption_fallback_seed="admin-webhook-seed",
    )


def _build_admin_service(
    *,
    otp_service: OTPService | None = None,
    webhook_service: WebhookService | None = None,
) -> AdminService:
    """Build admin service with optional overridden collaborators."""
    return AdminService(
        user_service=UserService(),
        session_service=get_session_service(),
        otp_service=otp_service or get_otp_service(),
        brute_force_service=get_brute_force_service(),
        api_key_service=get_api_key_service(),
        m2m_service=get_m2m_service(),
        webhook_service=webhook_service or get_webhook_service(),
        audit_service=get_audit_service(),
        signing_key_service=get_signing_key_service(),
        erasure_service=get_erasure_service(),
        enable_retention_purge=False,
        audit_log_retention_days=90,
        session_log_retention_days=30,
    )


async def _create_user(
    db_session,
    *,
    email: str,
    password: str,
    role: str = "user",
    email_verified: bool = False,
    email_otp_enabled: bool = False,
) -> User:
    """Create a user with explicit role and OTP flags."""
    user_service = UserService()
    user = User(
        email=email,
        password_hash=user_service.hash_password(password),
        is_active=True,
        role=role,
        email_verified=email_verified,
        email_otp_enabled=email_otp_enabled,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def _login_password(client: AsyncClient, *, email: str, password: str) -> dict[str, Any]:
    """Perform a password login and return the JSON payload."""
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()


async def _login_with_optional_otp(
    client: AsyncClient,
    *,
    email: str,
    password: str,
    sender: _CapturingOTPEmailSender | None = None,
) -> str:
    """Login and complete OTP if the account requires it."""
    payload = await _login_password(client, email=email, password=password)
    if payload.get("otp_required"):
        assert sender is not None
        verify = await client.post(
            "/auth/otp/verify/login",
            json={
                "challenge_token": payload["challenge_token"],
                "code": sender.latest_code("login"),
            },
        )
        assert verify.status_code == 200
        payload = verify.json()
    return str(payload["access_token"])


async def _make_stale_access_token(db_session, raw_access_token: str) -> str:
    """Re-sign an access token with a stale auth_time for reauth-gate tests."""
    current_claims = get_jwt_service().verify_token(raw_access_token, expected_type="access")
    active_key = await get_signing_key_service().get_active_signing_key(db_session)
    await db_session.rollback()
    stale_time = datetime.now(UTC) - timedelta(minutes=10)
    return jwt.encode(
        {
            **current_claims,
            "iat": int(stale_time.timestamp()),
            "auth_time": int(stale_time.timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        active_key.private_key_pem,
        algorithm="RS256",
        headers={"kid": active_key.kid},
    )


@pytest.mark.asyncio
async def test_admin_routes_require_admin_role(app_factory, db_session) -> None:
    """Non-admin access tokens receive insufficient_role on admin routes."""
    app: FastAPI = app_factory()
    await _create_user(db_session, email="member@example.com", password="Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="member@example.com",
            password="Password123!",
        )
        response = await client.get(
            "/admin/users",
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 403
    assert response.json()["code"] == "insufficient_role"


@pytest.mark.asyncio
async def test_admin_routes_accept_local_dev_bootstrap_key(
    app_factory,
    db_session,
    monkeypatch,
) -> None:
    """Development-only bootstrap key grants admin route access without a JWT."""
    monkeypatch.setenv("ADMIN_API_KEY", "dev-bootstrap-key")
    get_settings.cache_clear()
    get_admin_service.cache_clear()
    app: FastAPI = app_factory()
    await _create_user(db_session, email="listed@example.com", password="Password123!")

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            response = await client.get(
                "/admin/users",
                headers={"x-admin-api-key": "dev-bootstrap-key"},
            )
    finally:
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)
        get_settings.cache_clear()
        get_admin_service.cache_clear()

    assert response.status_code == 200
    assert response.json()["data"][0]["email"] == "listed@example.com"


@pytest.mark.asyncio
async def test_admin_users_list_supports_cursor_pagination(app_factory, db_session) -> None:
    """Admin user listing uses the documented cursor page shape."""
    app: FastAPI = app_factory()
    await _create_user(
        db_session,
        email="admin@example.com",
        password="Password123!",
        role="admin",
    )
    first_user = await _create_user(db_session, email="one@example.com", password="Password123!")
    second_user = await _create_user(db_session, email="two@example.com", password="Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="admin@example.com",
            password="Password123!",
        )
        headers = {"authorization": f"Bearer {access_token}"}

        first_page = await client.get("/admin/users?limit=1", headers=headers)
        assert first_page.status_code == 200
        first_payload = first_page.json()
        assert len(first_payload["data"]) == 1
        assert first_payload["has_more"] is True
        assert first_payload["next_cursor"] is not None
        assert first_payload["data"][0]["id"] == str(second_user.id)

        second_page = await client.get(
            f"/admin/users?limit=1&cursor={first_payload['next_cursor']}",
            headers=headers,
        )
        assert second_page.status_code == 200
        second_payload = second_page.json()
        assert len(second_payload["data"]) == 1
        assert second_payload["data"][0]["id"] == str(first_user.id)
        assert second_payload["has_more"] is True


@pytest.mark.asyncio
async def test_admin_sensitive_role_change_requires_otp_for_otp_enabled_admin(
    app_factory,
    db_session,
) -> None:
    """OTP-enabled admins are directed to the OTP gate on sensitive admin routes."""
    app: FastAPI = app_factory()
    sender = _CapturingOTPEmailSender()
    otp_service = _build_otp_service(sender)
    app.dependency_overrides[get_otp_service] = lambda: otp_service
    app.dependency_overrides[get_admin_service] = lambda: _build_admin_service(
        otp_service=otp_service
    )

    await _create_user(
        db_session,
        email="otp-admin@example.com",
        password="Password123!",
        role="admin",
        email_verified=True,
        email_otp_enabled=True,
    )
    target = await _create_user(db_session, email="target@example.com", password="Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="otp-admin@example.com",
            password="Password123!",
            sender=sender,
        )
        response = await client.patch(
            f"/admin/users/{target.id}",
            json={"role": "admin"},
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 403
    assert response.json()["code"] == "otp_required"
    assert response.headers["x-otp-required"] == "true"
    assert response.headers["x-otp-action"] == "role_change"
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_admin_sensitive_role_change_requires_reauth_for_stale_auth(
    app_factory,
    db_session,
) -> None:
    """Non-OTP admins fall back to password reauth on stale sensitive actions."""
    app: FastAPI = app_factory()
    await _create_user(
        db_session,
        email="reauth-admin@example.com",
        password="Password123!",
        role="admin",
        email_verified=True,
        email_otp_enabled=False,
    )
    target = await _create_user(db_session, email="member-two@example.com", password="Password123!")
    target_id = target.id

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        fresh_access_token = await _login_with_optional_otp(
            client,
            email="reauth-admin@example.com",
            password="Password123!",
        )
        stale_access_token = await _make_stale_access_token(db_session, fresh_access_token)
        response = await client.patch(
            f"/admin/users/{target_id}",
            json={"role": "admin"},
            headers={"authorization": f"Bearer {stale_access_token}"},
        )

    assert response.status_code == 403
    assert response.json()["code"] == "reauth_required"
    assert response.headers["x-reauth-required"] == "true"


@pytest.mark.asyncio
async def test_admin_last_admin_protection_and_otp_toggle(app_factory, db_session) -> None:
    """Admin routes protect the final admin and support admin OTP toggles."""
    app: FastAPI = app_factory()
    admin = await _create_user(
        db_session,
        email="solo-admin@example.com",
        password="Password123!",
        role="admin",
        email_verified=True,
    )
    otp_user = await _create_user(
        db_session,
        email="otp-user@example.com",
        password="Password123!",
        email_verified=True,
        email_otp_enabled=True,
    )
    unverified = await _create_user(
        db_session,
        email="unverified@example.com",
        password="Password123!",
        email_verified=False,
        email_otp_enabled=False,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="solo-admin@example.com",
            password="Password123!",
        )
        headers = {"authorization": f"Bearer {access_token}"}

        last_admin_delete = await client.delete(f"/admin/users/{admin.id}", headers=headers)
        assert last_admin_delete.status_code == 409
        assert last_admin_delete.json()["code"] == "last_admin_protected"

        disable_otp = await client.patch(
            f"/admin/users/{otp_user.id}/otp",
            json={"email_otp_enabled": False},
            headers=headers,
        )
        assert disable_otp.status_code == 200
        assert disable_otp.json() == {"email_otp_enabled": False}

        enable_unverified = await client.patch(
            f"/admin/users/{unverified.id}/otp",
            json={"email_otp_enabled": True},
            headers=headers,
        )
        assert enable_unverified.status_code == 400
        assert enable_unverified.json()["code"] == "email_not_verified"


@pytest.mark.asyncio
async def test_admin_api_key_routes_and_audit_log(app_factory, db_session) -> None:
    """Admin API-key CRUD works and the audit log exposes matching entries."""
    app: FastAPI = app_factory()
    await _create_user(
        db_session,
        email="keys-admin@example.com",
        password="Password123!",
        role="admin",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="keys-admin@example.com",
            password="Password123!",
        )
        headers = {"authorization": f"Bearer {access_token}"}

        created = await client.post(
            "/admin/api-keys",
            json={"name": "Admin Managed Key", "scope": "orders:read"},
            headers=headers,
        )
        assert created.status_code == 200
        created_payload = created.json()
        assert created_payload["api_key"].startswith("sk_")

        listed = await client.get("/admin/api-keys?limit=10", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"][0]["key_id"] == created_payload["key_id"]

        revoked = await client.delete(
            f"/admin/api-keys/{created_payload['key_id']}",
            headers=headers,
        )
        assert revoked.status_code == 200
        assert revoked.json()["key_id"] == created_payload["key_id"]

        audit_log = await client.get("/admin/audit-log?event_type=api_key.", headers=headers)
        assert audit_log.status_code == 200
        event_types = {item["event_type"] for item in audit_log.json()["data"]}
        assert "api_key.created" in event_types
        assert "api_key.revoked" in event_types


@pytest.mark.asyncio
async def test_admin_client_routes_cover_crud_flow(app_factory, db_session) -> None:
    """Admin client routes support create, list, update, rotate-secret, and delete."""
    app: FastAPI = app_factory()
    await _create_user(
        db_session,
        email="clients-admin@example.com",
        password="Password123!",
        role="admin",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="clients-admin@example.com",
            password="Password123!",
        )
        headers = {"authorization": f"Bearer {access_token}"}

        created = await client.post(
            "/admin/clients",
            json={"name": "Billing Worker", "scopes": ["billing:read"], "token_ttl_seconds": 1800},
            headers=headers,
        )
        assert created.status_code == 200
        created_payload = created.json()
        assert created_payload["client_secret"].startswith("cs_")

        listed = await client.get("/admin/clients?limit=10", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"][0]["id"] == created_payload["id"]

        updated = await client.patch(
            f"/admin/clients/{created_payload['id']}",
            json={"name": "Billing Worker Updated", "scopes": ["billing:read", "billing:write"]},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["name"] == "Billing Worker Updated"

        rotated = await client.post(
            f"/admin/clients/{created_payload['id']}/rotate-secret",
            headers=headers,
        )
        assert rotated.status_code == 200
        assert rotated.json()["client_secret"].startswith("cs_")

        deleted = await client.delete(
            f"/admin/clients/{created_payload['id']}",
            headers=headers,
        )
        assert deleted.status_code == 200
        assert deleted.json()["is_active"] is False


@pytest.mark.asyncio
async def test_admin_webhook_routes_cover_listing_retry_and_delete(app_factory, db_session) -> None:
    """Admin webhook routes expose deliveries, retry, and soft-delete semantics."""
    webhook_service = _build_webhook_service()
    app: FastAPI = app_factory()
    app.dependency_overrides[get_webhook_service] = lambda: webhook_service
    app.dependency_overrides[get_admin_service] = lambda: _build_admin_service(
        webhook_service=webhook_service
    )

    await _create_user(
        db_session,
        email="hooks-admin@example.com",
        password="Password123!",
        role="admin",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="hooks-admin@example.com",
            password="Password123!",
        )
        headers = {"authorization": f"Bearer {access_token}"}

        created = await client.post(
            "/admin/webhooks",
            json={
                "name": "Admin Hook",
                "url": "https://example.com/admin",
                "secret": "top-secret-hook",
                "events": ["session.created"],
            },
            headers=headers,
        )
        assert created.status_code == 200
        endpoint_id = UUID(created.json()["id"])

        delivery = WebhookDelivery(
            endpoint_id=endpoint_id,
            event_type="session.created",
            payload={"id": "delivery-1", "event": "session.created", "data": {}},
            status=WebhookDeliveryStatus.PENDING.value,
            attempt_count=1,
        )
        db_session.add(delivery)
        await db_session.commit()
        await db_session.refresh(delivery)

        listed = await client.get("/admin/webhooks?limit=10", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["data"][0]["id"] == str(endpoint_id)

        deliveries = await client.get(
            f"/admin/webhooks/{endpoint_id}/deliveries",
            headers=headers,
        )
        assert deliveries.status_code == 200
        assert deliveries.json()["data"][0]["id"] == str(delivery.id)

        retried = await client.post(
            f"/admin/webhooks/deliveries/{delivery.id}/retry",
            headers=headers,
        )
        assert retried.status_code == 200
        assert retried.json()["delivery_id"] == str(delivery.id)

        deleted = await client.delete(f"/admin/webhooks/{endpoint_id}", headers=headers)
        assert deleted.status_code == 200
        assert deleted.json()["endpoint_id"] == str(endpoint_id)
        assert deleted.json()["abandoned_delivery_count"] == 1

    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_admin_can_rotate_signing_key_with_fresh_auth(app_factory, db_session) -> None:
    """Freshly authenticated admins can rotate signing keys without OTP."""
    app: FastAPI = app_factory()
    await _create_user(
        db_session,
        email="rotate-admin@example.com",
        password="Password123!",
        role="admin",
        email_verified=True,
        email_otp_enabled=False,
    )
    current_active = await get_signing_key_service().get_active_signing_key(db_session)
    await db_session.rollback()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        access_token = await _login_with_optional_otp(
            client,
            email="rotate-admin@example.com",
            password="Password123!",
        )
        response = await client.post(
            "/admin/signing-keys/rotate",
            headers={"authorization": f"Bearer {access_token}"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["new_kid"] != current_active.kid
    assert payload["retiring_kid"] == current_active.kid
