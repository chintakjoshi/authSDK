"""Unit tests for lifecycle router audit-event wiring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import pytest
from fastapi import BackgroundTasks, FastAPI
from httpx import ASGITransport, AsyncClient

from app.dependencies import get_database_session
from app.routers.lifecycle import router
from app.services.audit_service import get_audit_service
from app.services.lifecycle_service import LifecycleServiceError, get_lifecycle_service
from app.services.webhook_service import get_webhook_service


@dataclass(frozen=True)
class _UserStub:
    """Minimal user payload for lifecycle success responses."""

    id: str
    email: str
    email_verified: bool


class _LifecycleServiceStub:
    """Lifecycle service stub with configurable verify/resend behavior."""

    def __init__(
        self,
        *,
        verify_error: LifecycleServiceError | None = None,
        resend_error: LifecycleServiceError | None = None,
    ) -> None:
        self.verify_error = verify_error
        self.resend_error = resend_error

    async def verify_email_token(self, db_session: Any, token: str) -> _UserStub:
        """Return a verified user or raise configured error."""
        del db_session, token
        if self.verify_error is not None:
            raise self.verify_error
        return _UserStub(id=str(uuid4()), email="user@example.com", email_verified=True)

    async def validate_access_token(self, db_session: Any, token: str) -> dict[str, object]:
        """Return deterministic access-token claims."""
        del db_session
        if token == "bad-token":
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401)
        return {"sub": "user-123"}

    async def resend_verification_email(self, db_session: Any, user_id: str) -> None:
        """Succeed or raise configured resend error."""
        del db_session, user_id
        if self.resend_error is not None:
            raise self.resend_error


class _AuditServiceStub:
    """Audit service stub recording event payloads."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    async def record(self, **kwargs: Any) -> None:
        """Capture audit call arguments excluding DB session."""
        self.events.append({key: value for key, value in kwargs.items() if key != "db"})

    def enqueue_record(self, background_tasks: BackgroundTasks, **kwargs: Any) -> None:
        background_tasks.add_task(self.record, db=None, **kwargs)


class _WebhookServiceStub:
    """Webhook service stub swallowing emitted events."""

    async def emit_event(self, *, event_type: str, data: dict[str, Any]) -> None:
        del event_type, data


async def _fake_db_dependency() -> Any:
    """Provide fake DB dependency object."""
    yield object()


@pytest.mark.asyncio
async def test_verify_email_failure_emits_failure_audit_event() -> None:
    """Verify-email failures are persisted as audit failures."""
    app = FastAPI()
    app.include_router(router)
    audit_stub = _AuditServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_lifecycle_service] = lambda: _LifecycleServiceStub(
        verify_error=LifecycleServiceError(
            "Invalid verification token.",
            "invalid_verify_token",
            400,
        )
    )
    app.dependency_overrides[get_audit_service] = lambda: audit_stub
    app.dependency_overrides[get_webhook_service] = _WebhookServiceStub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/auth/verify-email", params={"token": "x" * 24})

    assert response.status_code == 400
    assert audit_stub.events == [
        {
            "event_type": "user.email.verified",
            "actor_type": "user",
            "success": False,
            "request": audit_stub.events[0]["request"],
            "failure_reason": "invalid_verify_token",
            "metadata": {"operation": "verify"},
        }
    ]


@pytest.mark.asyncio
async def test_resend_verification_success_and_failure_emit_audit_events() -> None:
    """Resend lifecycle route emits success and failure audit records."""
    app = FastAPI()
    app.include_router(router)
    audit_stub = _AuditServiceStub()
    lifecycle_stub = _LifecycleServiceStub()
    app.dependency_overrides[get_database_session] = _fake_db_dependency
    app.dependency_overrides[get_lifecycle_service] = lambda: lifecycle_stub
    app.dependency_overrides[get_audit_service] = lambda: audit_stub
    app.dependency_overrides[get_webhook_service] = _WebhookServiceStub

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        success = await client.post(
            "/auth/verify-email/resend",
            headers={"authorization": "Bearer good-token"},
        )
        assert success.status_code == 200

    lifecycle_stub = _LifecycleServiceStub(
        resend_error=LifecycleServiceError("Email is already verified.", "already_verified", 400)
    )
    app.dependency_overrides[get_lifecycle_service] = lambda: lifecycle_stub
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        failure = await client.post(
            "/auth/verify-email/resend",
            headers={"authorization": "Bearer good-token"},
        )
        assert failure.status_code == 400

    event_types_and_success = [
        (event["event_type"], event["success"], event.get("failure_reason"))
        for event in audit_stub.events
    ]
    assert (
        "user.email.verification_resent",
        True,
        None,
    ) in event_types_and_success
    assert (
        "user.email.verification_resent",
        False,
        "already_verified",
    ) in event_types_and_success
