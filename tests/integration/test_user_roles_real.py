"""Integration tests for user role management protections."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import select
from starlette.requests import Request

from app.models.audit_event import AuditEvent
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.user_service import UserService, UserServiceError


def _make_request() -> Request:
    """Create a minimal HTTP request object for audit-service integration."""

    async def _receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": "PATCH",
        "path": "/admin/users/u-1",
        "headers": [(b"user-agent", b"pytest-agent/1.0")],
        "client": ("127.0.0.1", 50000),
        "state": {},
    }
    request = Request(scope=scope, receive=_receive)
    request.state.correlation_id = str(uuid4())
    return request


async def _create_user(db_session, email: str, role: str) -> User:
    """Create user row with explicit role."""
    user = User(
        email=email,
        password_hash=None,
        is_active=True,
        role=role,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        deleted_at=None,
        tenant_id=None,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_last_admin_cannot_be_demoted(db_session) -> None:
    """Demoting the final admin returns last_admin_protected."""
    service = UserService()
    admin = await _create_user(db_session, "admin@example.com", "admin")

    with pytest.raises(UserServiceError) as exc_info:
        await service.update_role(
            db_session=db_session,
            actor_role="admin",
            actor_id=str(admin.id),
            user_id=admin.id,
            new_role="user",
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.code == "last_admin_protected"


@pytest.mark.asyncio
async def test_last_admin_cannot_be_deleted(db_session) -> None:
    """Deleting the final admin returns last_admin_protected."""
    service = UserService()
    admin = await _create_user(db_session, "admin@example.com", "admin")

    with pytest.raises(UserServiceError) as exc_info:
        await service.delete_user(
            db_session=db_session,
            actor_role="admin",
            user_id=admin.id,
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.code == "last_admin_protected"


@pytest.mark.asyncio
async def test_role_change_succeeds_with_multiple_admins_and_emits_audit(db_session) -> None:
    """Role updates succeed with admin actor and emit user.role_changed event."""
    service = UserService()
    audit_service = AuditService()
    actor_admin = await _create_user(db_session, "admin-a@example.com", "admin")
    target_admin = await _create_user(db_session, "admin-b@example.com", "admin")
    request = _make_request()

    updated = await service.update_role(
        db_session=db_session,
        actor_role="admin",
        actor_id=str(actor_admin.id),
        user_id=target_admin.id,
        new_role="user",
        request=request,
        audit_service=audit_service,
    )

    assert updated.role == "user"
    await db_session.refresh(target_admin)
    assert target_admin.role == "user"

    result = await db_session.execute(
        select(AuditEvent).where(
            AuditEvent.event_type == "user.role_changed",
            AuditEvent.target_id == target_admin.id,
            AuditEvent.success.is_(True),
        )
    )
    audit_event = result.scalar_one_or_none()
    assert audit_event is not None
