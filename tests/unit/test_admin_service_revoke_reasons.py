"""Unit tests for admin revoke-reason propagation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.services.admin_service import AdminService


@dataclass(frozen=True)
class _ActiveUserStub:
    id: UUID
    email: str = "user@example.com"
    role: str = "user"
    is_active: bool = True
    email_verified: bool = True
    email_otp_enabled: bool = False
    created_at: datetime = datetime.now(UTC)
    updated_at: datetime = datetime.now(UTC)


class _CapturingSessionServiceStub:
    """Session service stub that records the reason used on revoke calls."""

    def __init__(self) -> None:
        self.bulk_calls: list[dict] = []
        self.single_calls: list[dict] = []

    async def revoke_user_sessions(self, **kwargs):  # type: ignore[no-untyped-def]
        self.bulk_calls.append(kwargs)
        return [uuid4(), uuid4()]

    async def revoke_one_session(self, **kwargs):  # type: ignore[no-untyped-def]
        self.single_calls.append(kwargs)
        return kwargs["session_id"]


class _UnusedDependency:
    """Placeholder dependency when a collaborator is not exercised in a test."""


def _admin_service(session_service: _CapturingSessionServiceStub) -> AdminService:
    service = AdminService(
        user_service=_UnusedDependency(),  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        otp_service=_UnusedDependency(),  # type: ignore[arg-type]
        brute_force_service=_UnusedDependency(),  # type: ignore[arg-type]
        api_key_service=_UnusedDependency(),  # type: ignore[arg-type]
        m2m_service=_UnusedDependency(),  # type: ignore[arg-type]
        webhook_service=_UnusedDependency(),  # type: ignore[arg-type]
        audit_service=_UnusedDependency(),  # type: ignore[arg-type]
        signing_key_service=_UnusedDependency(),  # type: ignore[arg-type]
        erasure_service=_UnusedDependency(),  # type: ignore[arg-type]
        enable_retention_purge=False,
        audit_log_retention_days=90,
        session_log_retention_days=30,
    )

    async def _active_user(**kwargs):  # type: ignore[no-untyped-def]
        return _ActiveUserStub(id=kwargs["user_id"])

    service._get_active_user = _active_user  # type: ignore[assignment]
    return service


@pytest.mark.asyncio
async def test_revoke_user_sessions_uses_default_reason_when_none_provided() -> None:
    """Admin bulk revoke falls back to admin_revoke_all when caller omits reason."""
    session_service = _CapturingSessionServiceStub()
    service = _admin_service(session_service)

    revoked_ids, reason = await service.revoke_user_sessions(
        db_session=object(),  # type: ignore[arg-type]
        user_id=uuid4(),
    )

    assert len(revoked_ids) == 2
    assert reason == "admin_revoke_all"
    assert session_service.bulk_calls[0]["reason"] == "admin_revoke_all"


@pytest.mark.asyncio
async def test_revoke_user_sessions_propagates_caller_reason() -> None:
    """Admin bulk revoke passes caller-supplied reason to the session service."""
    session_service = _CapturingSessionServiceStub()
    service = _admin_service(session_service)

    revoked_ids, reason = await service.revoke_user_sessions(
        db_session=object(),  # type: ignore[arg-type]
        user_id=uuid4(),
        reason="compromised_device",
    )

    assert len(revoked_ids) == 2
    assert reason == "compromised_device"
    assert session_service.bulk_calls[0]["reason"] == "compromised_device"


@pytest.mark.asyncio
async def test_revoke_user_session_uses_default_reason_when_none_provided() -> None:
    """Admin single-session revoke falls back to admin_targeted by default."""
    session_service = _CapturingSessionServiceStub()
    service = _admin_service(session_service)
    target_session_id = uuid4()

    revoked_id, reason = await service.revoke_user_session(
        db_session=object(),  # type: ignore[arg-type]
        user_id=uuid4(),
        session_id=target_session_id,
    )

    assert revoked_id == target_session_id
    assert reason == "admin_targeted"
    assert session_service.single_calls[0]["reason"] == "admin_targeted"


@pytest.mark.asyncio
async def test_revoke_user_session_propagates_caller_reason() -> None:
    """Admin single-session revoke passes caller-supplied reason through."""
    session_service = _CapturingSessionServiceStub()
    service = _admin_service(session_service)
    target_session_id = uuid4()

    revoked_id, reason = await service.revoke_user_session(
        db_session=object(),  # type: ignore[arg-type]
        user_id=uuid4(),
        session_id=target_session_id,
        reason="stolen_laptop",
    )

    assert revoked_id == target_session_id
    assert reason == "stolen_laptop"
    assert session_service.single_calls[0]["reason"] == "stolen_laptop"
