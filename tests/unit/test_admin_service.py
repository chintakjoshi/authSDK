"""Unit tests for admin-service scaffolding helpers."""

from __future__ import annotations

import pytest

from app.services.admin_service import AdminService


class _UnusedDependency:
    """Placeholder dependency for constructor-only tests."""


@pytest.mark.asyncio
async def test_run_retention_purge_noops_when_disabled() -> None:
    """Retention purge returns zeroed scaffolding counts when disabled."""
    service = AdminService(
        user_service=_UnusedDependency(),  # type: ignore[arg-type]
        session_service=_UnusedDependency(),  # type: ignore[arg-type]
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

    result = await service.run_retention_purge(db_session=object())  # type: ignore[arg-type]

    assert result.enabled is False
    assert result.audit_log_retention_days == 90
    assert result.session_log_retention_days == 30
    assert result.purged_audit_events == 0
    assert result.purged_sessions == 0
