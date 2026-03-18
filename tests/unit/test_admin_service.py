"""Unit tests for admin-service scaffolding helpers."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.services.admin_service import AdminService


class _UnusedDependency:
    """Placeholder dependency for constructor-only tests."""


@dataclass
class _DeleteResult:
    rowcount: int


class _RetentionDBSessionStub:
    def __init__(self, rowcounts: list[int]) -> None:
        self.rowcounts = rowcounts
        self.commit_count = 0
        self.rollback_count = 0
        self.statements: list[object] = []

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        self.statements.append(statement)
        return _DeleteResult(self.rowcounts.pop(0))

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1


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


@pytest.mark.asyncio
async def test_run_retention_purge_deletes_audit_and_session_rows() -> None:
    """Retention purge deletes aged rows and commits once when enabled."""
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
        enable_retention_purge=True,
        audit_log_retention_days=90,
        session_log_retention_days=30,
    )
    db_session = _RetentionDBSessionStub([4, 7])

    result = await service.run_retention_purge(db_session=db_session)  # type: ignore[arg-type]

    assert result.enabled is True
    assert result.purged_audit_events == 4
    assert result.purged_sessions == 7
    assert db_session.commit_count == 1
    assert db_session.rollback_count == 0
    assert len(db_session.statements) == 2
