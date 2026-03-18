"""RQ job entrypoints for scheduled maintenance tasks."""

from __future__ import annotations

import asyncio

import structlog

from app.db.session import get_session_factory
from app.services.admin_service import get_admin_service

logger = structlog.get_logger(__name__)


async def run_retention_purge_async() -> None:
    """Execute one retention purge run using the shared admin retention policy."""
    session_factory = get_session_factory()
    async with session_factory() as db_session:
        result = await get_admin_service().run_retention_purge(db_session)

    logger.info(
        "retention_purge_completed",
        enabled=result.enabled,
        audit_log_retention_days=result.audit_log_retention_days,
        session_log_retention_days=result.session_log_retention_days,
        purged_audit_events=result.purged_audit_events,
        purged_sessions=result.purged_sessions,
    )


def run_retention_purge() -> None:
    """Synchronous RQ wrapper for the async retention purge job."""
    asyncio.run(run_retention_purge_async())
