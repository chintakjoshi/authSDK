"""Integration tests for the live session-table schema."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_sessions_refresh_hash_lookup_is_backed_by_unique_index(
    db_session: AsyncSession,
) -> None:
    """The migrated sessions table should expose a unique index on hashed_refresh_token."""
    result = await db_session.execute(text("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND tablename = 'sessions'
            """))

    indexes = {str(row.indexname): str(row.indexdef).lower() for row in result.mappings().all()}

    assert indexes
    assert any(
        "unique index" in indexdef and "hashed_refresh_token" in indexdef
        for indexdef in indexes.values()
    )
