"""Integration tests validating the MFA core schema migration."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_users_expose_mfa_and_phone_columns(db_session: AsyncSession) -> None:
    """The migrated users table must expose the MFA and phone columns."""
    result = await db_session.execute(text("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'users'
            """))
    columns = {row.column_name for row in result.mappings().all()}

    expected = {
        "phone_ciphertext",
        "phone_last4",
        "phone_lookup_hash",
        "phone_verified",
        "phone_verified_at",
        "mfa_enabled",
        "mfa_primary_method",
    }
    assert expected.issubset(columns)
    legacy_column_name = "email_otp" + "_enabled"
    assert legacy_column_name not in columns


@pytest.mark.asyncio
async def test_user_recovery_codes_table_exists_with_unique_user_code_hash(
    db_session: AsyncSession,
) -> None:
    """user_recovery_codes must exist with a uniqueness constraint on (user_id, code_hash)."""
    table_result = await db_session.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'user_recovery_codes'
            """))
    assert table_result.mappings().first() is not None

    column_result = await db_session.execute(text("""
            SELECT column_name, is_nullable
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'user_recovery_codes'
            """))
    columns = {row.column_name: row.is_nullable for row in column_result.mappings().all()}
    assert {"id", "user_id", "code_hash", "used_at"}.issubset(columns.keys())
    assert columns["used_at"] == "YES"
    assert columns["user_id"] == "NO"
    assert columns["code_hash"] == "NO"

    unique_result = await db_session.execute(text("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND tablename = 'user_recovery_codes'
            """))
    indexes = {row.indexname: str(row.indexdef).lower() for row in unique_result.mappings().all()}
    assert any(
        "unique" in indexdef and "user_id" in indexdef and "code_hash" in indexdef
        for indexdef in indexes.values()
    )


@pytest.mark.asyncio
async def test_users_phone_lookup_hash_has_partial_unique_index(
    db_session: AsyncSession,
) -> None:
    """phone_lookup_hash must have a partial unique index scoped to live rows."""
    result = await db_session.execute(text("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND tablename = 'users'
            """))
    indexes = {row.indexname: str(row.indexdef).lower() for row in result.mappings().all()}
    matching = [
        indexdef
        for indexdef in indexes.values()
        if "phone_lookup_hash" in indexdef and "unique" in indexdef
    ]
    assert matching, "expected a unique index covering phone_lookup_hash"
    assert any(
        "where" in indexdef and "deleted_at is null" in indexdef for indexdef in matching
    ), "phone_lookup_hash unique index must be partial on deleted_at IS NULL"
