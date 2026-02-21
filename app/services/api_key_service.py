"""API key lifecycle and introspection service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api_keys import APIKeyCore
from app.models.api_key import APIKey


@dataclass(frozen=True)
class CreatedAPIKey:
    """API key creation result containing raw key one-time output."""

    key_id: UUID
    api_key: str
    key_prefix: str
    service: str
    scope: str
    user_id: UUID | None
    expires_at: datetime | None
    created_at: datetime


@dataclass(frozen=True)
class APIKeyIntrospectionResult:
    """Result contract for API key introspection endpoint."""

    valid: bool
    code: str | None = None
    user_id: str | None = None
    scopes: list[str] | None = None
    key_id: str | None = None
    expires_at: str | None = None


class APIKeyServiceError(Exception):
    """Raised for API key service failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class APIKeyService:
    """Service for API key CRUD and introspection operations."""

    def __init__(self, core: APIKeyCore) -> None:
        self._core = core

    async def create_key(
        self,
        db_session: AsyncSession,
        service: str,
        scope: str,
        user_id: UUID | None,
        expires_at: datetime | None,
    ) -> CreatedAPIKey:
        """Create a scoped API key and return raw key exactly once."""
        if not scope.strip():
            raise APIKeyServiceError("Scope is required.", "invalid_api_key", 400)

        raw_key = self._core.generate_raw_key()
        key_row = APIKey(
            user_id=user_id,
            service=service.strip(),
            hashed_key=self._core.hash_key(raw_key),
            key_prefix=self._core.key_prefix(raw_key),
            scope=scope.strip(),
            expires_at=expires_at,
            revoked_at=None,
        )
        try:
            db_session.add(key_row)
            await db_session.flush()
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return CreatedAPIKey(
            key_id=key_row.id,
            api_key=raw_key,
            key_prefix=key_row.key_prefix,
            service=key_row.service,
            scope=key_row.scope,
            user_id=key_row.user_id,
            expires_at=key_row.expires_at,
            created_at=key_row.created_at,
        )

    async def list_keys(
        self,
        db_session: AsyncSession,
        user_id: UUID | None = None,
        service: str | None = None,
    ) -> list[APIKey]:
        """List non-deleted API keys with optional filters."""
        statement = (
            select(APIKey).where(APIKey.deleted_at.is_(None)).order_by(APIKey.created_at.desc())
        )
        if user_id is not None:
            statement = statement.where(APIKey.user_id == user_id)
        if service is not None:
            statement = statement.where(APIKey.service == service)
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def revoke_key(self, db_session: AsyncSession, key_id: UUID) -> APIKey:
        """Revoke API key by key ID."""
        key_row = await self._get_key_by_id(db_session=db_session, key_id=key_id, for_update=True)
        if key_row is None:
            raise APIKeyServiceError("API key not found.", "invalid_api_key", 404)

        key_row.revoked_at = datetime.now(UTC)
        try:
            await db_session.flush()
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return key_row

    async def introspect(self, db_session: AsyncSession, raw_key: str) -> APIKeyIntrospectionResult:
        """Introspect raw API key and return validity contract."""
        if not self._core.is_valid_format(raw_key):
            return APIKeyIntrospectionResult(valid=False, code="invalid_api_key")

        key_hash = self._core.hash_key(raw_key)
        key_row = await self._get_key_by_hash(
            db_session=db_session, key_hash=key_hash, for_update=False
        )
        if key_row is None:
            return APIKeyIntrospectionResult(valid=False, code="invalid_api_key")
        if not self._core.hash_matches(key_row.hashed_key, raw_key):
            return APIKeyIntrospectionResult(valid=False, code="invalid_api_key")
        if key_row.revoked_at is not None:
            return APIKeyIntrospectionResult(valid=False, code="revoked_api_key")

        now = datetime.now(UTC)
        if key_row.expires_at is not None and key_row.expires_at <= now:
            return APIKeyIntrospectionResult(valid=False, code="expired_api_key")

        scopes = self._core.scopes_from_storage(key_row.scope)
        return APIKeyIntrospectionResult(
            valid=True,
            user_id=str(key_row.user_id) if key_row.user_id else None,
            scopes=scopes,
            key_id=str(key_row.id),
            expires_at=key_row.expires_at.isoformat() if key_row.expires_at else None,
        )

    async def _get_key_by_hash(
        self,
        db_session: AsyncSession,
        key_hash: str,
        for_update: bool,
    ) -> APIKey | None:
        """Fetch API key row by hash and non-deleted status."""
        statement = select(APIKey).where(
            APIKey.hashed_key == key_hash,
            APIKey.deleted_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_key_by_id(
        self,
        db_session: AsyncSession,
        key_id: UUID,
        for_update: bool,
    ) -> APIKey | None:
        """Fetch API key row by id and non-deleted status."""
        statement = select(APIKey).where(APIKey.id == key_id, APIKey.deleted_at.is_(None))
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()


@lru_cache
def get_api_key_service() -> APIKeyService:
    """Create and cache API key service dependency."""
    return APIKeyService(core=APIKeyCore())
