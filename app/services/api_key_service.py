"""API key lifecycle and introspection service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api_keys import APIKeyCore
from app.models.api_key import APIKey
from app.models.user import User
from app.services.pagination import CursorPage, apply_created_at_cursor, build_page, decode_cursor


@dataclass(frozen=True)
class CreatedAPIKey:
    """API key creation result containing raw key one-time output."""

    key_id: UUID
    api_key: str
    key_prefix: str
    name: str
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
    service: str | None = None


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
        name: str | None,
        service: str | None,
        scope: str,
        user_id: UUID | None,
        expires_at: datetime | None,
    ) -> CreatedAPIKey:
        """Create a scoped API key and return raw key exactly once."""
        normalized_scope = scope.strip()
        if not normalized_scope:
            raise APIKeyServiceError("Scope is required.", "invalid_api_key", 400)
        resolved_name, resolved_service = self._resolve_name_and_service(
            name=name,
            service=service,
            scope=normalized_scope,
        )

        raw_key = self._core.generate_raw_key()
        key_row = APIKey(
            user_id=user_id,
            name=resolved_name,
            service=resolved_service,
            hashed_key=self._core.hash_key(raw_key),
            key_prefix=self._core.key_prefix(raw_key),
            scope=normalized_scope,
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
            name=key_row.name,
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
        name: str | None = None,
        service: str | None = None,
        scope: str | None = None,
        active: bool | None = None,
    ) -> list[APIKey]:
        """List non-deleted API keys with optional filters."""
        statement = self._build_list_statement(
            user_id=user_id,
            name=name,
            service=service,
            scope=scope,
            active=active,
        )
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def list_keys_page(
        self,
        db_session: AsyncSession,
        *,
        cursor: str | None = None,
        limit: int = 50,
        user_id: UUID | None = None,
        name: str | None = None,
        service: str | None = None,
        scope: str | None = None,
        active: bool | None = None,
    ) -> CursorPage[APIKey]:
        """Return one cursor-paginated page of API keys."""
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = self._build_list_statement(
            user_id=user_id,
            name=name,
            service=service,
            scope=scope,
            active=active,
        )
        statement = apply_created_at_cursor(statement, model=APIKey, cursor=cursor_position).limit(
            limit + 1
        )
        result = await db_session.execute(statement)
        return build_page(list(result.scalars().all()), limit=limit)

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

    async def revoke_user_keys(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        commit: bool = True,
    ) -> list[APIKey]:
        """Revoke all non-deleted, not-yet-revoked API keys for one user."""
        key_rows = await self._get_revocable_keys_for_user(
            db_session=db_session,
            user_id=user_id,
        )
        revoked_at = datetime.now(UTC)
        for key_row in key_rows:
            key_row.revoked_at = revoked_at

        try:
            await db_session.flush()
        except Exception:
            await db_session.rollback()
            raise
        if commit:
            await db_session.commit()
        return key_rows

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
        if key_row.user_id is not None:
            owner = await self._get_active_key_owner(
                db_session=db_session,
                user_id=key_row.user_id,
            )
            if owner is None:
                return APIKeyIntrospectionResult(valid=False, code="revoked_api_key")

        scopes = self._core.scopes_from_storage(key_row.scope)
        return APIKeyIntrospectionResult(
            valid=True,
            user_id=str(key_row.user_id) if key_row.user_id else None,
            scopes=scopes,
            key_id=str(key_row.id),
            expires_at=key_row.expires_at.isoformat() if key_row.expires_at else None,
            service=key_row.service,
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

    async def _get_revocable_keys_for_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> list[APIKey]:
        """Fetch all user-bound API keys that still need revocation."""
        statement = (
            select(APIKey)
            .where(
                APIKey.user_id == user_id,
                APIKey.deleted_at.is_(None),
                APIKey.revoked_at.is_(None),
            )
            .with_for_update()
        )
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def _get_active_key_owner(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> User | None:
        """Fetch the active, non-deleted owner for one user-bound API key."""
        statement = select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    @staticmethod
    def _resolve_name_and_service(
        *,
        name: str | None,
        service: str | None,
        scope: str,
    ) -> tuple[str, str]:
        """Resolve backward-compatible API-key display name and service identity."""
        resolved_name = (name or service or "").strip()
        if not resolved_name:
            raise APIKeyServiceError("Name is required.", "invalid_api_key", 400)

        resolved_service = (service or "").strip()
        if not resolved_service:
            resolved_service = APIKeyService._service_from_scope(scope) or resolved_name
        return resolved_name, resolved_service

    @staticmethod
    def _service_from_scope(scope: str) -> str | None:
        """Infer service identity from the first scope prefix when available."""
        first_scope = scope.split(",", 1)[0].strip()
        if not first_scope:
            return None
        prefix, _, _ = first_scope.partition(":")
        normalized = prefix.strip()
        return normalized or None

    @staticmethod
    def _build_list_statement(
        *,
        user_id: UUID | None,
        name: str | None,
        service: str | None,
        scope: str | None,
        active: bool | None,
    ):
        """Build the base filtered API-key listing query."""
        statement = (
            select(APIKey)
            .where(APIKey.deleted_at.is_(None))
            .order_by(APIKey.created_at.desc(), APIKey.id.desc())
        )
        if user_id is not None:
            statement = statement.where(APIKey.user_id == user_id)
        if name is not None:
            statement = statement.where(APIKey.name == name)
        if service is not None:
            statement = statement.where(APIKey.service == service)
        if scope is not None:
            statement = statement.where(APIKey.scope == scope)
        if active is True:
            now = datetime.now(UTC)
            statement = statement.where(
                APIKey.revoked_at.is_(None),
                or_(APIKey.expires_at.is_(None), APIKey.expires_at > now),
            )
        elif active is False:
            now = datetime.now(UTC)
            statement = statement.where(
                or_(
                    APIKey.revoked_at.is_not(None),
                    (APIKey.expires_at.is_not(None) & (APIKey.expires_at <= now)),
                )
            )
        return statement


@lru_cache
def get_api_key_service() -> APIKeyService:
    """Create and cache API key service dependency."""
    return APIKeyService(core=APIKeyCore())
