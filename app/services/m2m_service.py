"""OAuth2 client-credentials service for M2M access tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import JWTService, get_jwt_service
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.models.oauth_client import OAuthClient
from app.services.pagination import CursorPage, apply_created_at_cursor, build_page, decode_cursor


@dataclass(frozen=True)
class ClientCredentialsTokenResult:
    """Issued client-credentials token payload."""

    access_token: str
    expires_in: int
    scope: str
    client_id: str


@dataclass(frozen=True)
class ManagedOAuthClient:
    """Management-safe OAuth client payload without raw secret material."""

    id: UUID
    client_id: str
    client_secret_prefix: str
    name: str
    scopes: list[str]
    is_active: bool
    token_ttl_seconds: int
    created_at: datetime


@dataclass(frozen=True)
class CreatedOAuthClient(ManagedOAuthClient):
    """Created client payload including one-time raw secret."""

    client_secret: str


@dataclass(frozen=True)
class RotatedOAuthClientSecret:
    """Client secret rotation result returned exactly once."""

    id: UUID
    client_id: str
    client_secret: str
    client_secret_prefix: str


class M2MServiceError(Exception):
    """Raised for client-credentials grant validation failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class M2MService:
    """Validate OAuth clients and issue M2M JWT access tokens."""

    def __init__(
        self,
        jwt_service: JWTService,
        signing_key_service: SigningKeyService,
    ) -> None:
        self._jwt_service = jwt_service
        self._signing_key_service = signing_key_service

    async def authenticate_client_credentials(
        self,
        db_session: AsyncSession,
        *,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
    ) -> ClientCredentialsTokenResult:
        """Validate client credentials and issue an M2M access token."""
        normalized_client_id = client_id.strip()
        normalized_secret = client_secret.strip()
        if not normalized_client_id or not normalized_secret:
            raise M2MServiceError("Invalid client credentials.", "invalid_credentials", 401)

        client = await self._get_client_by_client_id(
            db_session=db_session,
            client_id=normalized_client_id,
        )
        if client is None or not client.is_active:
            raise M2MServiceError("Invalid client credentials.", "invalid_credentials", 401)

        if not self.verify_client_secret(
            raw_secret=normalized_secret,
            stored_hash=client.client_secret_hash,
        ):
            raise M2MServiceError("Invalid client credentials.", "invalid_credentials", 401)

        requested_scopes = self._normalize_requested_scopes(scope)
        allowed_scopes = {item for item in client.scopes if item}
        if requested_scopes and not set(requested_scopes).issubset(allowed_scopes):
            raise M2MServiceError("Invalid scope.", "invalid_scope", 400)

        resolved_scopes = requested_scopes or list(client.scopes)
        scope_claim = " ".join(resolved_scopes)
        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        access_token = self._jwt_service.issue_token(
            subject=client.client_id,
            token_type="m2m",
            expires_in_seconds=client.token_ttl_seconds,
            additional_claims={
                "role": client.role,
                "scope": scope_claim,
            },
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        return ClientCredentialsTokenResult(
            access_token=access_token,
            expires_in=client.token_ttl_seconds,
            scope=scope_claim,
            client_id=client.client_id,
        )

    async def create_client(
        self,
        db_session: AsyncSession,
        *,
        name: str,
        scopes: list[str],
        token_ttl_seconds: int = 3600,
    ) -> CreatedOAuthClient:
        """Create an OAuth client and return its raw secret exactly once."""
        normalized_name = name.strip()
        normalized_scopes = self._normalize_client_scopes(scopes)
        if not normalized_name:
            raise M2MServiceError("Client name is required.", "invalid_credentials", 400)
        if not normalized_scopes:
            raise M2MServiceError("At least one scope is required.", "invalid_scope", 400)
        if token_ttl_seconds < 1:
            raise M2MServiceError("Invalid token TTL.", "invalid_credentials", 400)

        client_id = await self._generate_unique_client_id(db_session)
        raw_secret = self.generate_client_secret()
        row = OAuthClient(
            client_id=client_id,
            client_secret_hash=self.hash_client_secret(raw_secret),
            client_secret_prefix=self.client_secret_prefix(raw_secret),
            name=normalized_name,
            scopes=normalized_scopes,
            role="service",
            is_active=True,
            token_ttl_seconds=token_ttl_seconds,
        )
        db_session.add(row)
        await db_session.flush()
        await db_session.commit()
        return CreatedOAuthClient(
            id=row.id,
            client_id=row.client_id,
            client_secret=raw_secret,
            client_secret_prefix=row.client_secret_prefix,
            name=row.name,
            scopes=list(row.scopes),
            is_active=row.is_active,
            token_ttl_seconds=row.token_ttl_seconds,
            created_at=row.created_at,
        )

    async def list_clients(
        self,
        db_session: AsyncSession,
        *,
        active: bool | None = None,
    ) -> list[OAuthClient]:
        """List non-deleted OAuth clients with optional active filter."""
        statement = self._build_client_list_statement(active=active)
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def list_clients_page(
        self,
        db_session: AsyncSession,
        *,
        cursor: str | None = None,
        limit: int = 50,
        active: bool | None = None,
    ) -> CursorPage[OAuthClient]:
        """Return one cursor-paginated page of OAuth clients."""
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = self._build_client_list_statement(active=active)
        statement = apply_created_at_cursor(
            statement,
            model=OAuthClient,
            cursor=cursor_position,
        ).limit(limit + 1)
        result = await db_session.execute(statement)
        return build_page(list(result.scalars().all()), limit=limit)

    async def update_client(
        self,
        db_session: AsyncSession,
        *,
        client_row_id: UUID,
        name: str | None = None,
        scopes: list[str] | None = None,
        token_ttl_seconds: int | None = None,
        is_active: bool | None = None,
    ) -> OAuthClient:
        """Update mutable OAuth client fields."""
        client = await self._get_client_by_id(
            db_session=db_session,
            client_row_id=client_row_id,
            for_update=True,
        )
        if client is None:
            raise M2MServiceError("Client not found.", "invalid_credentials", 404)
        if name is not None:
            normalized_name = name.strip()
            if not normalized_name:
                raise M2MServiceError("Client name is required.", "invalid_credentials", 400)
            client.name = normalized_name
        if scopes is not None:
            normalized_scopes = self._normalize_client_scopes(scopes)
            if not normalized_scopes:
                raise M2MServiceError("At least one scope is required.", "invalid_scope", 400)
            client.scopes = normalized_scopes
        if token_ttl_seconds is not None:
            if token_ttl_seconds < 1:
                raise M2MServiceError("Invalid token TTL.", "invalid_credentials", 400)
            client.token_ttl_seconds = token_ttl_seconds
        if is_active is not None:
            client.is_active = is_active
        await db_session.flush()
        await db_session.commit()
        return client

    async def rotate_client_secret(
        self,
        db_session: AsyncSession,
        *,
        client_row_id: UUID,
    ) -> RotatedOAuthClientSecret:
        """Rotate client secret and invalidate the previous one immediately."""
        client = await self._get_client_by_id(
            db_session=db_session,
            client_row_id=client_row_id,
            for_update=True,
        )
        if client is None:
            raise M2MServiceError("Client not found.", "invalid_credentials", 404)

        raw_secret = self.generate_client_secret()
        client.client_secret_hash = self.hash_client_secret(raw_secret)
        client.client_secret_prefix = self.client_secret_prefix(raw_secret)
        await db_session.flush()
        await db_session.commit()
        return RotatedOAuthClientSecret(
            id=client.id,
            client_id=client.client_id,
            client_secret=raw_secret,
            client_secret_prefix=client.client_secret_prefix,
        )

    async def delete_client(
        self,
        db_session: AsyncSession,
        *,
        client_row_id: UUID,
    ) -> OAuthClient:
        """Soft-delete an OAuth client."""
        client = await self._get_client_by_id(
            db_session=db_session,
            client_row_id=client_row_id,
            for_update=True,
        )
        if client is None:
            raise M2MServiceError("Client not found.", "invalid_credentials", 404)
        client.deleted_at = datetime.now(UTC)
        client.is_active = False
        await db_session.flush()
        await db_session.commit()
        return client

    async def _get_client_by_client_id(
        self,
        db_session: AsyncSession,
        *,
        client_id: str,
    ) -> OAuthClient | None:
        """Fetch one active, non-deleted OAuth client by client_id."""
        statement = select(OAuthClient).where(
            OAuthClient.client_id == client_id,
            OAuthClient.deleted_at.is_(None),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_client_by_id(
        self,
        db_session: AsyncSession,
        *,
        client_row_id: UUID,
        for_update: bool,
    ) -> OAuthClient | None:
        """Fetch one non-deleted OAuth client by primary key."""
        statement = select(OAuthClient).where(
            OAuthClient.id == client_row_id,
            OAuthClient.deleted_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _generate_unique_client_id(self, db_session: AsyncSession) -> str:
        """Generate a unique random client identifier."""
        for _ in range(10):
            candidate = f"client_{secrets.token_urlsafe(16)}"
            existing = await self._get_client_by_client_id(
                db_session=db_session, client_id=candidate
            )
            if existing is None:
                return candidate
        raise RuntimeError("Unable to generate unique client ID.")

    @staticmethod
    def generate_client_secret() -> str:
        """Generate one raw client secret in the documented format."""
        return f"cs_{secrets.token_urlsafe(32)}"

    @staticmethod
    def hash_client_secret(raw_secret: str) -> str:
        """Hash one client secret for database persistence."""
        return hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

    @classmethod
    def verify_client_secret(cls, *, raw_secret: str, stored_hash: str) -> bool:
        """Validate a raw client secret against its stored SHA-256 hash."""
        return hmac.compare_digest(cls.hash_client_secret(raw_secret), stored_hash)

    @staticmethod
    def client_secret_prefix(raw_secret: str) -> str:
        """Return the first eight characters for display-only metadata."""
        return raw_secret[:8]

    @staticmethod
    def _normalize_requested_scopes(scope: str | None) -> list[str]:
        """Normalize optional OAuth scope string into an ordered list."""
        if scope is None:
            return []
        return [item for item in scope.strip().split(" ") if item]

    @staticmethod
    def _normalize_client_scopes(scopes: list[str]) -> list[str]:
        """Normalize and deduplicate stored client scopes while preserving order."""
        normalized: list[str] = []
        seen: set[str] = set()
        for scope in scopes:
            item = scope.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            normalized.append(item)
        return normalized

    @staticmethod
    def _build_client_list_statement(*, active: bool | None):
        """Build the base OAuth client listing query."""
        statement = (
            select(OAuthClient)
            .where(OAuthClient.deleted_at.is_(None))
            .order_by(OAuthClient.created_at.desc(), OAuthClient.id.desc())
        )
        if active is not None:
            statement = statement.where(OAuthClient.is_active.is_(active))
        return statement


@lru_cache
def get_m2m_service() -> M2MService:
    """Create and cache M2M client-credentials service dependency."""
    return M2MService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
    )
