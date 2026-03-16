"""OAuth2 client-credentials service for M2M access tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import JWTService, get_jwt_service
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.models.oauth_client import OAuthClient


@dataclass(frozen=True)
class ClientCredentialsTokenResult:
    """Issued client-credentials token payload."""

    access_token: str
    expires_in: int
    scope: str
    client_id: str


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


@lru_cache
def get_m2m_service() -> M2MService:
    """Create and cache M2M client-credentials service dependency."""
    return M2MService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
    )
