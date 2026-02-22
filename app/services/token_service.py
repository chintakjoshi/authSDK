"""Token issuance service."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.jwt import JWTService, get_jwt_service
from app.core.signing_keys import SigningKeyService, get_signing_key_service


@dataclass(frozen=True)
class TokenPair:
    """Returned access and refresh JWT pair."""

    access_token: str
    refresh_token: str


class TokenService:
    """Service responsible for creating access and refresh tokens."""

    def __init__(
        self,
        jwt_service: JWTService,
        signing_key_service: SigningKeyService,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        self._jwt_service = jwt_service
        self._signing_key_service = signing_key_service
        self._access_token_ttl_seconds = access_token_ttl_seconds
        self._refresh_token_ttl_seconds = refresh_token_ttl_seconds

    async def issue_token_pair(
        self,
        db_session: AsyncSession,
        user_id: str,
        email: str | None = None,
        role: str = "user",
        scopes: list[str] | None = None,
    ) -> TokenPair:
        """Issue access and refresh tokens for a user identity."""
        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        access_claims: dict[str, object] = {"role": role}
        if email is not None:
            access_claims["email"] = email
        if scopes is not None:
            access_claims["scopes"] = scopes
        access_token = self._jwt_service.issue_token(
            subject=user_id,
            token_type="access",
            expires_in_seconds=self._access_token_ttl_seconds,
            additional_claims=access_claims,
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        refresh_token = self._jwt_service.issue_token(
            subject=user_id,
            token_type="refresh",
            expires_in_seconds=self._refresh_token_ttl_seconds,
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        return TokenPair(access_token=access_token, refresh_token=refresh_token)


@lru_cache
def get_token_service() -> TokenService:
    """Build and cache token service based on application settings."""
    settings = get_settings()
    return TokenService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        access_token_ttl_seconds=settings.jwt.access_token_ttl_seconds,
        refresh_token_ttl_seconds=settings.jwt.refresh_token_ttl_seconds,
    )
