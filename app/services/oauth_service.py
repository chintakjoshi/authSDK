"""OAuth service orchestration for Google login flows."""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.oauth import GoogleOAuthClient, OAuthProtocolError, get_google_oauth_client
from app.core.sessions import SessionService, get_redis_client, get_session_service
from app.models.user import User, UserIdentity
from app.services.token_service import TokenPair, TokenService, get_token_service


@dataclass(frozen=True)
class OAuthStateRecord:
    """Serialized OAuth state payload stored in Redis."""

    nonce: str
    code_verifier: str
    redirect_uri: str


class OAuthServiceError(Exception):
    """Raised when OAuth flow orchestration fails."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class OAuthService:
    """Coordinates OAuth state, callback exchange, and identity upsert."""

    def __init__(
        self,
        oauth_client: GoogleOAuthClient,
        redis_client: Redis,
        token_service: TokenService,
        session_service: SessionService,
    ) -> None:
        self._oauth_client = oauth_client
        self._redis = redis_client
        self._token_service = token_service
        self._session_service = session_service
        self._state_ttl_seconds = 600

    def _issue_token_pair(
        self,
        db_session: AsyncSession,
        user_id: str,
        email: str,
        role: str,
        scopes: list[str],
    ):
        """Issue token pair while tolerating legacy test doubles."""
        issue_method = self._token_service.issue_token_pair
        try:
            signature = inspect.signature(issue_method)
        except (TypeError, ValueError):
            signature = None
        if signature and "db_session" in signature.parameters:
            kwargs: dict[str, object] = {
                "db_session": db_session,
                "user_id": user_id,
                "email": email,
                "scopes": scopes,
            }
            if "role" in signature.parameters:
                kwargs["role"] = role
            return issue_method(**kwargs)
        kwargs = {"user_id": user_id, "email": email, "scopes": scopes}
        if signature and "role" in signature.parameters:
            kwargs["role"] = role
        return issue_method(**kwargs)

    async def build_google_login_url(self, redirect_uri: str | None) -> str:
        """Create Google login URL and persist one-time state in Redis."""
        try:
            resolved_redirect_uri = self._oauth_client.resolve_redirect_uri(redirect_uri)
            state = self._oauth_client.generate_state()
            nonce = self._oauth_client.generate_nonce()
            code_verifier = self._oauth_client.generate_code_verifier()
        except OAuthProtocolError as exc:
            raise OAuthServiceError(exc.detail, exc.code, exc.status_code) from exc
        state_record = OAuthStateRecord(
            nonce=nonce,
            code_verifier=code_verifier,
            redirect_uri=resolved_redirect_uri,
        )
        await self._store_state(state=state, record=state_record)
        try:
            return await self._oauth_client.create_google_authorization_url(
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
                redirect_uri=resolved_redirect_uri,
            )
        except OAuthProtocolError as exc:
            raise OAuthServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def complete_google_callback(
        self,
        db_session: AsyncSession,
        state: str,
        code: str,
    ) -> TokenPair:
        """Complete OAuth callback and return access/refresh token pair."""
        state_record = await self._consume_state(state=state)
        try:
            resolved_redirect_uri = self._oauth_client.resolve_redirect_uri(
                state_record.redirect_uri
            )
            token_payload = await self._oauth_client.exchange_code_for_tokens(
                code=code,
                code_verifier=state_record.code_verifier,
                redirect_uri=resolved_redirect_uri,
            )
        except OAuthProtocolError as exc:
            raise OAuthServiceError(exc.detail, exc.code, exc.status_code) from exc

        id_token = str(token_payload.get("id_token", ""))
        if not id_token:
            raise OAuthServiceError("Invalid credentials.", "invalid_credentials", 401)
        try:
            claims = await self._oauth_client.verify_id_token(
                id_token=id_token, nonce=state_record.nonce
            )
        except OAuthProtocolError as exc:
            raise OAuthServiceError(exc.detail, exc.code, exc.status_code) from exc
        email = str(claims.get("email", "")).strip()
        email_verified = bool(claims.get("email_verified"))
        provider_user_id = str(claims.get("sub", "")).strip()
        if not email or not provider_user_id or not email_verified:
            raise OAuthServiceError("Invalid credentials.", "invalid_credentials", 401)

        user = await self._upsert_identity_then_resolve_user(
            db_session=db_session,
            provider_user_id=provider_user_id,
            email=email,
        )
        issued_pair = self._issue_token_pair(
            db_session=db_session,
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            scopes=[],
        )
        token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
        await self._session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=user.role,
            scopes=[],
            raw_refresh_token=token_pair.refresh_token,
        )
        return token_pair

    async def _upsert_identity_then_resolve_user(
        self,
        db_session: AsyncSession,
        provider_user_id: str,
        email: str,
    ) -> User:
        """Upsert identity first, then resolve/create canonical user."""
        identity_stmt = select(UserIdentity).where(
            UserIdentity.provider == "google",
            UserIdentity.provider_user_id == provider_user_id,
            UserIdentity.deleted_at.is_(None),
        )
        identity_result = await db_session.execute(identity_stmt)
        identity = identity_result.scalar_one_or_none()

        if identity is None:
            user = await self._get_user_by_email(db_session=db_session, email=email)
            if user is None:
                user = User(email=email, password_hash=None, is_active=True, role="user")
                db_session.add(user)
                await db_session.flush()
            identity = UserIdentity(
                user_id=user.id,
                provider="google",
                provider_user_id=provider_user_id,
                email=email,
            )
            db_session.add(identity)
            await db_session.flush()
            return user

        user = await self._get_user_by_id(db_session=db_session, user_id=identity.user_id)
        if user is None:
            user = User(email=email, password_hash=None, is_active=True, role="user")
            db_session.add(user)
            await db_session.flush()
            identity.user_id = user.id

        if user.email.lower() != email.lower():
            user.email = email
        if identity.email != email:
            identity.email = email
        await db_session.flush()
        return user

    async def _get_user_by_email(self, db_session: AsyncSession, email: str) -> User | None:
        """Fetch non-deleted user by email."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            User.deleted_at.is_(None),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, db_session: AsyncSession, user_id: Any) -> User | None:
        """Fetch non-deleted user by ID."""
        statement = select(User).where(User.id == user_id, User.deleted_at.is_(None))
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _store_state(self, state: str, record: OAuthStateRecord) -> None:
        """Persist one-time OAuth state in Redis."""
        key = self._state_key(state)
        try:
            await self._redis.setex(
                key,
                self._state_ttl_seconds,
                json.dumps(
                    {
                        "nonce": record.nonce,
                        "code_verifier": record.code_verifier,
                        "redirect_uri": record.redirect_uri,
                    }
                ),
            )
        except RedisError as exc:
            raise OAuthServiceError("OAuth state mismatch.", "oauth_state_mismatch", 503) from exc

    async def _consume_state(self, state: str) -> OAuthStateRecord:
        """Load and delete OAuth state payload (one-time use)."""
        key = self._state_key(state)
        try:
            if hasattr(self._redis, "getdel"):
                raw_payload = await self._redis.getdel(key)
            else:
                raw_payload = await self._redis.get(key)
                if raw_payload is not None:
                    await self._redis.delete(key)
        except RedisError as exc:
            raise OAuthServiceError("OAuth state mismatch.", "oauth_state_mismatch", 503) from exc

        if raw_payload is None:
            raise OAuthServiceError("OAuth state mismatch.", "oauth_state_mismatch", 401)
        try:
            payload_dict = json.loads(raw_payload)
            return OAuthStateRecord(**payload_dict)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OAuthServiceError("OAuth state mismatch.", "oauth_state_mismatch", 401) from exc

    @staticmethod
    def _state_key(state: str) -> str:
        """Build Redis key for OAuth state payload."""
        return f"oauth_state:{state}"


@lru_cache
def get_oauth_service() -> OAuthService:
    """Build and cache OAuth service dependencies."""
    return OAuthService(
        oauth_client=get_google_oauth_client(),
        redis_client=get_redis_client(),
        token_service=get_token_service(),
        session_service=get_session_service(),
    )
