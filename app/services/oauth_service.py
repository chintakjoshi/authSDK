"""OAuth service orchestration for Google login flows."""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import Any

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import reloadable_singleton
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
        email_verified: bool,
        email_otp_enabled: bool,
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
            if "email_verified" in signature.parameters:
                kwargs["email_verified"] = email_verified
            if "email_otp_enabled" in signature.parameters:
                kwargs["email_otp_enabled"] = email_otp_enabled
            return issue_method(**kwargs)
        kwargs = {"user_id": user_id, "email": email, "scopes": scopes}
        if signature and "role" in signature.parameters:
            kwargs["role"] = role
        if signature and "email_verified" in signature.parameters:
            kwargs["email_verified"] = email_verified
        if signature and "email_otp_enabled" in signature.parameters:
            kwargs["email_otp_enabled"] = email_otp_enabled
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
            email_verified=email_verified,
        )
        issued_pair = self._issue_token_pair(
            db_session=db_session,
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
            scopes=[],
        )
        token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
        await self._session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
            scopes=[],
            raw_access_token=token_pair.access_token,
            raw_refresh_token=token_pair.refresh_token,
        )
        return token_pair

    async def _upsert_identity_then_resolve_user(
        self,
        db_session: AsyncSession,
        provider_user_id: str,
        email: str,
        email_verified: bool,
    ) -> User:
        """Upsert identity first, then resolve/create canonical user."""
        try:
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
                    await self._ensure_email_available_for_new_user(
                        db_session=db_session,
                        email=email,
                    )
                    user = await self._create_user(
                        db_session=db_session,
                        email=email,
                        email_verified=email_verified,
                    )
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
                deleted_or_inactive_user = await self._get_deleted_or_inactive_user_by_id(
                    db_session=db_session,
                    user_id=identity.user_id,
                )
                if deleted_or_inactive_user is not None:
                    raise self._blocked_login_error()
                await self._ensure_email_available_for_new_user(
                    db_session=db_session,
                    email=email,
                )
                user = await self._create_user(
                    db_session=db_session,
                    email=email,
                    email_verified=email_verified,
                )
                identity.user_id = user.id

            if user.email.lower() != email.lower():
                await self._ensure_email_available_for_existing_user(
                    db_session=db_session,
                    user=user,
                    email=email,
                )
                user.email = email
            if email_verified and not user.email_verified:
                user.email_verified = True
            if identity.email != email:
                identity.email = email
            await db_session.flush()
            return user
        except IntegrityError as exc:
            await db_session.rollback()
            raise self._blocked_login_error() from exc

    async def _get_user_by_email(self, db_session: AsyncSession, email: str) -> User | None:
        """Fetch active, non-deleted user by email."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, db_session: AsyncSession, user_id: Any) -> User | None:
        """Fetch active, non-deleted user by ID."""
        statement = select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_deleted_or_inactive_user_by_email(
        self,
        db_session: AsyncSession,
        email: str,
    ) -> User | None:
        """Fetch a deleted or inactive user row when the email is reserved."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            or_(User.deleted_at.is_not(None), User.is_active.is_(False)),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_deleted_or_inactive_user_by_id(
        self,
        db_session: AsyncSession,
        user_id: Any,
    ) -> User | None:
        """Fetch a deleted or inactive user row by ID when login should stay blocked."""
        statement = select(User).where(
            User.id == user_id,
            or_(User.deleted_at.is_not(None), User.is_active.is_(False)),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _ensure_email_available_for_new_user(
        self,
        db_session: AsyncSession,
        *,
        email: str,
    ) -> None:
        """Raise when the provider email belongs to a deleted or inactive account."""
        deleted_or_inactive_user = await self._get_deleted_or_inactive_user_by_email(
            db_session=db_session,
            email=email,
        )
        if deleted_or_inactive_user is not None:
            raise self._blocked_login_error()

    async def _ensure_email_available_for_existing_user(
        self,
        db_session: AsyncSession,
        *,
        user: User,
        email: str,
    ) -> None:
        """Raise when an email update would collide with another reserved account."""
        active_user = await self._get_user_by_email(db_session=db_session, email=email)
        if active_user is not None and active_user.id != user.id:
            raise self._blocked_login_error()
        deleted_or_inactive_user = await self._get_deleted_or_inactive_user_by_email(
            db_session=db_session,
            email=email,
        )
        if deleted_or_inactive_user is not None and deleted_or_inactive_user.id != user.id:
            raise self._blocked_login_error()

    async def _create_user(
        self,
        db_session: AsyncSession,
        *,
        email: str,
        email_verified: bool,
    ) -> User:
        """Create a new canonical user for a first-time federated login."""
        user = User(
            email=email,
            password_hash=None,
            is_active=True,
            role="user",
            email_verified=email_verified,
        )
        db_session.add(user)
        await db_session.flush()
        return user

    @staticmethod
    def _blocked_login_error() -> OAuthServiceError:
        """Return the stable auth failure for deleted or conflicting OAuth accounts."""
        return OAuthServiceError("Invalid credentials.", "invalid_credentials", 401)

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


@reloadable_singleton
def get_oauth_service() -> OAuthService:
    """Build and cache OAuth service dependencies."""
    return OAuthService(
        oauth_client=get_google_oauth_client(),
        redis_client=get_redis_client(),
        token_service=get_token_service(),
        session_service=get_session_service(),
    )
