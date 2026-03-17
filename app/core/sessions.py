"""Redis-backed session state management."""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from jose import jwt
from jose.exceptions import JWTError
from redis import asyncio as redis_async
from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.session import Session
from app.models.user import User


@dataclass(frozen=True)
class SessionPayload:
    """Serializable Redis payload for a user session."""

    user_id: str
    email: str
    role: str
    email_verified: bool
    email_otp_enabled: bool
    scopes: list[str]
    issued_at: str
    auth_time: str


class SessionStateError(Exception):
    """Raised when session lifecycle operations fail."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class TokenPairLike(Protocol):
    """Protocol for token pair objects used during refresh rotation."""

    access_token: str
    refresh_token: str


class TokenIssuer(Protocol):
    """Protocol for token issuer callbacks used during refresh rotation."""

    def __call__(
        self,
        user_id: str,
        email: str | None = None,
        role: str | None = None,
        email_verified: bool | None = None,
        email_otp_enabled: bool | None = None,
        scopes: list[str] | None = None,
        auth_time: datetime | None = None,
    ) -> TokenPairLike | Awaitable[TokenPairLike]: ...


class SessionService:
    """Service for session creation, rotation, and revocation."""

    def __init__(
        self,
        redis_client: Redis,
        refresh_token_ttl_seconds: int,
        access_token_ttl_seconds: int,
    ) -> None:
        self._redis = redis_client
        self._refresh_token_ttl_seconds = refresh_token_ttl_seconds
        self._access_token_ttl_seconds = access_token_ttl_seconds

    async def create_login_session(
        self,
        db_session: AsyncSession,
        user_id: UUID,
        email: str,
        role: str,
        email_verified: bool,
        email_otp_enabled: bool,
        scopes: list[str],
        raw_access_token: str,
        raw_refresh_token: str,
    ) -> UUID:
        """Create a session row and cache payload in Redis."""
        now = datetime.now(UTC)
        access_claims = self._extract_access_claims(raw_access_token)
        auth_time = self._extract_auth_time(access_claims, fallback=now)
        access_jti = self._extract_access_jti(access_claims)
        session_row = Session(
            user_id=user_id,
            hashed_refresh_token=self._hash_token(raw_refresh_token),
            auth_time=auth_time,
            expires_at=datetime.now(UTC) + timedelta(seconds=self._refresh_token_ttl_seconds),
            revoked_at=None,
        )
        payload = SessionPayload(
            user_id=str(user_id),
            email=email,
            role=role,
            email_verified=email_verified,
            email_otp_enabled=email_otp_enabled,
            scopes=scopes,
            issued_at=now.isoformat(),
            auth_time=auth_time.isoformat(),
        )

        try:
            db_session.add(session_row)
            await db_session.flush()
            await self._set_session_payload(session_id=session_row.session_id, payload=payload)
            await self._set_access_token_binding(
                access_jti=access_jti,
                session_id=session_row.session_id,
            )
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return session_row.session_id

    async def rotate_refresh_session(
        self,
        db_session: AsyncSession,
        raw_refresh_token: str,
        token_issuer: TokenIssuer,
    ) -> TokenPairLike:
        """Rotate refresh token and return a new access/refresh pair."""
        incoming_hash = self._hash_token(raw_refresh_token)
        try:
            session_row = await self._fetch_session_by_refresh_hash(
                db_session=db_session,
                refresh_token_hash=incoming_hash,
                for_update=True,
            )
            if session_row is None:
                raise SessionStateError("Session expired.", "session_expired", 401)

            now = datetime.now(UTC)
            if session_row.revoked_at is not None or session_row.expires_at <= now:
                raise SessionStateError("Session expired.", "session_expired", 401)

            payload = await self._get_session_payload(session_id=session_row.session_id)
            user = await self._get_active_user(db_session=db_session, user_id=session_row.user_id)
            if user is None:
                raise SessionStateError("Session expired.", "session_expired", 401)

            payload = SessionPayload(
                user_id=str(user.id),
                email=user.email,
                role=user.role,
                email_verified=user.email_verified,
                email_otp_enabled=user.email_otp_enabled,
                scopes=payload.scopes,
                issued_at=payload.issued_at,
                auth_time=session_row.auth_time.isoformat(),
            )
            issued_pair = self._invoke_token_issuer(
                token_issuer=token_issuer,
                user_id=str(session_row.user_id),
                email=payload.email,
                role=payload.role,
                email_verified=payload.email_verified,
                email_otp_enabled=payload.email_otp_enabled,
                scopes=payload.scopes,
                auth_time=session_row.auth_time,
            )
            token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
            access_jti = self._extract_access_jti(
                self._extract_access_claims(token_pair.access_token)
            )
            session_row.hashed_refresh_token = self._hash_token(token_pair.refresh_token)
            session_row.expires_at = now + timedelta(seconds=self._refresh_token_ttl_seconds)
            await db_session.flush()
            await self._set_session_payload(session_id=session_row.session_id, payload=payload)
            await self._set_access_token_binding(
                access_jti=access_jti,
                session_id=session_row.session_id,
            )
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return token_pair

    async def reauthenticate_session(
        self,
        db_session: AsyncSession,
        *,
        current_access_jti: str,
        new_access_token: str,
        auth_time: datetime,
    ) -> UUID:
        """Update session auth_time and bind a fresh access token to the session."""
        try:
            session_id = await self._get_session_id_for_access_jti(current_access_jti)
            session_row = await self._fetch_session_by_session_id(
                db_session=db_session,
                session_id=session_id,
                for_update=True,
            )
            now = datetime.now(UTC)
            if (
                session_row is None
                or session_row.revoked_at is not None
                or session_row.expires_at <= now
            ):
                raise SessionStateError("Session expired.", "session_expired", 401)

            payload = await self._get_session_payload(session_id=session_row.session_id)
            session_row.auth_time = auth_time
            payload = SessionPayload(
                user_id=payload.user_id,
                email=payload.email,
                role=payload.role,
                email_verified=payload.email_verified,
                email_otp_enabled=payload.email_otp_enabled,
                scopes=payload.scopes,
                issued_at=payload.issued_at,
                auth_time=auth_time.isoformat(),
            )
            await db_session.flush()
            await self._set_session_payload(
                session_id=session_row.session_id,
                payload=payload,
                ttl_seconds=self._remaining_session_ttl(session_row.expires_at),
            )
            await self._set_access_token_binding(
                access_jti=self._extract_access_jti(self._extract_access_claims(new_access_token)),
                session_id=session_row.session_id,
            )
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return session_row.session_id

    async def revoke_user_sessions(
        self,
        db_session: AsyncSession,
        user_id: UUID,
        *,
        commit: bool = True,
    ) -> list[UUID]:
        """Revoke all non-deleted, non-revoked sessions for one user."""
        try:
            session_rows = await self._fetch_active_sessions_for_user(
                db_session=db_session,
                user_id=user_id,
            )
            revoked_at = datetime.now(UTC)
            session_ids: list[UUID] = []
            for session_row in session_rows:
                session_row.revoked_at = revoked_at
                session_ids.append(session_row.session_id)

            await db_session.flush()
            await self._delete_session_payloads(*session_ids)
        except Exception:
            await db_session.rollback()
            raise

        if commit:
            await db_session.commit()
        return session_ids

    async def validate_access_token_session(
        self,
        db_session: AsyncSession,
        *,
        access_jti: str,
    ) -> UUID:
        """Ensure an access token still belongs to an active, non-revoked session."""
        session_id = await self._get_session_id_for_access_jti(access_jti)
        session_row = await self._fetch_session_by_session_id(
            db_session=db_session,
            session_id=session_id,
            for_update=False,
        )
        now = datetime.now(UTC)
        if (
            session_row is None
            or session_row.revoked_at is not None
            or session_row.expires_at <= now
        ):
            raise SessionStateError("Session expired.", "session_expired", 401)

        await self._get_session_payload(session_id=session_id)
        return session_row.session_id

    async def revoke_session(
        self,
        db_session: AsyncSession,
        raw_refresh_token: str,
        access_jti: str,
        access_expiration_epoch: int,
    ) -> None:
        """Revoke a session and blocklist the access token JTI."""
        refresh_token_hash = self._hash_token(raw_refresh_token)
        try:
            session_row = await self._fetch_session_by_refresh_hash(
                db_session=db_session,
                refresh_token_hash=refresh_token_hash,
                for_update=True,
            )
            if session_row is None:
                raise SessionStateError("Invalid token.", "invalid_token", 401)

            session_row.revoked_at = datetime.now(UTC)
            await db_session.flush()
            await self._delete_session_payloads(session_row.session_id)
            remaining_ttl = self._remaining_lifetime_seconds(access_expiration_epoch)
            await self._add_to_blocklist(access_jti=access_jti, ttl_seconds=remaining_ttl)
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()

    async def _fetch_active_sessions_for_user(
        self,
        db_session: AsyncSession,
        user_id: UUID,
    ) -> list[Session]:
        """Fetch all revocable sessions for the provided user ID."""
        statement = (
            select(Session)
            .where(
                Session.user_id == user_id,
                Session.deleted_at.is_(None),
                Session.revoked_at.is_(None),
            )
            .with_for_update()
        )
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def _fetch_session_by_refresh_hash(
        self,
        db_session: AsyncSession,
        refresh_token_hash: str,
        for_update: bool,
    ) -> Session | None:
        """Fetch non-deleted session by hashed refresh token."""
        statement = select(Session).where(
            Session.hashed_refresh_token == refresh_token_hash,
            Session.deleted_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _fetch_session_by_session_id(
        self,
        db_session: AsyncSession,
        session_id: UUID,
        *,
        for_update: bool,
    ) -> Session | None:
        """Fetch non-deleted session by stable session ID."""
        statement = select(Session).where(
            Session.session_id == session_id,
            Session.deleted_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_active_user(self, db_session: AsyncSession, user_id: UUID) -> User | None:
        """Fetch the current active user record for refresh-time claim issuance."""
        statement = select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _get_session_payload(self, session_id: UUID) -> SessionPayload:
        """Fetch cached session payload from Redis and fail closed if missing."""
        key = self._session_key(session_id)
        try:
            raw_payload = await self._redis.get(key)
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc
        if raw_payload is None:
            raise SessionStateError("Session expired.", "session_expired", 401)
        try:
            payload_dict = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise SessionStateError("Session expired.", "session_expired", 401) from exc
        payload_dict.setdefault("role", "user")
        payload_dict.setdefault("email_verified", False)
        payload_dict.setdefault("email_otp_enabled", False)
        payload_dict.setdefault(
            "auth_time", payload_dict.get("issued_at", datetime.now(UTC).isoformat())
        )
        return SessionPayload(**payload_dict)

    async def _set_session_payload(
        self,
        session_id: UUID,
        payload: SessionPayload,
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store session payload in Redis with configured TTL."""
        key = self._session_key(session_id)
        try:
            await self._redis.setex(
                key,
                ttl_seconds or self._refresh_token_ttl_seconds,
                json.dumps(
                    {
                        "user_id": payload.user_id,
                        "email": payload.email,
                        "role": payload.role,
                        "email_verified": payload.email_verified,
                        "email_otp_enabled": payload.email_otp_enabled,
                        "scopes": payload.scopes,
                        "issued_at": payload.issued_at,
                        "auth_time": payload.auth_time,
                    }
                ),
            )
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc

    async def _delete_session_payloads(self, *session_ids: UUID) -> None:
        """Delete one or more Redis session keys in one backend call."""
        keys = [self._session_key(session_id) for session_id in session_ids]
        if not keys:
            return
        try:
            await self._redis.delete(*keys)
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc

    async def _add_to_blocklist(self, access_jti: str, ttl_seconds: int) -> None:
        """Add access token JTI to Redis blocklist."""
        key = f"blocklist:jti:{access_jti}"
        try:
            await self._redis.setex(key, ttl_seconds, "1")
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc

    def _session_key(self, session_id: UUID) -> str:
        """Build Redis key for session payload."""
        return f"session:{session_id}"

    async def _set_access_token_binding(self, access_jti: str, session_id: UUID) -> None:
        """Bind one access-token JTI to a stable session ID for re-authentication lookups."""
        try:
            await self._redis.setex(
                self._access_token_binding_key(access_jti),
                self._access_token_ttl_seconds,
                str(session_id),
            )
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc

    async def _get_session_id_for_access_jti(self, access_jti: str) -> UUID:
        """Resolve the stable session ID for an access token JTI."""
        try:
            raw_session_id = await self._redis.get(self._access_token_binding_key(access_jti))
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc
        if raw_session_id is None:
            raise SessionStateError("Session expired.", "session_expired", 401)
        try:
            return UUID(str(raw_session_id))
        except ValueError as exc:
            raise SessionStateError("Session expired.", "session_expired", 401) from exc

    @staticmethod
    def _invoke_token_issuer(
        token_issuer: TokenIssuer,
        user_id: str,
        email: str,
        role: str,
        email_verified: bool,
        email_otp_enabled: bool,
        scopes: list[str],
        auth_time: datetime,
    ) -> TokenPairLike | Awaitable[TokenPairLike]:
        """Call token issuer while supporting legacy callbacks."""
        try:
            signature = inspect.signature(token_issuer)
        except (TypeError, ValueError):
            signature = None
        kwargs: dict[str, object] = {"email": email, "role": role, "scopes": scopes}
        if signature and "email_verified" in signature.parameters:
            kwargs["email_verified"] = email_verified
        if signature and "email_otp_enabled" in signature.parameters:
            kwargs["email_otp_enabled"] = email_otp_enabled
        if signature and "auth_time" in signature.parameters:
            kwargs["auth_time"] = auth_time
        return token_issuer(user_id, **kwargs)

    @staticmethod
    def _extract_access_claims(raw_access_token: str) -> dict[str, object]:
        """Read issued access-token claims without re-verifying the signature."""
        try:
            claims = jwt.get_unverified_claims(raw_access_token)
        except JWTError as exc:
            raise SessionStateError("Invalid token.", "invalid_token", 401) from exc
        if str(claims.get("type", "")) != "access":
            raise SessionStateError("Invalid token.", "invalid_token", 401)
        return claims

    @staticmethod
    def _extract_access_jti(access_claims: dict[str, object]) -> str:
        """Extract access-token JTI from issued claims."""
        access_jti = str(access_claims.get("jti", "")).strip()
        if not access_jti:
            raise SessionStateError("Invalid token.", "invalid_token", 401)
        return access_jti

    @staticmethod
    def _extract_auth_time(access_claims: dict[str, object], *, fallback: datetime) -> datetime:
        """Extract auth_time from issued access-token claims."""
        raw_auth_time = access_claims.get("auth_time")
        if isinstance(raw_auth_time, int):
            return datetime.fromtimestamp(raw_auth_time, UTC)
        return fallback

    @staticmethod
    def _access_token_binding_key(access_jti: str) -> str:
        return f"session_access:{access_jti}"

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Hash token with SHA-256 for persistent storage."""
        return sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _remaining_lifetime_seconds(expiration_epoch: int) -> int:
        """Compute remaining lifetime for blocklist TTL."""
        now_epoch = int(datetime.now(UTC).timestamp())
        return max(expiration_epoch - now_epoch, 1)

    @staticmethod
    def _remaining_session_ttl(expires_at: datetime) -> int:
        """Compute remaining refresh-session TTL in seconds."""
        now = datetime.now(UTC)
        return max(int((expires_at - now).total_seconds()), 1)


@lru_cache
def get_redis_client() -> Redis:
    """Create and cache Redis client for async session operations."""
    settings = get_settings()
    return redis_async.from_url(settings.redis.url, decode_responses=True)


@lru_cache
def get_session_service() -> SessionService:
    """Create and cache session service."""
    settings = get_settings()
    return SessionService(
        redis_client=get_redis_client(),
        refresh_token_ttl_seconds=settings.jwt.refresh_token_ttl_seconds,
        access_token_ttl_seconds=settings.jwt.access_token_ttl_seconds,
    )
