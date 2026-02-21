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

from redis import asyncio as redis_async
from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.session import Session


@dataclass(frozen=True)
class SessionPayload:
    """Serializable Redis payload for a user session."""

    user_id: str
    email: str
    scopes: list[str]
    issued_at: str


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
        scopes: list[str] | None = None,
    ) -> TokenPairLike | Awaitable[TokenPairLike]: ...


class SessionService:
    """Service for session creation, rotation, and revocation."""

    def __init__(self, redis_client: Redis, refresh_token_ttl_seconds: int) -> None:
        self._redis = redis_client
        self._refresh_token_ttl_seconds = refresh_token_ttl_seconds

    async def create_login_session(
        self,
        db_session: AsyncSession,
        user_id: UUID,
        email: str,
        scopes: list[str],
        raw_refresh_token: str,
    ) -> UUID:
        """Create a session row and cache payload in Redis."""
        session_row = Session(
            user_id=user_id,
            hashed_refresh_token=self._hash_token(raw_refresh_token),
            expires_at=datetime.now(UTC) + timedelta(seconds=self._refresh_token_ttl_seconds),
            revoked_at=None,
        )
        payload = SessionPayload(
            user_id=str(user_id),
            email=email,
            scopes=scopes,
            issued_at=datetime.now(UTC).isoformat(),
        )

        try:
            db_session.add(session_row)
            await db_session.flush()
            await self._set_session_payload(session_id=session_row.session_id, payload=payload)
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
            issued_pair = token_issuer(
                str(session_row.user_id),
                email=payload.email,
                scopes=payload.scopes,
            )
            token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
            session_row.hashed_refresh_token = self._hash_token(token_pair.refresh_token)
            session_row.expires_at = now + timedelta(seconds=self._refresh_token_ttl_seconds)
            await db_session.flush()
            await self._set_session_payload(session_id=session_row.session_id, payload=payload)
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return token_pair

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
            await self._delete_session_payload(session_id=session_row.session_id)
            remaining_ttl = self._remaining_lifetime_seconds(access_expiration_epoch)
            await self._add_to_blocklist(access_jti=access_jti, ttl_seconds=remaining_ttl)
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()

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
        return SessionPayload(**payload_dict)

    async def _set_session_payload(self, session_id: UUID, payload: SessionPayload) -> None:
        """Store session payload in Redis with configured TTL."""
        key = self._session_key(session_id)
        try:
            await self._redis.setex(
                key,
                self._refresh_token_ttl_seconds,
                json.dumps(
                    {
                        "user_id": payload.user_id,
                        "email": payload.email,
                        "scopes": payload.scopes,
                        "issued_at": payload.issued_at,
                    }
                ),
            )
        except RedisError as exc:
            raise SessionStateError("Session backend unavailable.", "session_expired", 503) from exc

    async def _delete_session_payload(self, session_id: UUID) -> None:
        """Delete Redis session key."""
        key = self._session_key(session_id)
        try:
            await self._redis.delete(key)
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

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Hash token with SHA-256 for persistent storage."""
        return sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _remaining_lifetime_seconds(expiration_epoch: int) -> int:
        """Compute remaining lifetime for blocklist TTL."""
        now_epoch = int(datetime.now(UTC).timestamp())
        return max(expiration_epoch - now_epoch, 1)


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
    )
