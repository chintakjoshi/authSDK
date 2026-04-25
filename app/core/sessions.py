"""Redis-backed session state management."""

from __future__ import annotations

import hmac
import inspect
import json
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from redis import asyncio as redis_async
from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings, reloadable_singleton
from app.core.callable_compat import add_supported_kwarg, get_callable_parameter_names
from app.core.jwt import decode_unverified_jwt_claims, normalize_audiences
from app.models.session import Session
from app.models.user import User
from app.services.pagination import (
    CursorPage,
    apply_created_at_cursor,
    build_page,
    decode_cursor,
)

_REFRESH_TOKEN_HASH_CONTEXT = b"auth-service:refresh-token-hash:v1"

_LAST_SEEN_THROTTLE_SECONDS = 60
_IP_ADDRESS_MAX_LENGTH = 45
_USER_AGENT_MAX_LENGTH = 512


@dataclass(frozen=True)
class UserSessionSummary:
    """User-scoped session row for self-service listing."""

    id: UUID
    session_id: UUID
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None
    ip_address: str | None
    user_agent: str | None
    is_suspicious: bool
    suspicious_reasons: list[str]
    is_current: bool


@dataclass(frozen=True)
class SessionPayload:
    """Serializable Redis payload for a user session."""

    user_id: str
    email: str
    role: str
    email_verified: bool
    mfa_enabled: bool
    scopes: list[str]
    audiences: list[str]
    issued_at: str
    auth_time: str


class SessionStateError(Exception):
    """Raised when session lifecycle operations fail."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class RefreshTokenHasher:
    """Keyed refresh-token hash helper with legacy SHA-256 compatibility."""

    key: bytes

    @classmethod
    def from_secret(cls, secret: str) -> RefreshTokenHasher:
        """Derive a stable HMAC key from configured secret material."""
        if not secret.strip():
            raise ValueError("refresh token hash secret must be non-empty.")
        derived_key = hmac.digest(
            secret.encode("utf-8"),
            _REFRESH_TOKEN_HASH_CONTEXT,
            "sha256",
        )
        return cls(key=derived_key)

    @classmethod
    def from_settings(cls, settings: Settings) -> RefreshTokenHasher:
        """Build hasher from explicit settings or safe local-development fallback."""
        configured_secret = settings.session_security.refresh_token_hash_key
        if configured_secret is not None:
            return cls.from_secret(configured_secret.get_secret_value())
        return cls.from_secret(settings.jwt.private_key_pem.get_secret_value())

    def hash_token(self, raw_token: str) -> str:
        """Hash one refresh token using keyed HMAC-SHA256."""
        return hmac.new(self.key, raw_token.encode("utf-8"), sha256).hexdigest()

    @staticmethod
    def legacy_hash_token(raw_token: str) -> str:
        """Return the legacy plain SHA-256 verifier for rollout compatibility."""
        return sha256(raw_token.encode("utf-8")).hexdigest()


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
        mfa_enabled: bool | None = None,
        scopes: list[str] | None = None,
        audiences: list[str] | None = None,
        auth_time: datetime | None = None,
    ) -> TokenPairLike | Awaitable[TokenPairLike]: ...


class SessionService:
    """Service for session creation, rotation, and revocation."""

    def __init__(
        self,
        redis_client: Redis,
        refresh_token_ttl_seconds: int,
        access_token_ttl_seconds: int,
        refresh_token_hasher: RefreshTokenHasher,
    ) -> None:
        self._redis = redis_client
        self._refresh_token_ttl_seconds = refresh_token_ttl_seconds
        self._access_token_ttl_seconds = access_token_ttl_seconds
        self._refresh_token_hasher = refresh_token_hasher

    async def create_login_session(
        self,
        db_session: AsyncSession,
        user_id: UUID,
        email: str,
        role: str,
        email_verified: bool,
        mfa_enabled: bool,
        scopes: list[str],
        raw_access_token: str,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
        is_suspicious: bool = False,
        suspicious_reasons: list[str] | None = None,
    ) -> UUID:
        """Create a session row and cache payload in Redis."""
        now = datetime.now(UTC)
        access_claims = self._extract_access_claims(raw_access_token)
        auth_time = self._extract_auth_time(access_claims, fallback=now)
        access_jti = self._extract_access_jti(access_claims)
        audiences = normalize_audiences(access_claims.get("aud"))
        normalized_suspicious_reasons = _normalize_string_list(suspicious_reasons)
        session_row = Session(
            user_id=user_id,
            hashed_refresh_token=self._hash_token(raw_refresh_token),
            auth_time=auth_time,
            expires_at=datetime.now(UTC) + timedelta(seconds=self._refresh_token_ttl_seconds),
            revoked_at=None,
            ip_address=_truncate(ip_address, _IP_ADDRESS_MAX_LENGTH),
            user_agent=_truncate(user_agent, _USER_AGENT_MAX_LENGTH),
            last_seen_at=now,
            is_suspicious=bool(is_suspicious),
            suspicious_reasons=normalized_suspicious_reasons,
        )
        payload = SessionPayload(
            user_id=str(user_id),
            email=email,
            role=role,
            email_verified=email_verified,
            mfa_enabled=mfa_enabled,
            scopes=scopes,
            audiences=audiences,
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
        try:
            session_row = await self._find_session_for_refresh_token(
                db_session=db_session,
                raw_refresh_token=raw_refresh_token,
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
                mfa_enabled=user.mfa_enabled,
                scopes=payload.scopes,
                audiences=payload.audiences,
                issued_at=payload.issued_at,
                auth_time=session_row.auth_time.isoformat(),
            )
            issued_pair = self._invoke_token_issuer(
                token_issuer=token_issuer,
                user_id=str(session_row.user_id),
                email=payload.email,
                role=payload.role,
                email_verified=payload.email_verified,
                mfa_enabled=payload.mfa_enabled,
                scopes=payload.scopes,
                audiences=payload.audiences,
                auth_time=session_row.auth_time,
            )
            token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
            access_jti = self._extract_access_jti(
                self._extract_access_claims(token_pair.access_token)
            )
            session_row.hashed_refresh_token = self._hash_token(token_pair.refresh_token)
            session_row.expires_at = now + timedelta(seconds=self._refresh_token_ttl_seconds)
            session_row.last_seen_at = now
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
                mfa_enabled=payload.mfa_enabled,
                scopes=payload.scopes,
                audiences=payload.audiences,
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
        reason: str | None = None,
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
                if reason is not None:
                    session_row.revoke_reason = reason
                session_ids.append(session_row.session_id)

            await db_session.flush()
            await self._delete_session_payloads(*session_ids)
        except Exception:
            await db_session.rollback()
            raise

        if commit:
            await db_session.commit()
        return session_ids

    async def revoke_one_session(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        session_id: UUID,
        reason: str,
    ) -> UUID:
        """Revoke a single session owned by the given user."""
        try:
            session_row = await self._fetch_session_by_session_id(
                db_session=db_session,
                session_id=session_id,
                for_update=True,
            )
            if session_row is None or session_row.user_id != user_id:
                raise SessionStateError("Session not found.", "invalid_session", 404)
            if session_row.revoked_at is not None:
                raise SessionStateError("Session already revoked.", "session_revoked", 409)

            session_row.revoked_at = datetime.now(UTC)
            session_row.revoke_reason = reason
            await db_session.flush()
            await self._delete_session_payloads(session_row.session_id)
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return session_row.session_id

    async def resolve_session_id_for_access_jti(self, access_jti: str) -> UUID | None:
        """Return a bound session id or None when the access-token binding is absent."""
        try:
            return await self._get_session_id_for_access_jti(access_jti)
        except SessionStateError as exc:
            if exc.code == "session_expired" and exc.status_code == 401:
                return None
            raise

    async def list_sessions_for_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        status: str = "active",
        cursor: str | None = None,
        limit: int = 50,
        current_session_id: UUID | None = None,
    ) -> CursorPage[UserSessionSummary]:
        """Return a cursor-paginated list of sessions for one user."""
        if status not in {"active", "revoked", "all"}:
            raise SessionStateError("Invalid status filter.", "invalid_status", 400)
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = (
            select(Session)
            .where(Session.user_id == user_id, Session.deleted_at.is_(None))
            .order_by(Session.created_at.desc(), Session.session_id.desc())
        )
        now = datetime.now(UTC)
        if status == "active":
            statement = statement.where(
                Session.revoked_at.is_(None),
                Session.expires_at > now,
            )
        elif status == "revoked":
            statement = statement.where(
                or_(Session.revoked_at.is_not(None), Session.expires_at <= now)
            )
        statement = apply_created_at_cursor(
            statement,
            model=Session,
            cursor=cursor_position,
        ).limit(limit + 1)
        rows = list((await db_session.execute(statement)).scalars().all())
        summaries = [
            UserSessionSummary(
                id=row.id,
                session_id=row.session_id,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                revoke_reason=row.revoke_reason,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                is_suspicious=bool(getattr(row, "is_suspicious", False)),
                suspicious_reasons=_normalize_string_list(getattr(row, "suspicious_reasons", None)),
                is_current=(
                    current_session_id is not None and row.session_id == current_session_id
                ),
            )
            for row in rows
        ]
        return build_page(summaries, limit=limit)

    async def revoke_user_sessions_except(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        except_session_id: UUID | None,
        reason: str,
    ) -> list[UUID]:
        """Revoke all sessions for a user except the provided session id."""
        try:
            session_rows = await self._fetch_active_sessions_for_user(
                db_session=db_session,
                user_id=user_id,
            )
            revoked_at = datetime.now(UTC)
            session_ids: list[UUID] = []
            for session_row in session_rows:
                if except_session_id is not None and session_row.session_id == except_session_id:
                    continue
                session_row.revoked_at = revoked_at
                session_row.revoke_reason = reason
                session_ids.append(session_row.session_id)
            await db_session.flush()
            await self._delete_session_payloads(*session_ids)
        except Exception:
            await db_session.rollback()
            raise
        await db_session.commit()
        return session_ids

    async def match_user_sessions_for_revoke_filter(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        is_suspicious: bool | None = None,
        created_before: datetime | None = None,
        created_after: datetime | None = None,
        last_seen_before: datetime | None = None,
        last_seen_after: datetime | None = None,
        ip_address: str | None = None,
        user_agent_contains: str | None = None,
    ) -> list[UUID]:
        """Return active session ids matching the provided revoke filters."""
        session_rows = await self._fetch_active_sessions_for_user_by_filter(
            db_session=db_session,
            user_id=user_id,
            is_suspicious=is_suspicious,
            created_before=created_before,
            created_after=created_after,
            last_seen_before=last_seen_before,
            last_seen_after=last_seen_after,
            ip_address=ip_address,
            user_agent_contains=user_agent_contains,
            for_update=False,
        )
        return [row.session_id for row in session_rows]

    async def revoke_user_sessions_by_filter(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        is_suspicious: bool | None = None,
        created_before: datetime | None = None,
        created_after: datetime | None = None,
        last_seen_before: datetime | None = None,
        last_seen_after: datetime | None = None,
        ip_address: str | None = None,
        user_agent_contains: str | None = None,
        reason: str,
        commit: bool = True,
    ) -> list[UUID]:
        """Revoke active user sessions matching the provided revoke filters."""
        try:
            session_rows = await self._fetch_active_sessions_for_user_by_filter(
                db_session=db_session,
                user_id=user_id,
                is_suspicious=is_suspicious,
                created_before=created_before,
                created_after=created_after,
                last_seen_before=last_seen_before,
                last_seen_after=last_seen_after,
                ip_address=ip_address,
                user_agent_contains=user_agent_contains,
                for_update=True,
            )
            revoked_at = datetime.now(UTC)
            session_ids: list[UUID] = []
            for session_row in session_rows:
                session_row.revoked_at = revoked_at
                session_row.revoke_reason = reason
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
        await self._touch_last_seen(db_session=db_session, session_row=session_row, now=now)
        return session_row.session_id

    async def _touch_last_seen(
        self,
        db_session: AsyncSession,
        session_row: Session,
        now: datetime,
    ) -> None:
        """Update last_seen_at if stale beyond the throttle window.

        Best-effort: any failure is swallowed so the caller's auth flow is not
        impacted. Missing one update is acceptable since the field is advisory.
        """
        previous = session_row.last_seen_at
        if previous is not None and (now - previous).total_seconds() < _LAST_SEEN_THROTTLE_SECONDS:
            return
        try:
            await db_session.execute(
                update(Session)
                .where(Session.session_id == session_row.session_id)
                .values(last_seen_at=now)
                .execution_options(synchronize_session=False)
            )
            await db_session.commit()
        except Exception:
            try:
                await db_session.rollback()
            except Exception:
                pass

    async def revoke_session(
        self,
        db_session: AsyncSession,
        raw_refresh_token: str,
        access_jti: str,
        access_expiration_epoch: int,
    ) -> None:
        """Revoke a session and blocklist the access token JTI."""
        try:
            session_row = await self._find_session_for_refresh_token(
                db_session=db_session,
                raw_refresh_token=raw_refresh_token,
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

    async def _fetch_active_sessions_for_user_by_filter(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        is_suspicious: bool | None,
        created_before: datetime | None,
        created_after: datetime | None,
        last_seen_before: datetime | None,
        last_seen_after: datetime | None,
        ip_address: str | None,
        user_agent_contains: str | None,
        for_update: bool,
    ) -> list[Session]:
        """Fetch active sessions for one user constrained by explicit admin filters."""
        statement = (
            select(Session)
            .where(
                Session.user_id == user_id,
                Session.deleted_at.is_(None),
                Session.revoked_at.is_(None),
                Session.expires_at > datetime.now(UTC),
            )
            .order_by(Session.created_at.desc(), Session.session_id.desc())
        )
        if is_suspicious is not None:
            statement = statement.where(Session.is_suspicious.is_(is_suspicious))
        if created_before is not None:
            statement = statement.where(Session.created_at <= created_before)
        if created_after is not None:
            statement = statement.where(Session.created_at >= created_after)
        if last_seen_before is not None:
            statement = statement.where(
                Session.last_seen_at.is_not(None),
                Session.last_seen_at <= last_seen_before,
            )
        if last_seen_after is not None:
            statement = statement.where(
                Session.last_seen_at.is_not(None),
                Session.last_seen_at >= last_seen_after,
            )
        if ip_address is not None:
            statement = statement.where(Session.ip_address == ip_address)
        if user_agent_contains is not None:
            statement = statement.where(
                Session.user_agent.is_not(None),
                Session.user_agent.ilike(
                    f"%{_escape_like_pattern(user_agent_contains)}%",
                    escape="\\",
                ),
            )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def _find_session_for_refresh_token(
        self,
        db_session: AsyncSession,
        raw_refresh_token: str,
        *,
        for_update: bool,
    ) -> Session | None:
        """Look up one refresh-token session using current and legacy verifiers."""
        current_hash = self._hash_token(raw_refresh_token)
        session_row = await self._fetch_session_by_refresh_hash(
            db_session=db_session,
            refresh_token_hash=current_hash,
            for_update=for_update,
        )
        if session_row is not None:
            return session_row

        legacy_hash = self._refresh_token_hasher.legacy_hash_token(raw_refresh_token)
        if legacy_hash == current_hash:
            return None

        session_row = await self._fetch_session_by_refresh_hash(
            db_session=db_session,
            refresh_token_hash=legacy_hash,
            for_update=for_update,
        )
        return session_row

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
        payload_dict.setdefault("mfa_enabled", False)
        payload_dict["audiences"] = normalize_audiences(payload_dict.get("audiences"))
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
                        "mfa_enabled": payload.mfa_enabled,
                        "scopes": payload.scopes,
                        "audiences": payload.audiences,
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
        mfa_enabled: bool,
        scopes: list[str],
        audiences: list[str],
        auth_time: datetime,
    ) -> TokenPairLike | Awaitable[TokenPairLike]:
        """Call token issuer while supporting legacy callbacks."""
        supported_parameters = get_callable_parameter_names(token_issuer)
        kwargs: dict[str, object] = {"email": email, "role": role, "scopes": scopes}
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="email_verified",
            value=email_verified,
        )
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="mfa_enabled",
            value=mfa_enabled,
        )
        if supported_parameters is not None and "audiences" in supported_parameters:
            kwargs["audiences"] = audiences
        elif supported_parameters is not None and "audience" in supported_parameters:
            kwargs["audience"] = audiences
        add_supported_kwarg(
            kwargs,
            supported_parameters=supported_parameters,
            name="auth_time",
            value=auth_time,
        )
        return token_issuer(user_id, **kwargs)

    @staticmethod
    def _extract_access_claims(raw_access_token: str) -> dict[str, object]:
        """Read issued access-token claims without re-verifying the signature."""
        try:
            claims = decode_unverified_jwt_claims(raw_access_token)
        except ValueError as exc:
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

    def _hash_token(self, raw_token: str) -> str:
        """Hash refresh token with keyed HMAC for persistent storage."""
        return self._refresh_token_hasher.hash_token(raw_token)

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


def _truncate(value: str | None, max_length: int) -> str | None:
    """Trim a display-only string to a column's max length."""
    if value is None:
        return None
    stripped = value.strip()
    if not stripped:
        return None
    return stripped[:max_length]


def _normalize_string_list(values: list[str] | tuple[str, ...] | object | None) -> list[str]:
    """Return a deduplicated, trimmed list of non-empty strings."""
    if values is None or isinstance(values, str | bytes) or not isinstance(values, Iterable):
        return []

    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _escape_like_pattern(value: str) -> str:
    """Escape SQL LIKE wildcards so substring filters behave literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _close_async_redis_client(client: Redis) -> None:
    """Close a previous async Redis client instance."""
    close = getattr(client, "aclose", None)
    if callable(close):
        await close()
        return

    close = getattr(client, "close", None)
    if callable(close):
        result = close()
        if inspect.isawaitable(result):
            await result


@reloadable_singleton(cleanup=_close_async_redis_client)
def get_redis_client() -> Redis:
    """Create and cache Redis client for async session operations."""
    settings = get_settings()
    return redis_async.from_url(
        settings.redis.url,
        decode_responses=True,
        socket_keepalive=True,
        health_check_interval=settings.redis.health_check_interval_seconds,
    )


@reloadable_singleton
def get_session_service() -> SessionService:
    """Create and cache session service."""
    settings = get_settings()
    return SessionService(
        redis_client=get_redis_client(),
        refresh_token_ttl_seconds=settings.jwt.refresh_token_ttl_seconds,
        access_token_ttl_seconds=settings.jwt.access_token_ttl_seconds,
        refresh_token_hasher=RefreshTokenHasher.from_settings(settings),
    )
