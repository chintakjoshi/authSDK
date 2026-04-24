"""Admin API orchestration service."""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings, reloadable_singleton
from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.core.signing_keys import (
    SigningKeyRotationResult,
    SigningKeyService,
    get_signing_key_service,
)
from app.models.audit_event import AuditEvent
from app.models.session import Session
from app.models.user import User
from app.services.api_key_service import APIKeyService, get_api_key_service
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import (
    BruteForceProtectionError,
    BruteForceProtectionService,
    get_brute_force_service,
)
from app.services.erasure_service import (
    ErasedUserResult,
    ErasureService,
    ErasureServiceError,
    get_erasure_service,
)
from app.services.m2m_service import M2MService, get_m2m_service
from app.services.otp_service import OTPService, OTPServiceError, get_otp_service
from app.services.pagination import (
    CursorPage,
    CursorPosition,
    apply_created_at_cursor,
    build_page,
    decode_cursor,
)
from app.services.user_service import UserService, UserServiceError, get_user_service
from app.services.webhook_service import (
    DeletedWebhookEndpoint,
    WebhookService,
    WebhookServiceError,
    get_webhook_service,
)

_USER_HISTORY_EVENT_TYPES: list[str] = [
    "user.login.success",
    "user.login.failure",
    "user.login.suspicious",
    "user.logout",
    "session.created",
    "session.revoked",
    "password.reset.requested",
    "password.reset.completed",
    "otp.verified",
    "otp.failed",
    "otp.expired",
    "otp.excessive_failures",
    "otp.admin_toggled",
]

_SESSION_TIMELINE_EVENT_TYPES: list[str] = [
    "otp.verified",
    "user.login.success",
    "user.login.suspicious",
    "session.created",
    "session.revoked",
    "token.issued",
]


@dataclass(frozen=True)
class AdminUserSummary:
    """Admin-facing user summary with lock metadata."""

    id: UUID
    email: str
    role: str
    is_active: bool
    email_verified: bool
    mfa_enabled: bool
    locked: bool
    lock_retry_after: int | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class AdminUserDetailSummary(AdminUserSummary):
    """Admin-facing user detail summary."""

    active_session_count: int


@dataclass(frozen=True)
class DeletedUserResult:
    """Deleted user payload for admin responses."""

    user_id: UUID
    revoked_session_ids: list[UUID]


@dataclass(frozen=True)
class AdminSessionSummary:
    """Admin-facing session row for the session inventory view."""

    id: UUID
    session_id: UUID
    user_id: UUID
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None
    ip_address: str | None
    user_agent: str | None
    is_suspicious: bool
    suspicious_reasons: list[str]


@dataclass(frozen=True)
class AdminSuspiciousSessionSummary(AdminSessionSummary):
    """Global suspicious-session row enriched with user identity details."""

    user_email: str
    user_role: str


@dataclass(frozen=True)
class AdminSessionDetailSummary(AdminSessionSummary):
    """Admin-facing session detail payload with attributable timeline events."""

    timeline: list[AuditEvent]


@dataclass(frozen=True)
class AdminFilteredSessionRevokeResult:
    """Admin-facing result for filter-based session revoke operations."""

    user_id: UUID
    matched_session_ids: list[UUID]
    revoked_session_ids: list[UUID]
    revoke_reason: str
    dry_run: bool


@dataclass(frozen=True)
class RetentionPurgeResult:
    """Callable retention-purge scaffolding result."""

    enabled: bool
    audit_log_retention_days: int
    session_log_retention_days: int
    purged_audit_events: int
    purged_sessions: int


class AdminServiceError(Exception):
    """Raised for admin API validation and orchestration failures."""

    def __init__(
        self,
        detail: str,
        code: str,
        status_code: int,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code
        self.headers = headers or {}


class AdminService:
    """Coordinate admin-only user, key, client, webhook, and key-rotation operations."""

    def __init__(
        self,
        *,
        user_service: UserService,
        session_service: SessionService,
        otp_service: OTPService,
        brute_force_service: BruteForceProtectionService,
        api_key_service: APIKeyService,
        m2m_service: M2MService,
        webhook_service: WebhookService,
        audit_service: AuditService,
        signing_key_service: SigningKeyService,
        erasure_service: ErasureService,
        enable_retention_purge: bool,
        audit_log_retention_days: int,
        session_log_retention_days: int,
    ) -> None:
        self._user_service = user_service
        self._session_service = session_service
        self._otp_service = otp_service
        self._brute_force_service = brute_force_service
        self._api_key_service = api_key_service
        self._m2m_service = m2m_service
        self._webhook_service = webhook_service
        self._audit_service = audit_service
        self._signing_key_service = signing_key_service
        self._erasure_service = erasure_service
        self._enable_retention_purge = enable_retention_purge
        self._audit_log_retention_days = audit_log_retention_days
        self._session_log_retention_days = session_log_retention_days

    async def validate_admin_access_token(
        self,
        db_session: AsyncSession,
        *,
        token: str | None,
    ) -> dict[str, object]:
        """Validate bearer token and require the admin role."""
        if token is None or not token.strip():
            raise AdminServiceError("Invalid token.", "invalid_token", 401)
        try:
            claims = await self._otp_service.validate_access_token(
                db_session=db_session,
                token=token.strip(),
            )
        except OTPServiceError as exc:
            raise AdminServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
            ) from exc
        if not hmac.compare_digest(str(claims.get("role", "")), "admin"):
            raise AdminServiceError("Insufficient role.", "insufficient_role", 403)
        return claims

    async def enforce_sensitive_action_gate(
        self,
        db_session: AsyncSession,
        *,
        claims: dict[str, object],
        action: str,
        action_token: str | None,
    ) -> None:
        """Apply the dual-gate policy for sensitive admin operations."""
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            raise AdminServiceError("Invalid token.", "invalid_token", 401)

        action_token_valid = await self._otp_service.validate_action_token_for_user(
            db_session=db_session,
            token=action_token,
            expected_action=action,
            user_id=user_id,
        )
        if action_token_valid:
            return

        if bool(claims.get("mfa_enabled", False)):
            raise AdminServiceError(
                "OTP required.",
                "otp_required",
                403,
                headers={"X-OTP-Required": "true", "X-OTP-Action": action},
            )
        if not self._auth_time_is_fresh(claims):
            raise AdminServiceError(
                "Re-authentication required.",
                "reauth_required",
                403,
                headers={"X-Reauth-Required": "true"},
            )

    async def require_action_token(
        self,
        db_session: AsyncSession,
        *,
        claims: dict[str, object],
        action: str,
        action_token: str | None,
    ) -> None:
        """Require one valid action token for a specific admin user/action pair."""
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            raise AdminServiceError("Invalid token.", "invalid_token", 401)
        try:
            await self._otp_service.require_action_token_for_user(
                db_session=db_session,
                token=action_token,
                expected_action=action,
                user_id=user_id,
            )
        except OTPServiceError as exc:
            raise AdminServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
            ) from exc

    async def list_users_page(
        self,
        db_session: AsyncSession,
        *,
        role: str | None = None,
        email: str | None = None,
        locked: bool | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[AdminUserSummary]:
        """Return a cursor-paginated page of admin user summaries."""
        limit = max(1, min(limit, 200))
        scan_cursor = decode_cursor(cursor) if cursor is not None else None
        collected: list[AdminUserSummary] = []
        batch_size = max(limit * 3, 50)

        while len(collected) <= limit:
            statement = self._build_user_list_statement(role=role, email=email)
            statement = apply_created_at_cursor(
                statement,
                model=User,
                cursor=scan_cursor,
            ).limit(batch_size)
            rows = list((await db_session.execute(statement)).scalars().all())
            if not rows:
                break

            for user in rows:
                summary = await self._build_user_summary(user)
                if locked is not None and summary.locked is not locked:
                    continue
                collected.append(summary)
                if len(collected) > limit:
                    break

            if len(rows) < batch_size or len(collected) > limit:
                break
            last_row = rows[-1]
            scan_cursor = CursorPosition(created_at=last_row.created_at, row_id=last_row.id)

        return build_page(collected, limit=limit)

    async def get_user_detail(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> AdminUserDetailSummary:
        """Return one admin user detail payload."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        locked, retry_after = await self._get_lock_status(str(user.id))
        return AdminUserDetailSummary(
            id=user.id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            email_verified=user.email_verified,
            mfa_enabled=user.mfa_enabled,
            locked=locked,
            lock_retry_after=retry_after,
            created_at=user.created_at,
            updated_at=user.updated_at,
            active_session_count=await self._count_active_sessions(
                db_session=db_session,
                user_id=user.id,
            ),
        )

    async def update_user_role(
        self,
        db_session: AsyncSession,
        *,
        actor_id: str,
        user_id: UUID,
        new_role: str,
        request,
    ) -> User:
        """Update a user role through the existing role service protections."""
        try:
            return await self._user_service.update_role(
                db_session=db_session,
                actor_role="admin",
                actor_id=actor_id,
                user_id=user_id,
                new_role=new_role,
                request=request,
                audit_service=self._audit_service,
            )
        except UserServiceError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def delete_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> DeletedUserResult:
        """Soft-delete a user and synchronously revoke active sessions and API keys."""
        try:
            deleted_user = await self._user_service.delete_user(
                db_session=db_session,
                actor_role="admin",
                user_id=user_id,
                commit=False,
            )
            revoked_session_ids = await self._session_service.revoke_user_sessions(
                db_session=db_session,
                user_id=user_id,
                commit=False,
            )
            await self._api_key_service.revoke_user_keys(
                db_session=db_session,
                user_id=user_id,
                commit=False,
            )
            await db_session.commit()
        except UserServiceError as exc:
            await db_session.rollback()
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc
        except SessionStateError as exc:
            await db_session.rollback()
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc
        except Exception:
            await db_session.rollback()
            raise
        return DeletedUserResult(
            user_id=deleted_user.id,
            revoked_session_ids=revoked_session_ids,
        )

    async def revoke_user_sessions(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        reason: str | None = None,
    ) -> tuple[list[UUID], str]:
        """Revoke all active sessions for a target user."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        effective_reason = reason or "admin_revoke_all"
        try:
            revoked_ids = await self._session_service.revoke_user_sessions(
                db_session=db_session,
                user_id=user_id,
                reason=effective_reason,
            )
        except SessionStateError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc
        return revoked_ids, effective_reason

    async def list_user_sessions_page(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        status: str = "active",
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[AdminSessionSummary]:
        """Return a cursor-paginated list of sessions for one user."""
        if status not in {"active", "revoked", "all"}:
            raise AdminServiceError(
                "Invalid status filter.",
                "invalid_status",
                400,
            )
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)

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
            AdminSessionSummary(
                id=row.id,
                session_id=row.session_id,
                user_id=row.user_id,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                revoke_reason=row.revoke_reason,
                ip_address=row.ip_address,
                user_agent=row.user_agent,
                is_suspicious=bool(getattr(row, "is_suspicious", False)),
                suspicious_reasons=list(getattr(row, "suspicious_reasons", []) or []),
            )
            for row in rows
        ]
        return build_page(summaries, limit=limit)

    async def list_suspicious_sessions_page(
        self,
        db_session: AsyncSession,
        *,
        email: str | None = None,
        role: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[AdminSuspiciousSessionSummary]:
        """Return active suspicious sessions across all non-deleted users."""
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = (
            select(Session, User.email, User.role)
            .join(User, User.id == Session.user_id)
            .where(
                Session.deleted_at.is_(None),
                Session.is_suspicious.is_(True),
                Session.revoked_at.is_(None),
                Session.expires_at > datetime.now(UTC),
                User.deleted_at.is_(None),
            )
            .order_by(Session.created_at.desc(), Session.id.desc())
        )
        normalized_role = role.strip() if role is not None else None
        if normalized_role:
            statement = statement.where(User.role == normalized_role)
        normalized_email = email.strip().lower() if email is not None else None
        if normalized_email:
            statement = statement.where(func.lower(User.email).like(f"%{normalized_email}%"))

        statement = apply_created_at_cursor(
            statement,
            model=Session,
            cursor=cursor_position,
        ).limit(limit + 1)
        rows = list((await db_session.execute(statement)).all())
        summaries = [
            AdminSuspiciousSessionSummary(
                id=session_row.id,
                session_id=session_row.session_id,
                user_id=session_row.user_id,
                created_at=session_row.created_at,
                last_seen_at=session_row.last_seen_at,
                expires_at=session_row.expires_at,
                revoked_at=session_row.revoked_at,
                revoke_reason=session_row.revoke_reason,
                ip_address=session_row.ip_address,
                user_agent=session_row.user_agent,
                is_suspicious=bool(getattr(session_row, "is_suspicious", False)),
                suspicious_reasons=list(getattr(session_row, "suspicious_reasons", []) or []),
                user_email=str(user_email),
                user_role=str(user_role),
            )
            for session_row, user_email, user_role in rows
        ]
        return build_page(summaries, limit=limit)

    async def get_user_session_detail(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        session_id: UUID,
        timeline_limit: int = 20,
    ) -> AdminSessionDetailSummary:
        """Return one session plus the latest attributable audit events for it."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)

        session_row = await self._get_session_row_for_user(
            db_session=db_session,
            user_id=user_id,
            session_id=session_id,
        )
        if session_row is None:
            raise AdminServiceError("Session not found.", "invalid_session", 404)

        timeline = await self._list_session_timeline(
            db_session=db_session,
            user_id=user_id,
            session_id=session_id,
            timeline_limit=timeline_limit,
        )
        return AdminSessionDetailSummary(
            id=session_row.id,
            session_id=session_row.session_id,
            user_id=session_row.user_id,
            created_at=session_row.created_at,
            last_seen_at=session_row.last_seen_at,
            expires_at=session_row.expires_at,
            revoked_at=session_row.revoked_at,
            revoke_reason=session_row.revoke_reason,
            ip_address=session_row.ip_address,
            user_agent=session_row.user_agent,
            is_suspicious=bool(getattr(session_row, "is_suspicious", False)),
            suspicious_reasons=list(getattr(session_row, "suspicious_reasons", []) or []),
            timeline=timeline,
        )

    async def revoke_user_session(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        session_id: UUID,
        reason: str | None = None,
    ) -> tuple[UUID, str]:
        """Revoke a single session owned by the target user."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        effective_reason = reason or "admin_targeted"
        try:
            revoked_id = await self._session_service.revoke_one_session(
                db_session=db_session,
                user_id=user_id,
                session_id=session_id,
                reason=effective_reason,
            )
        except SessionStateError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc
        return revoked_id, effective_reason

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
        dry_run: bool = False,
        reason: str | None = None,
    ) -> AdminFilteredSessionRevokeResult:
        """Preview or revoke active sessions matching explicit admin filters."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        if not self._has_session_revoke_filter(
            is_suspicious=is_suspicious,
            created_before=created_before,
            created_after=created_after,
            last_seen_before=last_seen_before,
            last_seen_after=last_seen_after,
            ip_address=ip_address,
            user_agent_contains=user_agent_contains,
        ):
            raise AdminServiceError(
                "At least one session filter is required.", "invalid_filter", 400
            )

        effective_reason = reason or "admin_filtered_revoke"
        try:
            if dry_run:
                matched_ids = await self._session_service.match_user_sessions_for_revoke_filter(
                    db_session=db_session,
                    user_id=user_id,
                    is_suspicious=is_suspicious,
                    created_before=created_before,
                    created_after=created_after,
                    last_seen_before=last_seen_before,
                    last_seen_after=last_seen_after,
                    ip_address=ip_address,
                    user_agent_contains=user_agent_contains,
                )
                return AdminFilteredSessionRevokeResult(
                    user_id=user_id,
                    matched_session_ids=matched_ids,
                    revoked_session_ids=[],
                    revoke_reason=effective_reason,
                    dry_run=True,
                )

            revoked_ids = await self._session_service.revoke_user_sessions_by_filter(
                db_session=db_session,
                user_id=user_id,
                is_suspicious=is_suspicious,
                created_before=created_before,
                created_after=created_after,
                last_seen_before=last_seen_before,
                last_seen_after=last_seen_after,
                ip_address=ip_address,
                user_agent_contains=user_agent_contains,
                reason=effective_reason,
            )
        except SessionStateError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

        return AdminFilteredSessionRevokeResult(
            user_id=user_id,
            matched_session_ids=revoked_ids,
            revoked_session_ids=revoked_ids,
            revoke_reason=effective_reason,
            dry_run=False,
        )

    async def list_user_history_page(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        cursor: str | None = None,
        limit: int = 50,
    ):
        """List login/logout/session/otp/password-reset events for one user."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        return await self._audit_service.list_events_page(
            db_session=db_session,
            actor_or_target_id=user_id,
            event_types=_USER_HISTORY_EVENT_TYPES,
            cursor=cursor,
            limit=limit,
        )

    async def _get_session_row_for_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        session_id: UUID,
    ) -> Session | None:
        """Return one non-deleted session row owned by the provided user."""
        result = await db_session.execute(
            select(Session).where(
                Session.user_id == user_id,
                Session.session_id == session_id,
                Session.deleted_at.is_(None),
            )
        )
        return result.scalar_one_or_none()

    async def _list_session_timeline(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        session_id: UUID,
        timeline_limit: int,
    ) -> list[AuditEvent]:
        """Return the latest attributable audit events for one session."""
        limit = max(1, min(timeline_limit, 100))
        session_id_text = str(session_id)
        created_event = await self._get_session_created_event(
            db_session=db_session,
            session_id=session_id,
        )

        matching_conditions = [
            and_(AuditEvent.target_type == "session", AuditEvent.target_id == session_id),
            AuditEvent.event_metadata.contains({"session_id": session_id_text}),
            AuditEvent.event_metadata.contains({"session_ids": [session_id_text]}),
        ]
        if created_event is not None and created_event.correlation_id is not None:
            matching_conditions.append(
                and_(
                    AuditEvent.correlation_id == created_event.correlation_id,
                    AuditEvent.actor_id == user_id,
                )
            )

        statement = (
            select(AuditEvent)
            .where(
                AuditEvent.event_type.in_(_SESSION_TIMELINE_EVENT_TYPES),
                or_(*matching_conditions),
            )
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
        )
        rows = list((await db_session.execute(statement)).scalars().all())
        rows.reverse()
        return rows

    async def _get_session_created_event(
        self,
        db_session: AsyncSession,
        *,
        session_id: UUID,
    ) -> AuditEvent | None:
        """Return the canonical session-created event used to stitch login events."""
        result = await db_session.execute(
            select(AuditEvent)
            .where(
                AuditEvent.event_type == "session.created",
                AuditEvent.target_type == "session",
                AuditEvent.target_id == session_id,
            )
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    async def set_user_email_otp(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        enabled: bool,
    ) -> User:
        """Admin-toggle email OTP for a target user."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        try:
            if enabled:
                return await self._otp_service.enable_email_otp(
                    db_session=db_session,
                    user_id=str(user_id),
                    action_token=None,
                    require_action_token=False,
                )
            return await self._otp_service.disable_email_otp(
                db_session=db_session,
                user_id=str(user_id),
                action_token=None,
                require_action_token=False,
            )
        except OTPServiceError as exc:
            if exc.code == "invalid_token":
                raise AdminServiceError("User not found.", "invalid_user", 404) from exc
            raise AdminServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
            ) from exc

    async def list_api_keys_page(
        self,
        db_session: AsyncSession,
        *,
        scope: str | None = None,
        active: bool | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ):
        """Proxy paginated admin API-key listings."""
        return await self._api_key_service.list_keys_page(
            db_session=db_session,
            scope=scope,
            active=active,
            cursor=cursor,
            limit=limit,
        )

    async def list_clients_page(
        self,
        db_session: AsyncSession,
        *,
        active: bool | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ):
        """Proxy paginated admin OAuth-client listings."""
        return await self._m2m_service.list_clients_page(
            db_session=db_session,
            active=active,
            cursor=cursor,
            limit=limit,
        )

    async def list_webhooks_page(
        self,
        db_session: AsyncSession,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ):
        """Proxy paginated admin webhook listings."""
        return await self._webhook_service.list_endpoints_page(
            db_session=db_session,
            cursor=cursor,
            limit=limit,
        )

    async def list_webhook_deliveries_page(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ):
        """Proxy paginated admin webhook-delivery listings with endpoint validation."""
        try:
            await self._webhook_service.get_endpoint(
                db_session=db_session,
                endpoint_id=endpoint_id,
                for_update=False,
            )
            return await self._webhook_service.list_deliveries_page(
                db_session=db_session,
                endpoint_id=endpoint_id,
                status=status,
                cursor=cursor,
                limit=limit,
            )
        except WebhookServiceError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def list_audit_log_page(
        self,
        db_session: AsyncSession,
        *,
        actor_id: UUID | None = None,
        event_type: str | None = None,
        success: bool | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ):
        """Proxy paginated admin audit-log listings."""
        return await self._audit_service.list_events_page(
            db_session=db_session,
            actor_id=actor_id,
            event_type_prefix=event_type,
            success=success,
            date_from=date_from,
            date_to=date_to,
            cursor=cursor,
            limit=limit,
        )

    async def rotate_signing_key(
        self,
        db_session: AsyncSession,
        *,
        rotation_overlap_seconds: int,
    ) -> SigningKeyRotationResult:
        """Rotate the active signing key and commit the new state."""
        result = await self._signing_key_service.rotate_signing_key(
            db_session=db_session,
            rotation_overlap_seconds=rotation_overlap_seconds,
        )
        await db_session.commit()
        return result

    async def delete_webhook(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
    ) -> DeletedWebhookEndpoint:
        """Delete one webhook endpoint."""
        try:
            return await self._webhook_service.delete_endpoint(
                db_session=db_session,
                endpoint_id=endpoint_id,
            )
        except WebhookServiceError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def erase_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> ErasedUserResult:
        """Erase one user account on behalf of an admin actor."""
        try:
            return await self._erasure_service.erase_user(
                db_session=db_session,
                user_id=user_id,
            )
        except ErasureServiceError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

    async def run_retention_purge(self, db_session: AsyncSession) -> RetentionPurgeResult:
        """Purge aged audit and session records according to configured retention windows."""
        if not self._enable_retention_purge:
            return RetentionPurgeResult(
                enabled=False,
                audit_log_retention_days=self._audit_log_retention_days,
                session_log_retention_days=self._session_log_retention_days,
                purged_audit_events=0,
                purged_sessions=0,
            )

        audit_cutoff = datetime.now(UTC) - timedelta(days=self._audit_log_retention_days)
        session_cutoff = datetime.now(UTC) - timedelta(days=self._session_log_retention_days)
        try:
            purged_audit_events = await self._purge_audit_events(
                db_session=db_session,
                cutoff=audit_cutoff,
            )
            purged_sessions = await self._purge_sessions(
                db_session=db_session,
                cutoff=session_cutoff,
            )
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise
        return RetentionPurgeResult(
            enabled=True,
            audit_log_retention_days=self._audit_log_retention_days,
            session_log_retention_days=self._session_log_retention_days,
            purged_audit_events=purged_audit_events,
            purged_sessions=purged_sessions,
        )

    async def update_webhook(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
        name: str | None = None,
        url: str | None = None,
        events: list[str] | None = None,
        is_active: bool | None = None,
    ):
        """Update one webhook endpoint."""
        try:
            return await self._webhook_service.update_endpoint(
                db_session=db_session,
                endpoint_id=endpoint_id,
                name=name,
                url=url,
                events=events,
                is_active=is_active,
            )
        except WebhookServiceError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

    @staticmethod
    def _auth_time_is_fresh(claims: dict[str, object], *, max_age_seconds: int = 300) -> bool:
        """Return True when auth_time is recent enough for password step-up."""
        auth_time = claims.get("auth_time")
        if not isinstance(auth_time, int):
            return False
        return (time.time() - auth_time) <= max_age_seconds

    @staticmethod
    def _build_user_list_statement(*, role: str | None, email: str | None):
        """Build the base admin user listing query."""
        statement = (
            select(User)
            .where(User.deleted_at.is_(None))
            .order_by(User.created_at.desc(), User.id.desc())
        )
        if role is not None:
            statement = statement.where(User.role == role)
        if email is not None:
            normalized = email.strip().lower()
            if normalized:
                statement = statement.where(func.lower(User.email).like(f"%{normalized}%"))
        return statement

    @staticmethod
    def _has_session_revoke_filter(
        *,
        is_suspicious: bool | None,
        created_before: datetime | None,
        created_after: datetime | None,
        last_seen_before: datetime | None,
        last_seen_after: datetime | None,
        ip_address: str | None,
        user_agent_contains: str | None,
    ) -> bool:
        """Return whether at least one explicit filtered-revoke selector is present."""
        return any(
            (
                is_suspicious is not None,
                created_before is not None,
                created_after is not None,
                last_seen_before is not None,
                last_seen_after is not None,
                ip_address is not None,
                user_agent_contains is not None,
            )
        )

    async def _build_user_summary(self, user: User) -> AdminUserSummary:
        """Build one admin user summary with lock metadata."""
        locked, retry_after = await self._get_lock_status(str(user.id))
        return AdminUserSummary(
            id=user.id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            email_verified=user.email_verified,
            mfa_enabled=user.mfa_enabled,
            locked=locked,
            lock_retry_after=retry_after,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    async def _get_lock_status(self, user_id: str) -> tuple[bool, int | None]:
        """Read admin-visible lock status from the brute-force service."""
        try:
            return await self._brute_force_service.get_lock_status(user_id)
        except BruteForceProtectionError as exc:
            raise AdminServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
            ) from exc

    async def _get_active_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
        for_update: bool,
    ) -> User | None:
        """Fetch one non-deleted user for admin operations."""
        statement = select(User).where(User.id == user_id, User.deleted_at.is_(None))
        if for_update:
            statement = statement.with_for_update()
        return (await db_session.execute(statement)).scalar_one_or_none()

    async def _count_active_sessions(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> int:
        """Count active refresh sessions for one user."""
        statement = (
            select(func.count())
            .select_from(Session)
            .where(
                Session.user_id == user_id,
                Session.deleted_at.is_(None),
                Session.revoked_at.is_(None),
                Session.expires_at > datetime.now(UTC),
            )
        )
        return int((await db_session.execute(statement)).scalar_one())

    @staticmethod
    async def _purge_audit_events(
        db_session: AsyncSession,
        *,
        cutoff: datetime,
    ) -> int:
        """Delete immutable audit rows older than the configured retention cutoff."""
        result = await db_session.execute(delete(AuditEvent).where(AuditEvent.created_at < cutoff))
        return int(result.rowcount or 0)

    @staticmethod
    async def _purge_sessions(
        db_session: AsyncSession,
        *,
        cutoff: datetime,
    ) -> int:
        """Delete inactive session rows whose terminal timestamps are older than the cutoff."""
        result = await db_session.execute(
            delete(Session).where(
                or_(
                    and_(Session.deleted_at.is_not(None), Session.deleted_at < cutoff),
                    and_(Session.revoked_at.is_not(None), Session.revoked_at < cutoff),
                    Session.expires_at < cutoff,
                )
            )
        )
        return int(result.rowcount or 0)


@reloadable_singleton
def get_admin_service() -> AdminService:
    """Create and cache the admin orchestration service dependency."""
    settings = get_settings()
    return AdminService(
        user_service=get_user_service(),
        session_service=get_session_service(),
        otp_service=get_otp_service(),
        brute_force_service=get_brute_force_service(),
        api_key_service=get_api_key_service(),
        m2m_service=get_m2m_service(),
        webhook_service=get_webhook_service(),
        audit_service=get_audit_service(),
        signing_key_service=get_signing_key_service(),
        erasure_service=get_erasure_service(),
        enable_retention_purge=settings.retention.enable_retention_purge,
        audit_log_retention_days=settings.retention.audit_log_retention_days,
        session_log_retention_days=settings.retention.session_log_retention_days,
    )
