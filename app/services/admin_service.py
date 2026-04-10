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
from app.services.user_service import UserService, UserServiceError
from app.services.webhook_service import (
    DeletedWebhookEndpoint,
    WebhookService,
    WebhookServiceError,
    get_webhook_service,
)


@dataclass(frozen=True)
class AdminUserSummary:
    """Admin-facing user summary with lock metadata."""

    id: UUID
    email: str
    role: str
    is_active: bool
    email_verified: bool
    email_otp_enabled: bool
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

        if bool(claims.get("email_otp_enabled", False)):
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
            email_otp_enabled=user.email_otp_enabled,
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
    ) -> list[UUID]:
        """Revoke all active sessions for a target user."""
        user = await self._get_active_user(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise AdminServiceError("User not found.", "invalid_user", 404)
        try:
            return await self._session_service.revoke_user_sessions(
                db_session=db_session,
                user_id=user_id,
            )
        except SessionStateError as exc:
            raise AdminServiceError(exc.detail, exc.code, exc.status_code) from exc

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

    async def _build_user_summary(self, user: User) -> AdminUserSummary:
        """Build one admin user summary with lock metadata."""
        locked, retry_after = await self._get_lock_status(str(user.id))
        return AdminUserSummary(
            id=user.id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
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
        user_service=UserService(),
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
