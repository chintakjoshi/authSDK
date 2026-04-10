"""GDPR erasure workflow for self-service and admin-driven account removal."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.models.user import User
from app.service_registry import service_cached
from app.services.api_key_service import APIKeyService, APIKeyServiceError, get_api_key_service
from app.services.otp_service import OTPService, OTPServiceError, get_otp_service
from app.services.user_service import UserService


@dataclass(frozen=True)
class ErasedUserResult:
    """Result payload for one completed GDPR erasure."""

    user_id: UUID
    anonymized_email: str
    deleted_identity_count: int
    revoked_session_ids: list[UUID]
    revoked_api_key_ids: list[UUID]


class ErasureServiceError(Exception):
    """Raised when GDPR erasure cannot be completed."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class ErasureService:
    """Coordinate account erasure across Postgres and Redis."""

    def __init__(
        self,
        *,
        user_service: UserService,
        session_service: SessionService,
        otp_service: OTPService,
        api_key_service: APIKeyService,
    ) -> None:
        self._user_service = user_service
        self._session_service = session_service
        self._otp_service = otp_service
        self._api_key_service = api_key_service

    async def erase_user(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> ErasedUserResult:
        """Erase one user account and revoke all remaining access paths."""
        user = await self._get_user_for_update(db_session=db_session, user_id=user_id)
        if user is None:
            raise ErasureServiceError("User not found.", "invalid_user", 404)
        if self._is_erased_user(user):
            raise ErasureServiceError("User already erased.", "already_erased", 409)
        if user.deleted_at is not None:
            raise ErasureServiceError("User not found.", "invalid_user", 404)

        try:
            await self._user_service.ensure_admin_removal_allowed(
                db_session=db_session,
                user=user,
            )
            anonymized_email = self._anonymized_email(user.id)
            user.email = anonymized_email
            user.password_hash = None
            user.is_active = False
            user.email_verified = False
            user.email_otp_enabled = False
            user.email_verify_token_hash = None
            user.email_verify_token_expires = None
            user.password_reset_token_hash = None
            user.password_reset_token_expires = None
            user.deleted_at = datetime.now(UTC)
            await db_session.flush()

            deleted_identity_count = await self._user_service.hard_delete_identities(
                db_session=db_session,
                user_id=user.id,
                commit=False,
            )
            revoked_session_ids = await self._session_service.revoke_user_sessions(
                db_session=db_session,
                user_id=user.id,
                commit=False,
            )
            revoked_api_keys = await self._api_key_service.revoke_user_keys(
                db_session=db_session,
                user_id=user.id,
                commit=False,
            )
            await self._otp_service.clear_user_otp_state(str(user.id))
            await db_session.commit()
        except (
            APIKeyServiceError,
            OTPServiceError,
            SessionStateError,
        ) as exc:
            await db_session.rollback()
            raise ErasureServiceError(exc.detail, exc.code, exc.status_code) from exc
        except Exception:
            await db_session.rollback()
            raise

        return ErasedUserResult(
            user_id=user.id,
            anonymized_email=anonymized_email,
            deleted_identity_count=deleted_identity_count,
            revoked_session_ids=revoked_session_ids,
            revoked_api_key_ids=[row.id for row in revoked_api_keys],
        )

    async def _get_user_for_update(
        self,
        db_session: AsyncSession,
        *,
        user_id: UUID,
    ) -> User | None:
        """Fetch one user row for erasure, including already-deleted rows."""
        statement = select(User).where(User.id == user_id).with_for_update()
        return (await db_session.execute(statement)).scalar_one_or_none()

    @staticmethod
    def _anonymized_email(user_id: UUID) -> str:
        """Return the deterministic erased-email placeholder for one user."""
        return f"deleted_{user_id}@erased.invalid"

    @classmethod
    def _is_erased_user(cls, user: User) -> bool:
        """Return True when the user already matches the erased placeholder contract."""
        return user.email == cls._anonymized_email(user.id)


@service_cached
def get_erasure_service() -> ErasureService:
    """Create and cache the GDPR erasure service dependency."""
    return ErasureService(
        user_service=UserService(),
        session_service=get_session_service(),
        otp_service=get_otp_service(),
        api_key_service=get_api_key_service(),
    )
