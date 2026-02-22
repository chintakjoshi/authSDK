"""User lookup and password validation services."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import Request
from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services.audit_service import AuditService

AllowedRole = Literal["admin", "user", "service"]


class UserServiceError(Exception):
    """Raised when user management operations fail validation or authorization."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class UserService:
    """Service responsible for user retrieval and password verification."""

    def __init__(self) -> None:
        self._password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    async def get_user_by_email(self, db_session: AsyncSession, email: str) -> User | None:
        """Fetch an active, non-deleted user by email."""
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def authenticate_user(
        self,
        db_session: AsyncSession,
        email: str,
        password: str,
    ) -> User | None:
        """Authenticate user credentials for password login."""
        user = await self.get_user_by_email(db_session=db_session, email=email)
        if user is None or user.password_hash is None:
            self._password_context.dummy_verify()
            return None
        if not self.verify_password(password=password, password_hash=user.password_hash):
            return None
        return user

    async def update_role(
        self,
        db_session: AsyncSession,
        actor_role: str,
        actor_id: str | None,
        user_id: UUID,
        new_role: AllowedRole,
        request: Request | None = None,
        audit_service: AuditService | None = None,
    ) -> User:
        """Update role for target user with admin-only and last-admin protections."""
        if actor_role != "admin":
            raise UserServiceError("Insufficient role.", "insufficient_role", 403)
        if new_role not in {"admin", "user", "service"}:
            raise UserServiceError("Invalid role.", "invalid_role", 400)

        user = await self._get_user_for_update(db_session=db_session, user_id=user_id)
        if user is None:
            raise UserServiceError("User not found.", "invalid_user", 404)
        if user.deleted_at is not None:
            raise UserServiceError("User not found.", "invalid_user", 404)
        if new_role == user.role:
            return user
        if user.role == "admin" and new_role != "admin":
            await self._ensure_last_admin_not_violated(db_session=db_session)

        if request is not None and audit_service is not None:
            await audit_service.record(
                db=db_session,
                event_type="user.role_changed",
                actor_type=actor_role,
                success=True,
                request=request,
                actor_id=actor_id,
                target_id=str(user.id),
                target_type="user",
                metadata={"old_role": user.role, "new_role": new_role},
            )

        user.role = new_role
        await db_session.flush()
        await db_session.commit()
        return user

    async def delete_user(
        self,
        db_session: AsyncSession,
        actor_role: str,
        user_id: UUID,
    ) -> User:
        """Soft-delete a user with admin-only and last-admin protections."""
        if actor_role != "admin":
            raise UserServiceError("Insufficient role.", "insufficient_role", 403)

        user = await self._get_user_for_update(db_session=db_session, user_id=user_id)
        if user is None or user.deleted_at is not None:
            raise UserServiceError("User not found.", "invalid_user", 404)
        if user.role == "admin":
            await self._ensure_last_admin_not_violated(db_session=db_session)

        user.deleted_at = datetime.now(UTC)
        user.is_active = False
        await db_session.flush()
        await db_session.commit()
        return user

    async def count_active_admins(self, db_session: AsyncSession) -> int:
        """Return the count of non-deleted admin users."""
        statement = select(func.count()).select_from(User).where(
            User.role == "admin",
            User.deleted_at.is_(None),
        )
        result = await db_session.execute(statement)
        return int(result.scalar_one())

    def hash_password(self, password: str) -> str:
        """Generate a bcrypt hash for the provided password."""
        return str(self._password_context.hash(password))

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a plaintext password against the stored bcrypt hash."""
        return bool(self._password_context.verify(password, password_hash))

    async def _get_user_for_update(self, db_session: AsyncSession, user_id: UUID) -> User | None:
        """Fetch user row for mutation with row lock."""
        statement = select(User).where(User.id == user_id).with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _ensure_last_admin_not_violated(
        self,
        db_session: AsyncSession,
    ) -> None:
        """Raise when changing/deleting would remove the final admin account."""
        admin_ids_stmt = (
            select(User.id)
            .where(
                User.role == "admin",
                User.deleted_at.is_(None),
            )
            .with_for_update()
        )
        result = await db_session.execute(admin_ids_stmt)
        admin_count = len(list(result.scalars().all()))
        if admin_count <= 1:
            raise UserServiceError(
                "Cannot remove the last admin.",
                "last_admin_protected",
                409,
            )
