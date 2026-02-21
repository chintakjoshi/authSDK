"""User lookup and password validation services."""

from __future__ import annotations

from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User


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

    def hash_password(self, password: str) -> str:
        """Generate a bcrypt hash for the provided password."""
        return str(self._password_context.hash(password))

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a plaintext password against the stored bcrypt hash."""
        return bool(self._password_context.verify(password, password_hash))
