"""User and external identity ORM models."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampTenantMixin

if TYPE_CHECKING:
    from app.models.api_key import APIKey
    from app.models.session import Session


class User(Base, TimestampTenantMixin):
    """Canonical user record shared across all authentication providers."""

    __tablename__ = "users"
    __table_args__ = (Index("ix_users_email_deleted_at", "email", "deleted_at"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    identities: Mapped[list[UserIdentity]] = relationship(back_populates="user")
    sessions: Mapped[list[Session]] = relationship(back_populates="user")
    api_keys: Mapped[list[APIKey]] = relationship(back_populates="user")


class UserIdentity(Base, TimestampTenantMixin):
    """External identity mapping for OAuth, SAML, and password providers."""

    __tablename__ = "user_identities"
    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_user_id", name="uq_user_identities_provider_subject"
        ),
        Index("ix_user_identities_user_id_deleted_at", "user_id", "deleted_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)

    user: Mapped[User] = relationship(back_populates="identities")
