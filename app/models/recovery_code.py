"""Per-user recovery-code ORM model for MFA lost-phone fallback."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampTenantMixin

if TYPE_CHECKING:
    from app.models.user import User


class UserRecoveryCode(Base, TimestampTenantMixin):
    """Single-use MFA recovery code bound to one user.

    Codes are stored as keyed-HMAC hashes; the raw value is returned to the user
    only once at generation time. ``used_at`` enforces single-use semantics.
    """

    __tablename__ = "user_recovery_codes"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "code_hash",
            name="uq_user_recovery_codes_user_id_code_hash",
        ),
        Index("ix_user_recovery_codes_user_id_used_at", "user_id", "used_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="recovery_codes")
