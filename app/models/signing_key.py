"""Signing key ORM model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Index, String, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampTenantMixin


class SigningKeyStatus(str, Enum):
    """Lifecycle statuses for JWT signing keys."""

    ACTIVE = "active"
    RETIRING = "retiring"
    RETIRED = "retired"


class SigningKey(Base, TimestampTenantMixin):
    """Versioned RS256 signing keypair metadata and encrypted private key material."""

    __tablename__ = "signing_keys"
    __table_args__ = (
        UniqueConstraint("kid", name="uq_signing_keys_kid"),
        Index("ix_signing_keys_status_deleted_at", "status", "deleted_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    kid: Mapped[str] = mapped_column(String(128), nullable=False)
    public_key: Mapped[str] = mapped_column(String, nullable=False)
    private_key: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[SigningKeyStatus] = mapped_column(
        SAEnum(
            SigningKeyStatus,
            name="signing_key_status",
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
