"""Immutable audit event ORM model."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Index, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditActorType(str, Enum):
    """Allowed actor types for audit events."""

    USER = "user"
    SERVICE = "service"
    ADMIN = "admin"
    SYSTEM = "system"


def _actor_type_values(enum_cls: type[AuditActorType]) -> list[str]:
    """Store enum values instead of enum member names."""
    return [member.value for member in enum_cls]


class AuditEvent(Base):
    """Append-only audit event record for auth and security actions."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_created_at", "created_at"),
        Index("ix_audit_events_event_type_created_at", "event_type", "created_at"),
        Index("ix_audit_events_actor_id_created_at", "actor_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    actor_type: Mapped[AuditActorType] = mapped_column(
        SAEnum(
            AuditActorType,
            name="audit_actor_type",
            values_callable=_actor_type_values,
            validate_strings=True,
        ),
        nullable=False,
    )
    target_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    target_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
