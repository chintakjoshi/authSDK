"""OAuth client ORM model for M2M client-credentials auth."""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, Index, Integer, String, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampTenantMixin


class OAuthClient(Base, TimestampTenantMixin):
    """Machine client credentials allowed to mint M2M access tokens."""

    __tablename__ = "oauth_clients"
    __table_args__ = (
        UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
        Index("ix_oauth_clients_client_id_deleted_at", "client_id", "deleted_at"),
        CheckConstraint(
            "role IN ('service')",
            name="ck_oauth_clients_role_allowed",
        ),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    client_secret_prefix: Mapped[str] = mapped_column(String(8), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String()), nullable=False)
    role: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="service",
        server_default=text("'service'"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    token_ttl_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3600,
        server_default=text("3600"),
    )
