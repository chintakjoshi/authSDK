"""Add immutable audit events ledger."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260221_0003"
down_revision = "20260221_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create audit_events append-only table."""
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "actor_type",
            sa.Enum("user", "service", "admin", "system", name="audit_actor_type"),
            nullable=False,
        ),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("target_type", sa.String(length=128), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
    )
    op.create_index("ix_audit_events_created_at", "audit_events", ["created_at"], unique=False)
    op.create_index(
        "ix_audit_events_event_type_created_at",
        "audit_events",
        ["event_type", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_actor_id_created_at",
        "audit_events",
        ["actor_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop audit_events table and enum."""
    op.drop_index("ix_audit_events_actor_id_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_created_at", table_name="audit_events")
    op.drop_table("audit_events")
    op.execute("DROP TYPE IF EXISTS audit_actor_type")
