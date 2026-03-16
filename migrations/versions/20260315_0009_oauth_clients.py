"""Create oauth_clients table for M2M client credentials."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260315_0009"
down_revision = "20260314_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create oauth_clients table and supporting index/constraint set."""
    op.create_table(
        "oauth_clients",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("client_secret_hash", sa.String(length=64), nullable=False),
        sa.Column("client_secret_prefix", sa.String(length=8), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column(
            "role",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'service'"),
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "token_ttl_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("3600"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint("role IN ('service')", name="ck_oauth_clients_ck_oauth_clients_role_allowed"),
        sa.PrimaryKeyConstraint("id", name="pk_oauth_clients"),
        sa.UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
    )
    op.create_index(
        "ix_oauth_clients_client_id_deleted_at",
        "oauth_clients",
        ["client_id", "deleted_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop oauth_clients table."""
    op.drop_index("ix_oauth_clients_client_id_deleted_at", table_name="oauth_clients")
    op.drop_table("oauth_clients")
