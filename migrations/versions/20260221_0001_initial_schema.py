"""Initial auth service schema."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260221_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply the initial schema migration."""
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
    )
    op.create_index("ix_users_email_deleted_at", "users", ["email", "deleted_at"], unique=False)
    op.create_index(op.f("uq_users_email"), "users", ["email"], unique=True)

    op.create_table(
        "user_identities",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("provider_user_id", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_identities_user_id_users"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_identities"),
        sa.UniqueConstraint(
            "provider", "provider_user_id", name="uq_user_identities_provider_subject"
        ),
    )
    op.create_index(
        "ix_user_identities_user_id_deleted_at",
        "user_identities",
        ["user_id", "deleted_at"],
        unique=False,
    )

    op.create_table(
        "sessions",
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hashed_refresh_token", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_sessions_user_id_users"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("session_id", name="pk_sessions"),
        sa.UniqueConstraint("hashed_refresh_token", name=op.f("uq_sessions_hashed_refresh_token")),
        sa.UniqueConstraint("id", name=op.f("uq_sessions_id")),
    )
    op.create_index("ix_sessions_id", "sessions", ["id"], unique=False)
    op.create_index(
        "ix_sessions_user_id_deleted_at", "sessions", ["user_id", "deleted_at"], unique=False
    )

    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("service", sa.String(length=128), nullable=False),
        sa.Column("hashed_key", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=8), nullable=False),
        sa.Column("scope", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_api_keys_user_id_users"), ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.UniqueConstraint("hashed_key", name=op.f("uq_api_keys_hashed_key")),
    )
    op.create_index(op.f("ix_api_keys_hashed_key"), "api_keys", ["hashed_key"], unique=True)
    op.create_index(
        "ix_api_keys_user_id_deleted_at", "api_keys", ["user_id", "deleted_at"], unique=False
    )


def downgrade() -> None:
    """Revert the initial schema migration."""
    op.drop_index("ix_api_keys_user_id_deleted_at", table_name="api_keys")
    op.drop_index(op.f("ix_api_keys_hashed_key"), table_name="api_keys")
    op.drop_table("api_keys")

    op.drop_index("ix_sessions_user_id_deleted_at", table_name="sessions")
    op.drop_index("ix_sessions_id", table_name="sessions")
    op.drop_table("sessions")

    op.drop_index("ix_user_identities_user_id_deleted_at", table_name="user_identities")
    op.drop_table("user_identities")

    op.drop_index(op.f("uq_users_email"), table_name="users")
    op.drop_index("ix_users_email_deleted_at", table_name="users")
    op.drop_table("users")
