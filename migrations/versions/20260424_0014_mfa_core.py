"""Introduce MFA core schema and drop legacy email_otp_enabled column.

Adds phone enrollment, MFA toggle columns, and a per-user recovery-code table.
Drops the legacy ``users.email_otp_enabled`` column now that MFA state is
tracked via ``users.mfa_enabled`` and ``users.mfa_primary_method``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260424_0014"
down_revision = "20260416_0013"
branch_labels = None
depends_on = None


_PHONE_LOOKUP_HASH_INDEX = "uq_users_phone_lookup_hash"


def upgrade() -> None:
    """Apply MFA core schema changes."""
    op.add_column(
        "users",
        sa.Column("phone_ciphertext", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("phone_last4", sa.String(length=4), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("phone_lookup_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "phone_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "users",
        sa.Column("phone_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "users",
        sa.Column("mfa_primary_method", sa.String(length=16), nullable=True),
    )
    op.create_check_constraint(
        "ck_users_mfa_primary_method_allowed",
        "users",
        "mfa_primary_method IS NULL OR mfa_primary_method IN ('sms')",
    )
    op.execute(
        sa.text(
            "CREATE UNIQUE INDEX "
            f"{_PHONE_LOOKUP_HASH_INDEX} "
            "ON users (phone_lookup_hash) "
            "WHERE deleted_at IS NULL AND phone_lookup_hash IS NOT NULL"
        )
    )

    op.drop_column("users", "email_otp_enabled")

    op.create_table(
        "user_recovery_codes",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("code_hash", sa.String(length=128), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_recovery_codes")),
        sa.UniqueConstraint(
            "user_id",
            "code_hash",
            name="uq_user_recovery_codes_user_id_code_hash",
        ),
    )
    op.create_index(
        "ix_user_recovery_codes_user_id_used_at",
        "user_recovery_codes",
        ["user_id", "used_at"],
        unique=False,
    )


def downgrade() -> None:
    """Revert MFA core schema changes."""
    op.drop_index(
        "ix_user_recovery_codes_user_id_used_at",
        table_name="user_recovery_codes",
    )
    op.drop_table("user_recovery_codes")

    op.add_column(
        "users",
        sa.Column(
            "email_otp_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    op.execute(sa.text(f"DROP INDEX IF EXISTS {_PHONE_LOOKUP_HASH_INDEX}"))
    op.drop_constraint(
        "ck_users_mfa_primary_method_allowed",
        "users",
        type_="check",
    )
    op.drop_column("users", "mfa_primary_method")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "phone_verified_at")
    op.drop_column("users", "phone_verified")
    op.drop_column("users", "phone_lookup_hash")
    op.drop_column("users", "phone_last4")
    op.drop_column("users", "phone_ciphertext")
