"""Add role claim column to users."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260221_0004"
down_revision = "20260221_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add users.role with constrained values and default."""
    op.add_column(
        "users",
        sa.Column("role", sa.String(length=16), nullable=False, server_default="user"),
    )
    op.create_check_constraint(
        "ck_users_role_allowed",
        "users",
        "role IN ('admin', 'user', 'service')",
    )


def downgrade() -> None:
    """Drop users.role and its check constraint."""
    op.drop_constraint("ck_users_role_allowed", "users", type_="check")
    op.drop_column("users", "role")
