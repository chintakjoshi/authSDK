"""Add password reset fields to users."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0007"
down_revision = "20260305_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add password reset token fields for lifecycle Step 6."""
    op.add_column(
        "users",
        sa.Column("password_reset_token_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("password_reset_token_expires", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Drop password reset token fields from users."""
    op.drop_column("users", "password_reset_token_expires")
    op.drop_column("users", "password_reset_token_hash")
