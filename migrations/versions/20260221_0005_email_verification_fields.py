"""Add email verification fields to users."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260221_0005"
down_revision = "20260221_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add email verification columns for signup verification links."""
    op.add_column(
        "users",
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("email_verify_token_hash", sa.String(length=64), nullable=True))
    op.add_column(
        "users",
        sa.Column("email_verify_token_expires", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Drop email verification columns from users."""
    op.drop_column("users", "email_verify_token_expires")
    op.drop_column("users", "email_verify_token_hash")
    op.drop_column("users", "email_verified")
