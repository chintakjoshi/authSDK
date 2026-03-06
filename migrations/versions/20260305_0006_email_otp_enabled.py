"""Add email OTP enrollment field to users."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260305_0006"
down_revision = "20260221_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add email_otp_enabled column for Step 5 OTP enrollment."""
    op.add_column(
        "users",
        sa.Column("email_otp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    """Drop email_otp_enabled column from users."""
    op.drop_column("users", "email_otp_enabled")
