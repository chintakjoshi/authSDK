"""Add auth_time to sessions for re-authentication."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260314_0008"
down_revision = "20260314_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add auth_time column and backfill existing sessions."""
    op.add_column(
        "sessions",
        sa.Column(
            "auth_time",
            sa.DateTime(timezone=True),
            nullable=True,
            server_default=sa.func.now(),
        ),
    )
    op.execute(sa.text("UPDATE sessions SET auth_time = created_at WHERE auth_time IS NULL"))
    op.alter_column("sessions", "auth_time", nullable=False, server_default=None)


def downgrade() -> None:
    """Drop auth_time column from sessions."""
    op.drop_column("sessions", "auth_time")
