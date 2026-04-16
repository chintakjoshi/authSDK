"""Add device metadata columns to sessions for admin session management."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20260416_0012"
down_revision = "20260316_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add ip_address, user_agent, last_seen_at, and revoke_reason columns."""
    op.add_column("sessions", sa.Column("ip_address", sa.String(length=45), nullable=True))
    op.add_column("sessions", sa.Column("user_agent", sa.String(length=512), nullable=True))
    op.add_column(
        "sessions",
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("sessions", sa.Column("revoke_reason", sa.String(length=64), nullable=True))


def downgrade() -> None:
    """Drop device metadata columns."""
    op.drop_column("sessions", "revoke_reason")
    op.drop_column("sessions", "last_seen_at")
    op.drop_column("sessions", "user_agent")
    op.drop_column("sessions", "ip_address")
