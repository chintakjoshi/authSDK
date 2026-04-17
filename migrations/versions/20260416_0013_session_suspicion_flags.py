"""Persist suspicious-session flags on sessions for admin and self-service views."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260416_0013"
down_revision = "20260416_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add suspicious-session columns with safe defaults for existing rows."""
    op.add_column(
        "sessions",
        sa.Column(
            "is_suspicious",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "sessions",
        sa.Column(
            "suspicious_reasons",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    """Drop suspicious-session columns from sessions."""
    op.drop_column("sessions", "suspicious_reasons")
    op.drop_column("sessions", "is_suspicious")
