"""Add display name to API keys for admin API compatibility."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260316_0011"
down_revision = "20260316_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add api_keys.name and backfill it from the legacy service column."""
    op.add_column("api_keys", sa.Column("name", sa.String(length=128), nullable=True))
    op.execute("UPDATE api_keys SET name = service WHERE name IS NULL")
    op.alter_column("api_keys", "name", existing_type=sa.String(length=128), nullable=False)


def downgrade() -> None:
    """Remove api_keys.name."""
    op.drop_column("api_keys", "name")
