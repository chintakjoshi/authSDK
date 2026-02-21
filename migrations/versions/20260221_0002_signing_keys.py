"""Add signing key versioning table and seed active key from env fallback."""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from cryptography.fernet import Fernet
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "20260221_0002"
down_revision = "20260221_0001"
branch_labels = None
depends_on = None

_ENCRYPTION_PREFIX = "v1:"


def _derive_fernet_key(encryption_key: str | None, fallback_private_key_pem: str) -> bytes:
    """Derive fernet key from explicit config value or fallback private key."""
    source = encryption_key or fallback_private_key_pem
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _encrypt_private_key(
    private_key_pem: str, encryption_key: str | None, fallback_private_key_pem: str
) -> str:
    """Encrypt private key value for at-rest persistence."""
    fernet = Fernet(_derive_fernet_key(encryption_key, fallback_private_key_pem))
    encrypted = fernet.encrypt(private_key_pem.encode("utf-8")).decode("utf-8")
    return f"{_ENCRYPTION_PREFIX}{encrypted}"


def _calculate_kid(public_key_pem: str) -> str:
    """Compute deterministic key ID from public key material."""
    digest = hashlib.sha256(public_key_pem.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")


def upgrade() -> None:
    """Create signing_keys table and migrate env-backed key as first active key."""
    op.create_table(
        "signing_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kid", sa.String(length=128), nullable=False),
        sa.Column("public_key", sa.String(), nullable=False),
        sa.Column("private_key", sa.String(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("active", "retiring", "retired", name="signing_key_status"),
            nullable=False,
        ),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_signing_keys"),
        sa.UniqueConstraint("kid", name="uq_signing_keys_kid"),
    )
    op.create_index(
        "ix_signing_keys_status_deleted_at",
        "signing_keys",
        ["status", "deleted_at"],
        unique=False,
    )

    private_key_pem = os.environ.get("JWT__PRIVATE_KEY_PEM", "").strip()
    public_key_pem = os.environ.get("JWT__PUBLIC_KEY_PEM", "").strip()
    encryption_key = os.environ.get("SIGNING_KEYS__ENCRYPTION_KEY")
    if private_key_pem and public_key_pem:
        signing_keys_table = sa.table(
            "signing_keys",
            sa.column("id", postgresql.UUID(as_uuid=True)),
            sa.column("kid", sa.String(length=128)),
            sa.column("public_key", sa.String()),
            sa.column("private_key", sa.String()),
            sa.column(
                "status",
                sa.Enum("active", "retiring", "retired", name="signing_key_status"),
            ),
            sa.column("activated_at", sa.DateTime(timezone=True)),
            sa.column("retired_at", sa.DateTime(timezone=True)),
            sa.column("created_at", sa.DateTime(timezone=True)),
            sa.column("updated_at", sa.DateTime(timezone=True)),
            sa.column("deleted_at", sa.DateTime(timezone=True)),
            sa.column("tenant_id", postgresql.UUID(as_uuid=True)),
        )
        now = datetime.now(UTC)
        op.bulk_insert(
            signing_keys_table,
            [
                {
                    "id": uuid.uuid4(),
                    "kid": _calculate_kid(public_key_pem),
                    "public_key": public_key_pem,
                    "private_key": _encrypt_private_key(
                        private_key_pem=private_key_pem,
                        encryption_key=encryption_key,
                        fallback_private_key_pem=private_key_pem,
                    ),
                    "status": "active",
                    "activated_at": now,
                    "retired_at": None,
                    "created_at": now,
                    "updated_at": now,
                    "deleted_at": None,
                    "tenant_id": None,
                }
            ],
        )


def downgrade() -> None:
    """Drop signing_keys table and status enum."""
    op.drop_index("ix_signing_keys_status_deleted_at", table_name="signing_keys")
    op.drop_table("signing_keys")
    op.execute("DROP TYPE IF EXISTS signing_key_status")
