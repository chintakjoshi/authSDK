"""Signing key management and rotation primitives."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.jwt import JWTService
from app.models.signing_key import SigningKey, SigningKeyStatus


@dataclass(frozen=True)
class SigningKeyMaterial:
    """Decrypted signing-key material used by JWT issuance and verification."""

    kid: str
    public_key_pem: str
    private_key_pem: str
    status: SigningKeyStatus
    activated_at: datetime
    retired_at: datetime | None


@dataclass(frozen=True)
class SigningKeyRotationResult:
    """Result payload for one rotation operation."""

    new_kid: str
    retiring_kid: str | None


class SigningKeyService:
    """Manage signing key lifecycle with encrypted private-key persistence."""

    _ENCRYPTION_PREFIX = "v1:"

    def __init__(
        self,
        fallback_private_key_pem: str,
        fallback_public_key_pem: str,
        encryption_key: str | None = None,
    ) -> None:
        self._fallback_private_key_pem = fallback_private_key_pem
        self._fallback_public_key_pem = fallback_public_key_pem
        self._fernet = Fernet(self._build_fernet_key(encryption_key, fallback_private_key_pem))

    async def get_active_signing_key(self, db_session: AsyncSession) -> SigningKeyMaterial:
        """Return the currently active signing key, bootstrapping from env fallback if needed."""
        row = await self._fetch_single_active_row(db_session)
        if row is None:
            row = await self._bootstrap_fallback_active_key(db_session)
        return self._material_from_row(row)

    async def get_verification_public_keys(self, db_session: AsyncSession) -> dict[str, str]:
        """Return public keys for active and retiring key verification."""
        rows = await self._fetch_non_retired_rows(db_session)
        if not rows:
            await self._bootstrap_fallback_active_key(db_session)
            rows = await self._fetch_non_retired_rows(db_session)
        return {row.kid: row.public_key for row in rows}

    async def get_jwks_payload(self, db_session: AsyncSession) -> dict[str, list[dict[str, str]]]:
        """Return JWKS payload for all active and retiring keys."""
        public_keys = await self.get_verification_public_keys(db_session)
        jwk_keys = [
            JWTService.build_public_jwk(public_key_pem=public_key, kid=kid)
            for kid, public_key in sorted(public_keys.items())
        ]
        return {"keys": jwk_keys}

    async def rotate_signing_key(
        self,
        db_session: AsyncSession,
        rotation_overlap_seconds: int,
    ) -> SigningKeyRotationResult:
        """Rotate active key and retire overlap-expired retiring keys."""
        now = datetime.now(UTC)
        current_active = await self._fetch_single_active_row(db_session)
        if current_active is None:
            current_active = await self._bootstrap_fallback_active_key(db_session)

        new_private_pem, new_public_pem = self.generate_rsa_keypair()
        new_kid = JWTService.calculate_kid(new_public_pem)

        if current_active.kid == new_kid:
            raise ValueError("Generated key collides with current active key ID.")

        current_active.status = SigningKeyStatus.RETIRING
        new_row = SigningKey(
            kid=new_kid,
            public_key=new_public_pem,
            private_key=self._encrypt_private_key(new_private_pem),
            status=SigningKeyStatus.ACTIVE,
            activated_at=now,
            retired_at=None,
        )
        db_session.add(new_row)
        await db_session.flush()

        await self.retire_expired_keys(
            db_session=db_session,
            rotation_overlap_seconds=rotation_overlap_seconds,
        )
        return SigningKeyRotationResult(new_kid=new_kid, retiring_kid=current_active.kid)

    async def retire_expired_keys(
        self,
        db_session: AsyncSession,
        rotation_overlap_seconds: int,
    ) -> list[str]:
        """Retire keys that have remained in retiring status past overlap duration."""
        cutoff = datetime.now(UTC) - timedelta(seconds=rotation_overlap_seconds)
        statement = select(SigningKey).where(
            SigningKey.status == SigningKeyStatus.RETIRING,
            SigningKey.deleted_at.is_(None),
            SigningKey.updated_at <= cutoff,
        )
        rows = list((await db_session.execute(statement)).scalars().all())
        retired_kids: list[str] = []
        now = datetime.now(UTC)
        for row in rows:
            row.status = SigningKeyStatus.RETIRED
            row.retired_at = now
            retired_kids.append(row.kid)
        if rows:
            await db_session.flush()
        return retired_kids

    async def _fetch_single_active_row(self, db_session: AsyncSession) -> SigningKey | None:
        """Fetch one active non-deleted key row, enforcing single-active invariant."""
        statement = (
            select(SigningKey)
            .where(
                SigningKey.status == SigningKeyStatus.ACTIVE,
                SigningKey.deleted_at.is_(None),
            )
            .order_by(SigningKey.activated_at.desc())
            .with_for_update()
        )
        rows = list((await db_session.execute(statement)).scalars().all())
        if len(rows) > 1:
            raise ValueError("Multiple active signing keys detected.")
        return rows[0] if rows else None

    async def _fetch_non_retired_rows(self, db_session: AsyncSession) -> list[SigningKey]:
        """Fetch active and retiring key rows for verification/JWKS use."""
        statement = (
            select(SigningKey)
            .where(
                SigningKey.status.in_((SigningKeyStatus.ACTIVE, SigningKeyStatus.RETIRING)),
                SigningKey.deleted_at.is_(None),
            )
            .order_by(SigningKey.activated_at.desc())
        )
        return list((await db_session.execute(statement)).scalars().all())

    async def _bootstrap_fallback_active_key(self, db_session: AsyncSession) -> SigningKey:
        """Insert env-backed key as first active row when key table is empty."""
        fallback_kid = JWTService.calculate_kid(self._fallback_public_key_pem)
        existing_statement = select(SigningKey).where(
            SigningKey.kid == fallback_kid,
            SigningKey.deleted_at.is_(None),
        )
        existing = (await db_session.execute(existing_statement)).scalar_one_or_none()
        if existing is not None:
            if existing.status == SigningKeyStatus.RETIRED:
                existing.status = SigningKeyStatus.ACTIVE
                existing.retired_at = None
                await db_session.flush()
            return existing

        row = SigningKey(
            kid=fallback_kid,
            public_key=self._fallback_public_key_pem,
            private_key=self._encrypt_private_key(self._fallback_private_key_pem),
            status=SigningKeyStatus.ACTIVE,
            activated_at=datetime.now(UTC),
            retired_at=None,
        )
        db_session.add(row)
        await db_session.flush()
        return row

    def _material_from_row(self, row: SigningKey) -> SigningKeyMaterial:
        """Convert persisted signing-key row into decrypted material."""
        return SigningKeyMaterial(
            kid=row.kid,
            public_key_pem=row.public_key,
            private_key_pem=self._decrypt_private_key(row.private_key),
            status=row.status,
            activated_at=row.activated_at,
            retired_at=row.retired_at,
        )

    def _encrypt_private_key(self, private_key_pem: str) -> str:
        """Encrypt private key material before persistence."""
        encrypted = self._fernet.encrypt(private_key_pem.encode("utf-8")).decode("utf-8")
        return f"{self._ENCRYPTION_PREFIX}{encrypted}"

    def _decrypt_private_key(self, stored_value: str) -> str:
        """Decrypt persisted private key, supporting legacy plaintext rows."""
        if not stored_value.startswith(self._ENCRYPTION_PREFIX):
            return stored_value
        token = stored_value[len(self._ENCRYPTION_PREFIX) :]
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt signing key material.") from exc

    @staticmethod
    def _build_fernet_key(encryption_key: str | None, fallback_private_key_pem: str) -> bytes:
        """Build a valid fernet key from explicit secret or fallback seed material."""
        source = encryption_key or fallback_private_key_pem
        digest = hashlib.sha256(source.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    @staticmethod
    def generate_rsa_keypair() -> tuple[str, str]:
        """Generate a fresh PEM-encoded RSA keypair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_key_pem = (
            private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )
        return private_key_pem, public_key_pem


@lru_cache
def get_signing_key_service() -> SigningKeyService:
    """Create and cache signing-key service from settings."""
    settings = get_settings()
    return SigningKeyService(
        fallback_private_key_pem=settings.jwt.private_key_pem.get_secret_value(),
        fallback_public_key_pem=settings.jwt.public_key_pem.get_secret_value(),
        encryption_key=(
            settings.signing_keys.encryption_key.get_secret_value()
            if settings.signing_keys.encryption_key is not None
            else None
        ),
    )
