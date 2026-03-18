"""Additional unit tests for signing-key lifecycle edge cases."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet

from app.core.jwt import JWTService
from app.core.signing_keys import SigningKeyService
from app.models.signing_key import SigningKey, SigningKeyStatus


class _ScalarResult:
    """Scalar result stub mirroring SQLAlchemy's scalar helpers."""

    def __init__(self, value: object) -> None:
        self._value = value

    def scalars(self) -> _ScalarResult:
        return self

    def all(self) -> list[object]:
        return list(self._value) if isinstance(self._value, list) else []

    def scalar_one_or_none(self) -> object:
        return self._value


class _DBSessionStub:
    """DB session stub returning queued execute payloads."""

    def __init__(self, execute_results: list[object] | None = None) -> None:
        self._execute_results = list(execute_results or [])
        self.added: list[object] = []
        self.flush_count = 0

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        if self._execute_results:
            return _ScalarResult(self._execute_results.pop(0))
        return _ScalarResult(None)

    def add(self, row: object) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        self.flush_count += 1


def _service() -> SigningKeyService:
    private_pem, public_pem = SigningKeyService.generate_rsa_keypair()
    return SigningKeyService(
        fallback_private_key_pem=private_pem,
        fallback_public_key_pem=public_pem,
        encryption_key=Fernet.generate_key().decode("utf-8"),
    )


def _row(
    *, service: SigningKeyService, status: SigningKeyStatus, kid: str | None = None
) -> SigningKey:
    private_pem, public_pem = SigningKeyService.generate_rsa_keypair()
    return SigningKey(
        kid=kid or JWTService.calculate_kid(public_pem),
        public_key=public_pem,
        private_key=service._encrypt_private_key(private_pem),
        status=status,
        activated_at=datetime.now(UTC),
        retired_at=None,
    )


@pytest.mark.asyncio
async def test_get_verification_keys_jwks_and_rotate_cover_bootstrap_paths(monkeypatch) -> None:
    """Signing-key service bootstraps fallback keys for verification, JWKS, and rotation."""
    service = _service()
    fallback_row = SigningKey(
        kid=JWTService.calculate_kid(service._fallback_public_key_pem),
        public_key=service._fallback_public_key_pem,
        private_key=service._encrypt_private_key(service._fallback_private_key_pem),
        status=SigningKeyStatus.ACTIVE,
        activated_at=datetime.now(UTC),
        retired_at=None,
    )
    verification_batches = [[], [fallback_row], [fallback_row]]

    async def _fetch_non_retired(db_session):  # type: ignore[no-untyped-def]
        del db_session
        return verification_batches.pop(0)

    async def _bootstrap(db_session):  # type: ignore[no-untyped-def]
        del db_session
        return fallback_row

    monkeypatch.setattr(service, "_fetch_non_retired_rows", _fetch_non_retired)
    monkeypatch.setattr(service, "_bootstrap_fallback_active_key", _bootstrap)
    public_keys = await service.get_verification_public_keys(_DBSessionStub())  # type: ignore[arg-type]
    jwks = await service.get_jwks_payload(_DBSessionStub())  # type: ignore[arg-type]
    assert public_keys == {fallback_row.kid: fallback_row.public_key}
    assert jwks["keys"][0]["kid"] == fallback_row.kid

    active_row = _row(service=service, status=SigningKeyStatus.ACTIVE)
    fetch_calls = {"count": 0}

    async def _fetch_active(db_session):  # type: ignore[no-untyped-def]
        del db_session
        fetch_calls["count"] += 1
        return None if fetch_calls["count"] == 1 else active_row

    monkeypatch.setattr(service, "_fetch_single_active_row", _fetch_active)
    monkeypatch.setattr(service, "_bootstrap_fallback_active_key", _bootstrap)
    with pytest.raises(ValueError, match="collides"):
        monkeypatch.setattr(
            service,
            "generate_rsa_keypair",
            lambda: (service._fallback_private_key_pem, service._fallback_public_key_pem),
        )
        await service.rotate_signing_key(_DBSessionStub(), rotation_overlap_seconds=60)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_fetch_active_bootstrap_revival_and_decrypt_edge_cases() -> None:
    """Signing-key helper methods reject invalid active sets and revive retired fallback rows."""
    service = _service()
    first = _row(service=service, status=SigningKeyStatus.ACTIVE, kid="kid-1")
    second = _row(service=service, status=SigningKeyStatus.ACTIVE, kid="kid-2")
    with pytest.raises(ValueError, match="Multiple active"):
        await service._fetch_single_active_row(_DBSessionStub([[first, second]]))  # type: ignore[arg-type]

    retired_fallback = SigningKey(
        kid=JWTService.calculate_kid(service._fallback_public_key_pem),
        public_key=service._fallback_public_key_pem,
        private_key=service._encrypt_private_key(service._fallback_private_key_pem),
        status=SigningKeyStatus.RETIRED,
        activated_at=datetime.now(UTC),
        retired_at=datetime.now(UTC),
    )
    db_session = _DBSessionStub([retired_fallback])
    revived = await service._bootstrap_fallback_active_key(db_session)  # type: ignore[arg-type]
    assert revived.status == SigningKeyStatus.ACTIVE
    assert revived.retired_at is None
    assert db_session.flush_count == 1

    assert service._decrypt_private_key("plaintext-private-key") == "plaintext-private-key"
    with pytest.raises(ValueError, match="Unable to decrypt"):
        service._decrypt_private_key("enc1:not-a-real-fernet-token")
