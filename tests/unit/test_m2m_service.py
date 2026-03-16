"""Unit tests for Step 9 M2M client-credentials service."""

from __future__ import annotations

from datetime import UTC, datetime
from types import MethodType
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.jwt import JWTService
from app.models.oauth_client import OAuthClient
from app.services.m2m_service import M2MService, M2MServiceError


class _SigningKeyStub:
    """Signing-key stub returning one active PEM pair."""

    def __init__(self, private_key_pem: str, public_key_pem: str) -> None:
        self.private_key_pem = private_key_pem
        self.public_key_pem = public_key_pem

    async def get_active_signing_key(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        return type(
            "SigningKeyMaterial",
            (),
            {
                "kid": "kid-1",
                "private_key_pem": self.private_key_pem,
                "public_key_pem": self.public_key_pem,
            },
        )()


def _generate_keypair() -> tuple[str, str]:
    """Generate one PEM-encoded RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


@pytest.fixture
def m2m_service() -> tuple[M2MService, JWTService]:
    """Build M2M service with ephemeral signing material."""
    private_pem, public_pem = _generate_keypair()
    jwt_service = JWTService(private_key_pem=private_pem, public_key_pem=public_pem)
    service = M2MService(
        jwt_service=jwt_service,
        signing_key_service=_SigningKeyStub(private_pem, public_pem),  # type: ignore[arg-type]
    )
    return service, jwt_service


def _build_client(raw_secret: str, scopes: list[str], *, is_active: bool = True) -> OAuthClient:
    """Create one in-memory OAuth client row for service tests."""
    now = datetime.now(UTC)
    return OAuthClient(
        id=uuid4(),
        client_id="client-123",
        client_secret_hash=M2MService.hash_client_secret(raw_secret),
        client_secret_prefix=M2MService.client_secret_prefix(raw_secret),
        name="Billing Worker",
        scopes=scopes,
        role="service",
        is_active=is_active,
        token_ttl_seconds=1200,
        created_at=now,
        updated_at=now,
        deleted_at=None,
        tenant_id=None,
    )


@pytest.mark.asyncio
async def test_authenticate_client_credentials_issues_m2m_token(
    m2m_service: tuple[M2MService, JWTService],
) -> None:
    """Valid client credentials issue an M2M JWT with subset scope."""
    service, jwt_service = m2m_service
    client = _build_client("cs_test_secret", ["billing:read", "billing:write"])

    async def _fake_lookup(self: M2MService, db_session, *, client_id: str) -> OAuthClient | None:  # type: ignore[no-untyped-def]
        del db_session
        assert client_id == "client-123"
        return client

    service._get_client_by_client_id = MethodType(_fake_lookup, service)  # type: ignore[assignment]

    result = await service.authenticate_client_credentials(
        db_session=object(),  # type: ignore[arg-type]
        client_id="client-123",
        client_secret="cs_test_secret",
        scope="billing:read",
    )

    claims = jwt_service.verify_token(result.access_token, expected_type="m2m")
    assert claims["sub"] == "client-123"
    assert claims["role"] == "service"
    assert claims["scope"] == "billing:read"
    assert result.expires_in == 1200
    assert result.scope == "billing:read"


@pytest.mark.asyncio
async def test_authenticate_client_credentials_rejects_invalid_scope(
    m2m_service: tuple[M2MService, JWTService],
) -> None:
    """Requested scopes must be a subset of the client allowlist."""
    service, _ = m2m_service
    client = _build_client("cs_test_secret", ["billing:read"])

    async def _fake_lookup(self: M2MService, db_session, *, client_id: str) -> OAuthClient | None:  # type: ignore[no-untyped-def]
        del db_session, client_id
        return client

    service._get_client_by_client_id = MethodType(_fake_lookup, service)  # type: ignore[assignment]

    with pytest.raises(M2MServiceError) as exc_info:
        await service.authenticate_client_credentials(
            db_session=object(),  # type: ignore[arg-type]
            client_id="client-123",
            client_secret="cs_test_secret",
            scope="billing:write",
        )

    assert exc_info.value.code == "invalid_scope"
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_authenticate_client_credentials_rejects_inactive_client(
    m2m_service: tuple[M2MService, JWTService],
) -> None:
    """Inactive clients fail with 401 and never issue tokens."""
    service, _ = m2m_service
    client = _build_client("cs_test_secret", ["billing:read"], is_active=False)

    async def _fake_lookup(self: M2MService, db_session, *, client_id: str) -> OAuthClient | None:  # type: ignore[no-untyped-def]
        del db_session, client_id
        return client

    service._get_client_by_client_id = MethodType(_fake_lookup, service)  # type: ignore[assignment]

    with pytest.raises(M2MServiceError) as exc_info:
        await service.authenticate_client_credentials(
            db_session=object(),  # type: ignore[arg-type]
            client_id="client-123",
            client_secret="cs_test_secret",
        )

    assert exc_info.value.code == "invalid_credentials"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_authenticate_client_credentials_rejects_invalid_secret(
    m2m_service: tuple[M2MService, JWTService],
) -> None:
    """Invalid client secrets fail with 401."""
    service, _ = m2m_service
    client = _build_client("cs_test_secret", ["billing:read"])

    async def _fake_lookup(self: M2MService, db_session, *, client_id: str) -> OAuthClient | None:  # type: ignore[no-untyped-def]
        del db_session, client_id
        return client

    service._get_client_by_client_id = MethodType(_fake_lookup, service)  # type: ignore[assignment]

    with pytest.raises(M2MServiceError) as exc_info:
        await service.authenticate_client_credentials(
            db_session=object(),  # type: ignore[arg-type]
            client_id="client-123",
            client_secret="cs_wrong_secret",
        )

    assert exc_info.value.code == "invalid_credentials"
    assert exc_info.value.status_code == 401
