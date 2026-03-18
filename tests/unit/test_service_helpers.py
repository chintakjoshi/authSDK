"""Additional helper-focused service tests for coverage gaps."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.jwt import JWTService
from app.services.api_key_service import APIKeyService, get_api_key_service
from app.services.m2m_service import M2MService, M2MServiceError
from app.services.user_service import UserService, UserServiceError


class _APICoreStub:
    def generate_raw_key(self) -> str:
        return "ak_test_secret"

    def hash_key(self, raw_key: str) -> str:
        return f"hash::{raw_key}"

    def key_prefix(self, raw_key: str) -> str:
        return raw_key[:8]

    def is_valid_format(self, raw_key: str) -> bool:
        return raw_key.startswith("ak_")

    def hash_matches(self, stored_hash: str, raw_key: str) -> bool:
        return stored_hash == f"hash::{raw_key}"

    def scopes_from_storage(self, scope: str) -> list[str]:
        return [item for item in scope.split(",") if item]


class _DBSessionStub:
    def __init__(self, *, rowcount: int = 0, fail_execute: bool = False) -> None:
        self.rowcount = rowcount
        self.fail_execute = fail_execute
        self.rollback_count = 0
        self.commit_count = 0

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        if self.fail_execute:
            raise RuntimeError("boom")
        return type(
            "Result", (), {"rowcount": self.rowcount, "scalar_one_or_none": lambda self: None}
        )()

    async def rollback(self) -> None:
        self.rollback_count += 1

    async def commit(self) -> None:
        self.commit_count += 1


class _M2MSigningKeyStub:
    async def get_active_signing_key(self, db_session):  # type: ignore[no-untyped-def]
        del db_session
        raise AssertionError("get_active_signing_key should not be called in these helper tests")


def test_api_key_helpers_cover_filter_and_scope_resolution() -> None:
    """API-key helper branches cover derived service names and active/inactive filters."""
    service = APIKeyService(core=_APICoreStub())  # type: ignore[arg-type]
    assert service._resolve_name_and_service(
        name=None, service="billing", scope="billing:read"
    ) == (
        "billing",
        "billing",
    )
    assert service._resolve_name_and_service(
        name="Billing",
        service=None,
        scope="billing:read,orders:write",
    ) == ("Billing", "billing")
    assert service._service_from_scope("   ") is None
    assert (
        service._build_list_statement(
            user_id=None,
            name="svc",
            service="svc",
            scope="svc:read",
            active=True,
        )
        is not None
    )
    assert (
        service._build_list_statement(
            user_id=None,
            name=None,
            service=None,
            scope=None,
            active=False,
        )
        is not None
    )
    assert get_api_key_service() is get_api_key_service()


@pytest.mark.asyncio
async def test_user_service_helpers_cover_admin_guard_and_rollback() -> None:
    """User-service helper paths cover admin-removal checks, dummy verify, and rollback."""
    service = UserService()
    await service.ensure_admin_removal_allowed(
        db_session=object(),  # type: ignore[arg-type]
        user=type("User", (), {"role": "user"})(),
    )

    async def _raise_last_admin(**kwargs):  # type: ignore[no-untyped-def]
        raise UserServiceError("Cannot remove the last admin.", "last_admin_protected", 409)

    service._ensure_last_admin_not_violated = _raise_last_admin  # type: ignore[assignment]
    with pytest.raises(UserServiceError):
        await service.ensure_admin_removal_allowed(
            db_session=object(),  # type: ignore[arg-type]
            user=type("User", (), {"role": "admin"})(),
        )

    db_session = _DBSessionStub(fail_execute=True)
    with pytest.raises(RuntimeError):
        await service.hard_delete_identities(
            db_session=db_session,  # type: ignore[arg-type]
            user_id=uuid4(),
        )
    assert db_session.rollback_count == 1
    service.dummy_verify()


@pytest.mark.asyncio
async def test_m2m_service_validation_and_listing_helpers_cover_edge_cases(monkeypatch) -> None:
    """M2M helpers reject invalid payloads, missing clients, and exhausted client IDs."""
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
    service = M2MService(
        jwt_service=JWTService(private_key_pem=private_pem, public_key_pem=public_pem),
        signing_key_service=_M2MSigningKeyStub(),  # type: ignore[arg-type]
        auth_service_audience="auth-service",
    )

    with pytest.raises(M2MServiceError, match="Invalid client credentials"):
        await service.authenticate_client_credentials(
            db_session=object(),  # type: ignore[arg-type]
            client_id=" ",
            client_secret=" ",
        )
    with pytest.raises(M2MServiceError, match="Client name is required"):
        await service.create_client(
            db_session=object(),  # type: ignore[arg-type]
            name=" ",
            scopes=["svc:read"],
        )
    with pytest.raises(M2MServiceError, match="At least one scope is required"):
        await service.create_client(
            db_session=object(),  # type: ignore[arg-type]
            name="svc",
            scopes=[],
        )
    with pytest.raises(M2MServiceError, match="Invalid token TTL"):
        await service.create_client(
            db_session=object(),  # type: ignore[arg-type]
            name="svc",
            scopes=["svc:read"],
            token_ttl_seconds=0,
        )

    async def _missing_by_id(**kwargs: object) -> None:
        return None

    service._get_client_by_id = _missing_by_id  # type: ignore[assignment]
    with pytest.raises(M2MServiceError, match="Client not found"):
        await service.update_client(
            db_session=object(),  # type: ignore[arg-type]
            client_row_id=uuid4(),
            name="svc",
        )
    with pytest.raises(M2MServiceError, match="Client not found"):
        await service.rotate_client_secret(
            db_session=object(),  # type: ignore[arg-type]
            client_row_id=uuid4(),
        )
    with pytest.raises(M2MServiceError, match="Client not found"):
        await service.delete_client(
            db_session=object(),  # type: ignore[arg-type]
            client_row_id=uuid4(),
        )

    async def _always_exists(**kwargs: object) -> object:
        return object()

    monkeypatch.setattr(service, "_get_client_by_client_id", _always_exists)
    with pytest.raises(RuntimeError, match="Unable to generate unique client ID"):
        await service._generate_unique_client_id(object())  # type: ignore[arg-type]

    assert service._normalize_requested_scopes(None) == []
    assert service._normalize_requested_scopes("svc:read svc:write") == ["svc:read", "svc:write"]
    assert service._build_client_list_statement(active=True) is not None
