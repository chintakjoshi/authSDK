"""Unit tests for API key core and service logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import MethodType
from uuid import uuid4

import pytest

from app.core.api_keys import APIKeyCore
from app.models.api_key import APIKey
from app.services.api_key_service import APIKeyIntrospectionResult, APIKeyService


class _FakeDBSession:
    """Minimal DB session stub for API key service tests."""

    async def execute(self, _statement: object) -> object:
        """Unsupported default execute for tests."""
        raise AssertionError("execute should not be called directly in these tests")

    async def flush(self) -> None:
        """No-op flush."""
        return None

    async def commit(self) -> None:
        """No-op commit."""
        return None

    async def rollback(self) -> None:
        """No-op rollback."""
        return None


def _api_key_row(
    *,
    hashed_key: str,
    revoked_at: datetime | None = None,
    expires_at: datetime | None = None,
    scope: str = "svc:read,svc:write",
) -> APIKey:
    """Build in-memory API key row."""
    now = datetime.now(UTC)
    return APIKey(
        id=uuid4(),
        user_id=uuid4(),
        service="service-a",
        hashed_key=hashed_key,
        key_prefix="sk_abc12",
        scope=scope,
        expires_at=expires_at,
        revoked_at=revoked_at,
        created_at=now,
        updated_at=now,
        deleted_at=None,
        tenant_id=None,
    )


def test_core_generate_key_format() -> None:
    """Generated API key matches required sk_ format."""
    core = APIKeyCore()
    raw_key = core.generate_raw_key()
    assert core.is_valid_format(raw_key) is True
    assert raw_key.startswith("sk_")
    assert len(core.key_prefix(raw_key)) == 8


@pytest.mark.asyncio
async def test_introspect_invalid_format_returns_invalid_code() -> None:
    """Malformed key immediately returns invalid_api_key."""
    service = APIKeyService(core=APIKeyCore())
    result = await service.introspect(db_session=_FakeDBSession(), raw_key="bad-key")  # type: ignore[arg-type]
    assert result == APIKeyIntrospectionResult(valid=False, code="invalid_api_key")


@pytest.mark.asyncio
async def test_introspect_missing_key_returns_invalid_code() -> None:
    """Unknown hashed key returns invalid_api_key."""
    service = APIKeyService(core=APIKeyCore())

    async def _fake_get_by_hash(
        self: APIKeyService,
        db_session: _FakeDBSession,
        key_hash: str,
        for_update: bool,
    ) -> APIKey | None:
        return None

    service._get_key_by_hash = MethodType(_fake_get_by_hash, service)  # type: ignore[assignment]
    result = await service.introspect(
        db_session=_FakeDBSession(),  # type: ignore[arg-type]
        raw_key="sk_valid_key_value",
    )
    assert result == APIKeyIntrospectionResult(valid=False, code="invalid_api_key")


@pytest.mark.asyncio
async def test_introspect_revoked_key_returns_revoked_code() -> None:
    """Revoked key returns revoked_api_key."""
    core = APIKeyCore()
    service = APIKeyService(core=core)
    raw_key = "sk_test_raw_key_value"
    row = _api_key_row(
        hashed_key=core.hash_key(raw_key),
        revoked_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    async def _fake_get_by_hash(
        self: APIKeyService,
        db_session: _FakeDBSession,
        key_hash: str,
        for_update: bool,
    ) -> APIKey | None:
        return row

    service._get_key_by_hash = MethodType(_fake_get_by_hash, service)  # type: ignore[assignment]
    result = await service.introspect(db_session=_FakeDBSession(), raw_key=raw_key)  # type: ignore[arg-type]
    assert result == APIKeyIntrospectionResult(valid=False, code="revoked_api_key")


@pytest.mark.asyncio
async def test_introspect_expired_key_returns_expired_code() -> None:
    """Expired key returns expired_api_key."""
    core = APIKeyCore()
    service = APIKeyService(core=core)
    raw_key = "sk_test_raw_key_value"
    row = _api_key_row(
        hashed_key=core.hash_key(raw_key),
        revoked_at=None,
        expires_at=datetime.now(UTC) - timedelta(seconds=10),
    )

    async def _fake_get_by_hash(
        self: APIKeyService,
        db_session: _FakeDBSession,
        key_hash: str,
        for_update: bool,
    ) -> APIKey | None:
        return row

    service._get_key_by_hash = MethodType(_fake_get_by_hash, service)  # type: ignore[assignment]
    result = await service.introspect(db_session=_FakeDBSession(), raw_key=raw_key)  # type: ignore[arg-type]
    assert result == APIKeyIntrospectionResult(valid=False, code="expired_api_key")


@pytest.mark.asyncio
async def test_introspect_valid_key_returns_contract_payload() -> None:
    """Valid key returns contract payload fields."""
    core = APIKeyCore()
    service = APIKeyService(core=core)
    raw_key = "sk_test_raw_key_value"
    row = _api_key_row(
        hashed_key=core.hash_key(raw_key),
        revoked_at=None,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        scope="svc:read, svc:write",
    )

    async def _fake_get_by_hash(
        self: APIKeyService,
        db_session: _FakeDBSession,
        key_hash: str,
        for_update: bool,
    ) -> APIKey | None:
        return row

    service._get_key_by_hash = MethodType(_fake_get_by_hash, service)  # type: ignore[assignment]
    result = await service.introspect(db_session=_FakeDBSession(), raw_key=raw_key)  # type: ignore[arg-type]
    assert result.valid is True
    assert result.code is None
    assert result.key_id == str(row.id)
    assert result.user_id == str(row.user_id)
    assert result.scopes == ["svc:read", "svc:write"]
