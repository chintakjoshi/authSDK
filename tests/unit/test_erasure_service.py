"""Unit tests for the GDPR erasure service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.core.sessions import SessionStateError
from app.services.api_key_service import APIKeyServiceError
from app.services.erasure_service import ErasureService, ErasureServiceError
from app.services.otp_service import OTPServiceError


@dataclass
class _UserStub:
    id: object
    email: str
    password_hash: str | None = "hashed"
    is_active: bool = True
    email_verified: bool = True
    email_otp_enabled: bool = True
    email_verify_token_hash: str | None = "verify"
    email_verify_token_expires: datetime | None = datetime.now(UTC)
    password_reset_token_hash: str | None = "reset"
    password_reset_token_expires: datetime | None = datetime.now(UTC)
    deleted_at: datetime | None = None
    role: str = "user"


@dataclass
class _RevokedKeyStub:
    id: object


class _DBSessionStub:
    def __init__(self) -> None:
        self.flush_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    async def flush(self) -> None:
        self.flush_count += 1

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        self.rollback_count += 1


class _UserServiceStub:
    def __init__(self) -> None:
        self.deleted_identity_count = 2

    async def ensure_admin_removal_allowed(self, *, db_session, user):  # type: ignore[no-untyped-def]
        del db_session, user

    async def hard_delete_identities(self, *, db_session, user_id, commit):  # type: ignore[no-untyped-def]
        del db_session, user_id, commit
        return self.deleted_identity_count


class _SessionServiceStub:
    def __init__(self) -> None:
        self.raise_error: SessionStateError | None = None

    async def revoke_user_sessions(self, *, db_session, user_id, commit):  # type: ignore[no-untyped-def]
        del db_session, user_id, commit
        if self.raise_error is not None:
            raise self.raise_error
        return [uuid4()]


class _OTPServiceStub:
    def __init__(self) -> None:
        self.raise_error: OTPServiceError | None = None
        self.cleared: list[str] = []

    async def clear_user_otp_state(self, user_id: str) -> None:
        if self.raise_error is not None:
            raise self.raise_error
        self.cleared.append(user_id)


class _APIKeyServiceStub:
    def __init__(self) -> None:
        self.raise_error: APIKeyServiceError | None = None

    async def revoke_user_keys(self, *, db_session, user_id, commit):  # type: ignore[no-untyped-def]
        del db_session, user_id, commit
        if self.raise_error is not None:
            raise self.raise_error
        return [_RevokedKeyStub(id=uuid4())]


def _service(
    *,
    user_service: _UserServiceStub | None = None,
    session_service: _SessionServiceStub | None = None,
    otp_service: _OTPServiceStub | None = None,
    api_key_service: _APIKeyServiceStub | None = None,
) -> ErasureService:
    return ErasureService(
        user_service=user_service or _UserServiceStub(),  # type: ignore[arg-type]
        session_service=session_service or _SessionServiceStub(),  # type: ignore[arg-type]
        otp_service=otp_service or _OTPServiceStub(),  # type: ignore[arg-type]
        api_key_service=api_key_service or _APIKeyServiceStub(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_erase_user_rejects_missing_and_already_erased_accounts() -> None:
    """Erasure fails with stable contracts for missing or already-erased users."""
    service = _service()

    async def _missing(**kwargs: object) -> None:
        return None

    service._get_user_for_update = _missing  # type: ignore[assignment]

    with pytest.raises(ErasureServiceError) as exc_info:
        await service.erase_user(db_session=_DBSessionStub(), user_id=uuid4())  # type: ignore[arg-type]
    assert exc_info.value.code == "invalid_user"

    user_id = uuid4()
    erased_user = _UserStub(id=user_id, email=f"deleted_{user_id}@erased.invalid")

    async def _erased(**kwargs: object) -> _UserStub:
        return erased_user

    service._get_user_for_update = _erased  # type: ignore[assignment]
    with pytest.raises(ErasureServiceError) as exc_info:
        await service.erase_user(db_session=_DBSessionStub(), user_id=user_id)  # type: ignore[arg-type]
    assert exc_info.value.code == "already_erased"


@pytest.mark.asyncio
async def test_erase_user_successfully_scrubs_and_revokes_all_paths() -> None:
    """Successful erasure anonymizes the user and commits all revocations."""
    user_id = uuid4()
    user = _UserStub(id=user_id, email="erase@example.com")
    db_session = _DBSessionStub()
    otp_service = _OTPServiceStub()
    service = _service(otp_service=otp_service)

    async def _found(**kwargs: object) -> _UserStub:
        return user

    service._get_user_for_update = _found  # type: ignore[assignment]

    result = await service.erase_user(db_session=db_session, user_id=user_id)  # type: ignore[arg-type]

    assert result.user_id == user_id
    assert result.anonymized_email == f"deleted_{user_id}@erased.invalid"
    assert user.email == f"deleted_{user_id}@erased.invalid"
    assert user.password_hash is None
    assert user.is_active is False
    assert user.deleted_at is not None
    assert otp_service.cleared == [str(user_id)]
    assert db_session.commit_count == 1


@pytest.mark.asyncio
async def test_erase_user_rolls_back_mapped_backend_failures() -> None:
    """Mapped collaborator failures roll back and preserve their error contracts."""
    user_id = uuid4()
    user = _UserStub(id=user_id, email="erase@example.com")
    db_session = _DBSessionStub()
    api_key_service = _APIKeyServiceStub()
    api_key_service.raise_error = APIKeyServiceError("boom", "invalid_credentials", 400)
    service = _service(api_key_service=api_key_service)

    async def _found(**kwargs: object) -> _UserStub:
        return user

    service._get_user_for_update = _found  # type: ignore[assignment]

    with pytest.raises(ErasureServiceError) as exc_info:
        await service.erase_user(db_session=db_session, user_id=user_id)  # type: ignore[arg-type]

    assert exc_info.value.code == "invalid_credentials"
    assert db_session.rollback_count == 1
