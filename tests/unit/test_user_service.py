"""Unit tests for user service password authentication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.models.user import User
from app.services.user_service import UserService, UserServiceError


@dataclass
class _FakeResult:
    """Simple scalar result stub for async session tests."""

    user: User | None

    def scalar_one_or_none(self) -> User | None:
        """Return the configured scalar value."""
        return self.user


class _FakeSession:
    """Minimal async session stub returning a fixed user."""

    def __init__(self, user: User | None) -> None:
        self._user = user

    async def execute(self, _statement: object) -> _FakeResult:
        """Mimic AsyncSession.execute for unit tests."""
        return _FakeResult(user=self._user)


class _DeleteResult:
    """Simple delete-result stub exposing rowcount."""

    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount


class _DeletingSession:
    """Minimal async session stub for hard-delete identity tests."""

    def __init__(self, rowcount: int) -> None:
        self.rowcount = rowcount
        self.commit_calls = 0

    async def execute(self, _statement: object) -> _DeleteResult:
        """Return a fixed delete rowcount."""
        return _DeleteResult(self.rowcount)

    async def commit(self) -> None:
        """Capture commit usage."""
        self.commit_calls += 1

    async def rollback(self) -> None:
        """No-op rollback for error-path compatibility."""
        return None


class _MutatingSession:
    """AsyncSession-like stub for successful role updates."""

    def __init__(self, user: User) -> None:
        self._user = user
        self.flush_calls = 0
        self.commit_calls = 0

    async def execute(self, _statement: object) -> _FakeResult:
        return _FakeResult(user=self._user)

    async def flush(self) -> None:
        self.flush_calls += 1

    async def commit(self) -> None:
        self.commit_calls += 1


class _AuditRecorder:
    """Audit stub that records calls for ordering assertions."""

    def __init__(self, session: _MutatingSession) -> None:
        self._session = session
        self.calls: list[dict[str, object]] = []

    async def record(self, **kwargs: object) -> None:
        assert self._session.commit_calls == 1
        self.calls.append(kwargs)


def _build_user(password_hash: str | None) -> User:
    """Create a lightweight user model for service tests."""
    now = datetime.now(UTC)
    return User(
        id=uuid4(),
        email="user@example.com",
        password_hash=password_hash,
        is_active=True,
        role="user",
        created_at=now,
        updated_at=now,
        deleted_at=None,
        tenant_id=None,
    )


@pytest.mark.asyncio
async def test_authenticate_user_success() -> None:
    """Returns the user when password is valid."""
    service = UserService()
    password_hash = service.hash_password("my-secure-password")
    user = _build_user(password_hash=password_hash)

    authenticated = await service.authenticate_user(
        db_session=_FakeSession(user=user),  # type: ignore[arg-type]
        email="user@example.com",
        password="my-secure-password",
    )

    assert authenticated is not None
    assert authenticated.id == user.id


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password_returns_none() -> None:
    """Returns None when password does not match."""
    service = UserService()
    password_hash = service.hash_password("my-secure-password")
    user = _build_user(password_hash=password_hash)

    authenticated = await service.authenticate_user(
        db_session=_FakeSession(user=user),  # type: ignore[arg-type]
        email="user@example.com",
        password="wrong-password",
    )

    assert authenticated is None


@pytest.mark.asyncio
async def test_authenticate_user_missing_user_returns_none() -> None:
    """Returns None when no user exists for the email."""
    service = UserService()
    authenticated = await service.authenticate_user(
        db_session=_FakeSession(user=None),  # type: ignore[arg-type]
        email="missing@example.com",
        password="irrelevant-password",
    )

    assert authenticated is None


@pytest.mark.asyncio
async def test_authenticate_user_without_password_hash_returns_none() -> None:
    """Returns None when user has no password hash set."""
    service = UserService()
    user = _build_user(password_hash=None)

    authenticated = await service.authenticate_user(
        db_session=_FakeSession(user=user),  # type: ignore[arg-type]
        email="user@example.com",
        password="any-password",
    )

    assert authenticated is None


def test_hash_password_and_verify_round_trip() -> None:
    """Hashed password is not plaintext and verifies correctly."""
    service = UserService()
    password = "my-secure-password"
    password_hash = service.hash_password(password)

    assert password_hash != password
    assert service.verify_password(password=password, password_hash=password_hash) is True
    assert (
        service.verify_password(password="not-the-password", password_hash=password_hash) is False
    )


@pytest.mark.asyncio
async def test_update_role_requires_admin_actor() -> None:
    """Role updates are forbidden for non-admin actors."""
    service = UserService()
    with pytest.raises(UserServiceError) as exc_info:
        await service.update_role(
            db_session=_FakeSession(user=None),  # type: ignore[arg-type]
            actor_role="user",
            actor_id=str(uuid4()),
            user_id=uuid4(),
            new_role="admin",
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "insufficient_role"


@pytest.mark.asyncio
async def test_update_role_commits_before_recording_success_audit() -> None:
    """Successful role changes commit the mutation before writing the success audit."""
    service = UserService()
    user = _build_user(password_hash=service.hash_password("Password123!"))
    user.role = "user"
    db_session = _MutatingSession(user)
    audit_service = _AuditRecorder(db_session)

    updated = await service.update_role(
        db_session=db_session,  # type: ignore[arg-type]
        actor_role="admin",
        actor_id=str(uuid4()),
        user_id=user.id,
        new_role="admin",
        request=object(),  # type: ignore[arg-type]
        audit_service=audit_service,  # type: ignore[arg-type]
    )

    assert updated.role == "admin"
    assert db_session.flush_calls == 1
    assert db_session.commit_calls == 1
    assert audit_service.calls[0]["metadata"] == {"old_role": "user", "new_role": "admin"}


@pytest.mark.asyncio
async def test_delete_user_requires_admin_actor() -> None:
    """User deletion is forbidden for non-admin actors."""
    service = UserService()
    with pytest.raises(UserServiceError) as exc_info:
        await service.delete_user(
            db_session=_FakeSession(user=None),  # type: ignore[arg-type]
            actor_role="user",
            user_id=uuid4(),
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "insufficient_role"


@pytest.mark.asyncio
async def test_hard_delete_identities_returns_deleted_row_count() -> None:
    """Hard-deleting identities returns the number of removed rows."""
    service = UserService()
    db_session = _DeletingSession(rowcount=2)

    deleted_count = await service.hard_delete_identities(
        db_session=db_session,  # type: ignore[arg-type]
        user_id=uuid4(),
    )

    assert deleted_count == 2
    assert db_session.commit_calls == 1
