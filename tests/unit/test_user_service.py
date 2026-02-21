"""Unit tests for user service password authentication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.models.user import User
from app.services.user_service import UserService


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


def _build_user(password_hash: str | None) -> User:
    """Create a lightweight user model for service tests."""
    now = datetime.now(UTC)
    return User(
        id=uuid4(),
        email="user@example.com",
        password_hash=password_hash,
        is_active=True,
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
