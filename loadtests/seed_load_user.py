"""Seed or update a password-login user for Locust scenarios."""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import func, select

from app.db.session import get_session_factory
from app.models.user import User
from app.services.user_service import UserService


async def seed_user(email: str, password: str) -> None:
    """Create or update load-test user credentials."""
    session_factory = get_session_factory()
    user_service = UserService()

    async with session_factory() as session:
        statement = select(User).where(
            func.lower(User.email) == email.lower(),
            User.deleted_at.is_(None),
        )
        existing = (await session.execute(statement)).scalar_one_or_none()

        password_hash = user_service.hash_password(password)
        if existing is None:
            session.add(
                User(
                    email=email,
                    password_hash=password_hash,
                    is_active=True,
                )
            )
            await session.commit()
            print(f"created load-test user: {email}")
            return

        existing.password_hash = password_hash
        existing.is_active = True
        await session.commit()
        print(f"updated load-test user password: {email}")


def _parse_args() -> argparse.Namespace:
    """Parse CLI options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", default="loadtest@example.com")
    parser.add_argument("--password", default="Password123!")
    return parser.parse_args()


def main() -> None:
    """Entrypoint."""
    args = _parse_args()
    asyncio.run(seed_user(email=args.email, password=args.password))


if __name__ == "__main__":
    main()
