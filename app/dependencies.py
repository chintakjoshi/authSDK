"""Shared FastAPI dependency helpers."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db_session


async def get_database_session() -> AsyncGenerator[AsyncSession, None]:
    """Expose the request-scoped async database session dependency."""
    async for session in get_db_session():
        yield session
