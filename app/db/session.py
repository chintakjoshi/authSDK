"""Async SQLAlchemy session and engine configuration."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings, reloadable_singleton


async def _dispose_async_engine(engine: AsyncEngine) -> None:
    """Dispose a previous async engine instance."""
    await engine.dispose()


@reloadable_singleton(cleanup=_dispose_async_engine)
def get_engine() -> AsyncEngine:
    """Build and cache the async SQLAlchemy engine."""
    settings = get_settings()
    return create_async_engine(
        settings.database.url,
        pool_pre_ping=True,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_timeout=settings.database.pool_timeout_seconds,
        pool_recycle=settings.database.pool_recycle_seconds,
    )


@reloadable_singleton
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Build and cache the async session factory."""
    return async_sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session for request-scoped use."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        yield session


async def dispose_engine() -> None:
    """Dispose the SQLAlchemy engine and close pooled connections."""
    await get_engine().dispose()
