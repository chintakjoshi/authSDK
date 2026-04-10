"""Async SQLAlchemy session and engine configuration."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings
from app.service_registry import registry, service_cached


@service_cached
def get_engine() -> AsyncEngine:
    """Build and cache the async SQLAlchemy engine."""
    settings = get_settings()
    engine = create_async_engine(settings.database.url, pool_pre_ping=True)
    registry.register_dispose(get_engine._registry_key, engine.dispose)
    return engine


@service_cached
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
