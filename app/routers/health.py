"""Health check router endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core.sessions import get_redis_client
from app.db.session import get_engine

router = APIRouter(prefix="/health", tags=["health"])


async def check_postgres_ready() -> bool:
    """Return True when Postgres accepts a lightweight query."""
    try:
        async with get_engine().connect() as connection:
            await connection.execute(select(1))
        return True
    except (SQLAlchemyError, Exception):
        return False


async def check_redis_ready() -> bool:
    """Return True when Redis responds to PING."""
    client = get_redis_client()
    try:
        return bool(await client.ping())
    except (RedisError, Exception):
        return False


@router.get("/live")
async def live() -> dict[str, str]:
    """Liveness probe endpoint."""
    return {"status": "live"}


@router.get("/ready")
async def ready(
    postgres_ready: Annotated[bool, Depends(check_postgres_ready)],
    redis_ready: Annotated[bool, Depends(check_redis_ready)],
) -> dict[str, str]:
    """Readiness probe requiring both Postgres and Redis."""
    if not postgres_ready or not redis_ready:
        raise HTTPException(
            status_code=503,
            detail={"detail": "Service not ready.", "code": "session_expired"},
        )
    return {"status": "ready"}
