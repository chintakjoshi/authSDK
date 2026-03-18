"""Integration tests for brute-force protection and lockout flows."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.core.sessions import get_redis_client


@pytest.mark.asyncio
async def test_password_login_locks_after_fifth_failure(app_factory, user_factory) -> None:
    """Five consecutive password failures lock the account with Retry-After."""
    app: FastAPI = app_factory()
    await user_factory("locked@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        for _ in range(4):
            invalid = await client.post(
                "/auth/login",
                json={"email": "locked@example.com", "password": "WrongPassword123!"},
            )
            assert invalid.status_code == 401
            assert invalid.json()["code"] == "invalid_credentials"

        locked = await client.post(
            "/auth/login",
            json={"email": "locked@example.com", "password": "WrongPassword123!"},
        )
        assert locked.status_code == 401
        assert locked.json()["code"] == "account_locked"
        assert locked.headers["retry-after"] == "60"

        still_locked = await client.post(
            "/auth/login",
            json={"email": "locked@example.com", "password": "Password123!"},
        )
        assert still_locked.status_code == 401
        assert still_locked.json()["code"] == "account_locked"


@pytest.mark.asyncio
async def test_successful_login_clears_failed_attempt_counter(app_factory, user_factory) -> None:
    """A successful login resets accumulated failed attempts for the account."""
    app: FastAPI = app_factory()
    await user_factory("counter-reset@example.com", "Password123!")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        for _ in range(3):
            invalid = await client.post(
                "/auth/login",
                json={"email": "counter-reset@example.com", "password": "WrongPassword123!"},
            )
            assert invalid.status_code == 401
            assert invalid.json()["code"] == "invalid_credentials"

        success = await client.post(
            "/auth/login",
            json={"email": "counter-reset@example.com", "password": "Password123!"},
        )
        assert success.status_code == 200

        for _ in range(4):
            invalid = await client.post(
                "/auth/login",
                json={"email": "counter-reset@example.com", "password": "WrongPassword123!"},
            )
            assert invalid.status_code == 401
            assert invalid.json()["code"] == "invalid_credentials"

        locked = await client.post(
            "/auth/login",
            json={"email": "counter-reset@example.com", "password": "WrongPassword123!"},
        )
        assert locked.status_code == 401
        assert locked.json()["code"] == "account_locked"


@pytest.mark.asyncio
async def test_distributed_attack_detection_locks_after_ten_distinct_ips(
    app_factory,
    user_factory,
) -> None:
    """Distinct failed-login IPs trigger the one-hour distributed attack lockout."""
    app: FastAPI = app_factory()
    user = await user_factory("distributed@example.com", "Password123!")
    redis = get_redis_client()
    attack_key = f"distributed_attack:{user.id}"
    for octet in range(1, 10):
        await redis.pfadd(attack_key, f"203.0.113.{octet}")
    await redis.expire(attack_key, 300)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        locked = await client.post(
            "/auth/login",
            json={"email": "distributed@example.com", "password": "WrongPassword123!"},
            headers={"x-forwarded-for": "203.0.113.10"},
        )
        assert locked.status_code == 401
        assert locked.json()["code"] == "account_locked"
        assert locked.headers["retry-after"] == "3600"
