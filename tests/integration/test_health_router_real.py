"""Integration tests for health endpoints against real backing services."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


@pytest.mark.asyncio
async def test_health_live_and_ready_are_healthy_with_real_backends(app_factory) -> None:
    """Live and ready probes return 200 when Postgres and Redis are reachable."""
    app: FastAPI = app_factory()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        live_response = await client.get("/health/live")
        ready_response = await client.get("/health/ready")

    assert live_response.status_code == 200
    assert live_response.json() == {"status": "live"}
    assert ready_response.status_code == 200
    assert ready_response.json() == {"status": "ready"}
