"""Unit tests for logging middleware credential redaction."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.middleware import logging as logging_module
from app.middleware.logging import REDACTED, LoggingMiddleware


class _CaptureLogger:
    """Capture structlog-like logger calls for assertions."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def info(self, event: str, **kwargs: Any) -> None:
        """Capture info-level calls."""
        self.calls.append(("info", event, kwargs))

    def warning(self, event: str, **kwargs: Any) -> None:
        """Capture warning-level calls."""
        self.calls.append(("warning", event, kwargs))

    def exception(self, event: str, **kwargs: Any) -> None:
        """Capture exception-level calls."""
        self.calls.append(("exception", event, kwargs))


@pytest.mark.asyncio
async def test_logging_middleware_redacts_password_and_token_values(monkeypatch) -> None:
    """Request logs never contain raw token/password query parameter values."""
    capture = _CaptureLogger()
    monkeypatch.setattr(logging_module, "logger", capture)

    app = FastAPI()
    app.add_middleware(LoggingMiddleware)

    @app.get("/ok")
    async def ok() -> dict[str, bool]:
        return {"ok": True}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.get(
            "/ok",
            params={"password": "Password123!", "access_token": "token-secret"},
        )

    assert response.status_code == 200
    assert len(capture.calls) == 1
    level, event, payload = capture.calls[0]
    assert level == "info"
    assert event == "request_completed"
    assert payload["query_params"]["password"] == REDACTED
    assert payload["query_params"]["access_token"] == REDACTED

    serialized = str(payload)
    assert "Password123!" not in serialized
    assert "token-secret" not in serialized
