"""Structured request logging middleware with credential redaction."""

from __future__ import annotations

from time import perf_counter
from typing import Any

import structlog
from fastapi import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.client_ip import extract_client_ip

SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "refresh_token",
    "set-cookie",
    "token",
    "x-api-key",
}
REDACTED = "***REDACTED***"

logger = structlog.get_logger(__name__)


def _is_sensitive_key(key: str) -> bool:
    """Return True when key likely carries credential material."""
    normalized = key.lower().replace("-", "_")
    if normalized in SENSITIVE_KEYS:
        return True
    return "token" in normalized or "password" in normalized or "api_key" in normalized


def _redact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive values from a dictionary."""
    redacted: dict[str, Any] = {}
    for key, value in values.items():
        if _is_sensitive_key(key):
            redacted[key] = REDACTED
        elif isinstance(value, dict):
            redacted[key] = _redact_mapping(value)
        elif isinstance(value, list):
            redacted[key] = [
                _redact_mapping(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            redacted[key] = value
    return redacted


class LoggingMiddleware:
    """Emit one structured log per request with redacted metadata."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize middleware with the downstream ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Log completion metadata for each request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        start = perf_counter()
        query_params = _redact_mapping({key: value for key, value in request.query_params.items()})
        client_ip = extract_client_ip(request) or "unknown"
        status_code = 500

        async def send_with_status_capture(message: Message) -> None:
            """Capture the response status code while forwarding ASGI events."""
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_with_status_capture)
        except Exception:
            duration_ms = round((perf_counter() - start) * 1000, 2)
            logger.exception(
                "request_completed",
                method=request.method,
                path=request.url.path,
                query_params=query_params,
                status_code=500,
                duration_ms=duration_ms,
                client_ip=client_ip,
                user_agent=request.headers.get("user-agent", ""),
            )
            raise

        duration_ms = round((perf_counter() - start) * 1000, 2)
        event_logger = logger.warning if status_code >= 400 else logger.info
        event_logger(
            "request_completed",
            method=request.method,
            path=request.url.path,
            query_params=query_params,
            status_code=status_code,
            duration_ms=duration_ms,
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent", ""),
        )
