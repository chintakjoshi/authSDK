"""Correlation ID middleware."""

from __future__ import annotations

from uuid import uuid4

import structlog
from fastapi import Request
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CORRELATION_ID_HEADER = "X-Correlation-ID"
_CONTEXT_KEY = "correlation_id"


class CorrelationIdMiddleware:
    """Attach a request correlation ID and bind it to structlog context."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize middleware with the downstream ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Bind correlation ID context for the current request lifecycle."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        correlation_id = request.headers.get(CORRELATION_ID_HEADER, "").strip() or str(uuid4())
        request.state.correlation_id = correlation_id
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        async def send_with_correlation_id(message: Message) -> None:
            """Attach the correlation ID header to the outgoing response."""
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message["headers"])
                headers[CORRELATION_ID_HEADER] = correlation_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_correlation_id)
        finally:
            structlog.contextvars.unbind_contextvars(_CONTEXT_KEY)
