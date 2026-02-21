"""Correlation ID middleware."""

from __future__ import annotations

from uuid import uuid4

import structlog
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

CORRELATION_ID_HEADER = "X-Correlation-ID"
_CONTEXT_KEY = "correlation_id"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach a request correlation ID and bind it to structlog context."""

    async def dispatch(self, request: Request, call_next) -> Response:
        """Bind correlation ID context for the current request lifecycle."""
        correlation_id = request.headers.get(CORRELATION_ID_HEADER, "").strip() or str(uuid4())
        request.state.correlation_id = correlation_id
        structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        try:
            response = await call_next(request)
        finally:
            structlog.contextvars.unbind_contextvars(_CONTEXT_KEY)

        response.headers[CORRELATION_ID_HEADER] = correlation_id
        return response
