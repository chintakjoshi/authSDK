"""OpenTelemetry request tracing middleware."""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode

    _OTEL_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - exercised only in stripped local envs.
    trace = None  # type: ignore[assignment]
    Status = None  # type: ignore[assignment]
    StatusCode = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False


class TracingMiddleware(BaseHTTPMiddleware):
    """Create an OpenTelemetry span for request handler execution."""

    def __init__(self, app) -> None:
        """Initialize tracer instance."""
        super().__init__(app)
        self._tracer = trace.get_tracer("app.middleware.tracing") if _OTEL_AVAILABLE else None

    async def dispatch(self, request: Request, call_next) -> Response:
        """Trace request processing and attach key HTTP attributes."""
        if self._tracer is None:
            return await call_next(request)

        span_name = f"{request.method} {request.url.path}"
        with self._tracer.start_as_current_span(span_name) as span:
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.target", request.url.path)
            try:
                response = await call_next(request)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))  # type: ignore[operator]
                raise

            span.set_attribute("http.status_code", response.status_code)
            if response.status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))  # type: ignore[operator]
            else:
                span.set_status(Status(StatusCode.OK))  # type: ignore[operator]
            return response
