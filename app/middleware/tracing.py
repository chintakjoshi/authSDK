"""OpenTelemetry request tracing middleware."""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode

    _OTEL_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - exercised only in stripped local envs.
    trace = None  # type: ignore[assignment]
    Status = None  # type: ignore[assignment]
    StatusCode = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False


class TracingMiddleware:
    """Create an OpenTelemetry span for request handler execution."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialize tracer instance."""
        self.app = app
        self._tracer = trace.get_tracer("app.middleware.tracing") if _OTEL_AVAILABLE else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Trace request processing and attach key HTTP attributes."""
        if scope["type"] != "http" or self._tracer is None:
            await self.app(scope, receive, send)
            return

        method = scope["method"]
        path = scope["path"]
        status_code = 500

        async def send_with_status_capture(message: Message) -> None:
            """Capture the response status code while forwarding ASGI events."""
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        span_name = f"{method} {path}"
        with self._tracer.start_as_current_span(span_name) as span:
            span.set_attribute("http.method", method)
            span.set_attribute("http.target", path)
            try:
                await self.app(scope, receive, send_with_status_capture)
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR))  # type: ignore[operator]
                raise

            span.set_attribute("http.status_code", status_code)
            if status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))  # type: ignore[operator]
            else:
                span.set_status(Status(StatusCode.OK))  # type: ignore[operator]
