"""Prometheus-style metrics middleware and ASGI endpoint."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from time import perf_counter

from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


@dataclass
class _DurationStat:
    """Aggregate duration stats per label tuple."""

    count: int = 0
    total_seconds: float = 0.0


class MetricsRegistry:
    """In-process metrics registry that exposes Prometheus text format."""

    def __init__(self) -> None:
        """Initialize counters and locks."""
        self._request_counts: dict[tuple[str, str, str], int] = {}
        self._duration_stats: dict[tuple[str, str, str], _DurationStat] = {}
        self._lock = Lock()

    def record(self, method: str, path: str, status: str, duration_seconds: float) -> None:
        """Record one request measurement for the label set."""
        key = (method, path, status)
        with self._lock:
            self._request_counts[key] = self._request_counts.get(key, 0) + 1
            stat = self._duration_stats.setdefault(key, _DurationStat())
            stat.count += 1
            stat.total_seconds += duration_seconds

    def render_prometheus_text(self) -> str:
        """Render metrics in Prometheus exposition format."""
        lines = [
            "# HELP auth_service_http_requests_total Total HTTP requests seen by the service.",
            "# TYPE auth_service_http_requests_total counter",
        ]

        with self._lock:
            for method, path, status in sorted(self._request_counts.keys()):
                count = self._request_counts[(method, path, status)]
                labels = _format_labels(method=method, path=path, status=status)
                lines.append(f"auth_service_http_requests_total{{{labels}}} {count}")

            lines.append(
                "# HELP auth_service_http_request_duration_seconds End-to-end HTTP request duration in seconds."
            )
            lines.append("# TYPE auth_service_http_request_duration_seconds summary")
            for method, path, status in sorted(self._duration_stats.keys()):
                stat = self._duration_stats[(method, path, status)]
                labels = _format_labels(method=method, path=path, status=status)
                lines.append(
                    f"auth_service_http_request_duration_seconds_count{{{labels}}} {stat.count}"
                )
                lines.append(
                    "auth_service_http_request_duration_seconds_sum"
                    f"{{{labels}}} {stat.total_seconds}"
                )

        return "\n".join(lines) + "\n"


def _escape_label(value: str) -> str:
    """Escape string values for Prometheus label rendering."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(method: str, path: str, status: str) -> str:
    """Build deterministic label set string."""
    return (
        f'method="{_escape_label(method)}",'
        f'path="{_escape_label(path)}",'
        f'status="{_escape_label(status)}"'
    )


DEFAULT_METRICS_REGISTRY = MetricsRegistry()


class MetricsMiddleware:
    """Record metrics for all responses, including failed requests."""

    def __init__(
        self,
        app: ASGIApp,
        registry: MetricsRegistry = DEFAULT_METRICS_REGISTRY,
    ) -> None:
        """Initialize middleware with optional custom metrics registry."""
        self.app = app
        self._registry = registry

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Capture request counts and durations."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = perf_counter()
        path = scope["path"]
        status_code = 500
        method = scope["method"]

        async def send_with_status_capture(message: Message) -> None:
            """Capture the response status code while forwarding ASGI events."""
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_with_status_capture)
        finally:
            route = scope.get("route")
            if route is not None:
                path = getattr(route, "path", path)
            self._registry.record(
                method=method,
                path=path,
                status=str(status_code),
                duration_seconds=perf_counter() - start,
            )


def build_metrics_asgi_app(registry: MetricsRegistry = DEFAULT_METRICS_REGISTRY):
    """Build ASGI app exposing metrics as Prometheus text."""

    async def metrics_app(scope: Scope, receive: Receive, send: Send) -> None:
        """Serve metrics payload on GET requests."""
        if scope["type"] != "http":
            return
        if scope["method"] != "GET":
            response = PlainTextResponse("Method Not Allowed", status_code=405)
            await response(scope, receive, send)
            return
        response = PlainTextResponse(
            registry.render_prometheus_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )
        await response(scope, receive, send)

    return metrics_app


def build_metrics_endpoint(registry: MetricsRegistry = DEFAULT_METRICS_REGISTRY):
    """Build FastAPI-compatible endpoint that serves metrics text."""

    async def metrics_endpoint() -> PlainTextResponse:
        """Return current metrics in Prometheus exposition format."""
        return PlainTextResponse(
            registry.render_prometheus_text(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return metrics_endpoint
