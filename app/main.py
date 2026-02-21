"""FastAPI application factory."""

from fastapi import FastAPI

from app.config import configure_structlog, get_settings
from app.middleware.correlation_id import CorrelationIdMiddleware
from app.middleware.logging import LoggingMiddleware
from app.middleware.metrics import MetricsMiddleware, build_metrics_endpoint
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.tracing import TracingMiddleware
from app.routers import apikeys, auth, health, oauth, saml


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    configure_structlog(settings)

    app = FastAPI(title=settings.app.service)
    app.add_middleware(TracingMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(CorrelationIdMiddleware)

    app.add_api_route("/metrics", build_metrics_endpoint(), methods=["GET"], include_in_schema=False)
    app.include_router(auth.router)
    app.include_router(oauth.router)
    app.include_router(saml.router)
    app.include_router(apikeys.router)
    app.include_router(health.router)
    return app


app = create_app()
