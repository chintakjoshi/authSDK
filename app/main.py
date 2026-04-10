"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import configure_structlog, get_settings, shutdown_reloadable_singletons
from app.error_handlers import register_exception_handlers
from app.middleware.correlation_id import CorrelationIdMiddleware
from app.middleware.logging import LoggingMiddleware
from app.middleware.metrics import MetricsMiddleware, build_metrics_endpoint
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.tracing import TracingMiddleware
from app.routers import admin, apikeys, auth, health, lifecycle, oauth, otp, saml, webhooks
from app.routers._admin_access import require_admin_access


@asynccontextmanager
async def _app_lifespan(_: FastAPI):
    """Dispose reloadable singleton resources on application shutdown."""
    try:
        yield
    finally:
        await shutdown_reloadable_singletons()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    configure_structlog(settings)
    docs_enabled = settings.app.expose_docs

    app = FastAPI(
        title=settings.app.service,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
        lifespan=_app_lifespan,
    )
    register_exception_handlers(app, environment=settings.app.environment)

    if settings.app.allowed_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.app.allowed_hosts)
    app.add_middleware(TracingMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(CorrelationIdMiddleware)

    metrics_dependencies = (
        [] if settings.app.environment == "development" else [Depends(require_admin_access)]
    )
    app.add_api_route(
        "/metrics",
        build_metrics_endpoint(),
        methods=["GET"],
        include_in_schema=False,
        dependencies=metrics_dependencies,
    )
    app.include_router(auth.router)
    app.include_router(lifecycle.router)
    app.include_router(otp.router)
    app.include_router(oauth.router)
    app.include_router(saml.router)
    app.include_router(apikeys.router)
    app.include_router(webhooks.router)
    app.include_router(admin.router)
    app.include_router(health.router)
    return app


app = create_app()
