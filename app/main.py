"""FastAPI application factory."""

from fastapi import FastAPI

from app.config import configure_structlog, get_settings
from app.routers import apikeys, auth, health, oauth, saml


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    configure_structlog(settings)

    app = FastAPI(title=settings.app.service)
    app.include_router(auth.router)
    app.include_router(oauth.router)
    app.include_router(saml.router)
    app.include_router(apikeys.router)
    app.include_router(health.router)
    return app


app = create_app()
