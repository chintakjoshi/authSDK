"""Shared pytest fixtures for unit tests."""

from __future__ import annotations

import pytest

from app.config import get_settings
from app.services.user_service import get_user_service


@pytest.fixture(autouse=True)
def default_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide a minimal valid settings environment for unit tests."""
    monkeypatch.setenv("APP__ENVIRONMENT", "development")
    monkeypatch.setenv("APP__SERVICE", "auth-service")
    monkeypatch.setenv(
        "DATABASE__URL",
        "postgresql+asyncpg://user:pass@db.example.com:5432/auth_service",
    )
    monkeypatch.setenv("REDIS__URL", "redis://redis.example.com:6379/0")
    monkeypatch.setenv("JWT__ALGORITHM", "RS256")
    monkeypatch.setenv("JWT__PRIVATE_KEY_PEM", "private-key")
    monkeypatch.setenv("JWT__PUBLIC_KEY_PEM", "public-key")
    monkeypatch.setenv("JWT__ACCESS_TOKEN_TTL_SECONDS", "900")
    monkeypatch.setenv("JWT__REFRESH_TOKEN_TTL_SECONDS", "604800")
    monkeypatch.setenv("OAUTH__GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("OAUTH__GOOGLE_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("OAUTH__GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/oauth/callback")
    monkeypatch.setenv(
        "OAUTH__REDIRECT_URI_ALLOWLIST",
        '["http://localhost:8000/auth/oauth/callback"]',
    )
    monkeypatch.setenv("SAML__SP_ENTITY_ID", "sp-entity")
    monkeypatch.setenv("SAML__SP_ACS_URL", "http://localhost:8000/auth/saml/callback")
    monkeypatch.setenv("SAML__SP_X509_CERT", "sp-cert")
    monkeypatch.setenv("SAML__SP_PRIVATE_KEY", "sp-private-key")
    monkeypatch.setenv("SAML__IDP_ENTITY_ID", "idp-entity")
    monkeypatch.setenv("SAML__IDP_SSO_URL", "http://localhost:9000/sso")
    monkeypatch.setenv("SAML__IDP_X509_CERT", "idp-cert")
    monkeypatch.setenv("RATE_LIMIT__DEFAULT_REQUESTS_PER_MINUTE", "120")
    monkeypatch.setenv("RATE_LIMIT__LOGIN_REQUESTS_PER_MINUTE", "10")
    monkeypatch.setenv("RATE_LIMIT__TOKEN_REQUESTS_PER_MINUTE", "30")
    get_settings.cache_clear()
    get_user_service.cache_clear()
    yield
    get_settings.cache_clear()
    get_user_service.cache_clear()


@pytest.fixture
def browser_session_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure explicit browser-session settings for cookie-transport unit tests."""
    monkeypatch.setenv("BROWSER_SESSIONS__ENABLED", "true")
    monkeypatch.setenv("BROWSER_SESSIONS__SECURE_ONLY", "false")
    monkeypatch.setenv("BROWSER_SESSIONS__ACCESS_COOKIE_NAME", "auth_access")
    monkeypatch.setenv("BROWSER_SESSIONS__REFRESH_COOKIE_NAME", "auth_refresh")
    monkeypatch.setenv("BROWSER_SESSIONS__CSRF_COOKIE_NAME", "auth_csrf")
    monkeypatch.setenv("BROWSER_SESSIONS__ACCESS_COOKIE_PATH", "/")
    monkeypatch.setenv("BROWSER_SESSIONS__REFRESH_COOKIE_PATH", "/_auth")
    monkeypatch.setenv("BROWSER_SESSIONS__CSRF_COOKIE_PATH", "/")
    monkeypatch.setenv("BROWSER_SESSIONS__CSRF_HEADER_NAME", "X-CSRF-Token")
    get_settings.cache_clear()
    get_user_service.cache_clear()
    yield
    get_settings.cache_clear()
    get_user_service.cache_clear()
