"""Unit tests for production app-edge hardening."""

from __future__ import annotations

import importlib

import pytest
from fastapi import HTTPException, Request
from httpx import ASGITransport, AsyncClient

from app.config import Settings, get_settings


class _NoopRateLimitRedis:
    """In-memory Redis stub that never rejects requests."""

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        del key, min, max
        return 0

    async def zcard(self, key: str) -> int:
        del key
        return 0

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        del key, mapping
        return 1

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        del key, ttl_seconds
        return True


def _production_settings() -> Settings:
    """Build a valid production settings object for app-factory tests."""
    return Settings(
        app={
            "environment": "production",
            "service": "auth-service",
            "host": "0.0.0.0",
            "port": 8000,
            "log_level": "INFO",
            "trusted_proxy_cidrs": [],
            "allowed_hosts": ["auth.example.com"],
        },
        database={"url": "postgresql+asyncpg://user:pass@db.example.com:5432/auth_service"},
        redis={"url": "redis://redis.example.com:6379/0"},
        jwt={
            "algorithm": "RS256",
            "private_key_pem": "private-key",
            "public_key_pem": "public-key",
            "access_token_ttl_seconds": 900,
            "refresh_token_ttl_seconds": 604800,
        },
        oauth={
            "google_client_id": "client-id",
            "google_client_secret": "client-secret",
            "google_redirect_uri": "https://auth.example.com/auth/oauth/google/callback",
            "redirect_uri_allowlist": ["https://auth.example.com/auth/oauth/google/callback"],
        },
        saml={
            "sp_entity_id": "sp-entity",
            "sp_acs_url": "https://auth.example.com/auth/saml/callback",
            "sp_x509_cert": "sp-cert",
            "sp_private_key": "sp-private-key",
            "idp_entity_id": "idp-entity",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_x509_cert": "idp-cert",
        },
        rate_limit={
            "default_requests_per_minute": 1000,
            "login_requests_per_minute": 1000,
            "token_requests_per_minute": 1000,
        },
        email={"public_base_url": "https://auth.example.com"},
        signing_keys={"rotation_overlap_seconds": 900, "encryption_key": "signing-secret"},
        webhook={
            "queue_name": "webhooks",
            "request_timeout_seconds": 10,
            "response_body_max_chars": 1000,
            "secret_encryption_key": "webhook-secret",
        },
    )


@pytest.mark.asyncio
async def test_create_app_enforces_trusted_hosts_and_private_metrics(monkeypatch) -> None:
    """Production app enforces host allowlisting and admin-only metrics."""
    settings = _production_settings()
    monkeypatch.setenv("APP__ENVIRONMENT", "production")
    monkeypatch.setenv("APP__SERVICE", "auth-service")
    monkeypatch.setenv("APP__HOST", "0.0.0.0")
    monkeypatch.setenv("APP__PORT", "8000")
    monkeypatch.setenv("APP__LOG_LEVEL", "INFO")
    monkeypatch.setenv("APP__ALLOWED_HOSTS", '["auth.example.com"]')
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
    monkeypatch.setenv(
        "OAUTH__GOOGLE_REDIRECT_URI",
        "https://auth.example.com/auth/oauth/google/callback",
    )
    monkeypatch.setenv(
        "OAUTH__REDIRECT_URI_ALLOWLIST",
        '["https://auth.example.com/auth/oauth/google/callback"]',
    )
    monkeypatch.setenv("SAML__SP_ENTITY_ID", "sp-entity")
    monkeypatch.setenv("SAML__SP_ACS_URL", "https://auth.example.com/auth/saml/callback")
    monkeypatch.setenv("SAML__SP_X509_CERT", "sp-cert")
    monkeypatch.setenv("SAML__SP_PRIVATE_KEY", "sp-private-key")
    monkeypatch.setenv("SAML__IDP_ENTITY_ID", "idp-entity")
    monkeypatch.setenv("SAML__IDP_SSO_URL", "https://idp.example.com/sso")
    monkeypatch.setenv("SAML__IDP_X509_CERT", "idp-cert")
    monkeypatch.setenv("RATE_LIMIT__DEFAULT_REQUESTS_PER_MINUTE", "1000")
    monkeypatch.setenv("RATE_LIMIT__LOGIN_REQUESTS_PER_MINUTE", "1000")
    monkeypatch.setenv("RATE_LIMIT__TOKEN_REQUESTS_PER_MINUTE", "1000")
    monkeypatch.setenv("EMAIL__PUBLIC_BASE_URL", "https://auth.example.com")
    monkeypatch.setenv("SIGNING_KEYS__ENCRYPTION_KEY", "signing-secret")
    monkeypatch.setenv("WEBHOOK__SECRET_ENCRYPTION_KEY", "webhook-secret")
    get_settings.cache_clear()

    import app.main as main_module

    main_module = importlib.reload(main_module)

    async def _require_metrics_admin(request: Request) -> None:
        if request.headers.get("x-metrics-admin") != "yes":
            raise HTTPException(status_code=401, detail="Admin credentials required.")

    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module, "configure_structlog", lambda current_settings: None)
    monkeypatch.setattr(main_module, "require_admin_access", _require_metrics_admin)
    monkeypatch.setattr("app.middleware.rate_limit.get_settings", lambda: settings)
    monkeypatch.setattr(
        "app.middleware.rate_limit.get_rate_limit_redis_client",
        lambda: _NoopRateLimitRedis(),
    )

    app = main_module.create_app()

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://auth.example.com",
    ) as client:
        metrics_denied = await client.get("/metrics")
        metrics_allowed = await client.get("/metrics", headers={"x-metrics-admin": "yes"})

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://evil.example",
    ) as client:
        invalid_host = await client.get("/health/live")

    assert metrics_denied.status_code == 401
    assert metrics_allowed.status_code == 200
    assert "auth_service_http_requests_total" in metrics_allowed.text
    assert invalid_host.status_code == 400

    get_settings.cache_clear()
