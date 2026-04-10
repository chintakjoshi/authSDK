"""Regression tests for reloadable configuration-backed singleton factories."""

from __future__ import annotations

import asyncio

import pytest

import app.core.sessions as sessions_module
import app.db.session as db_session_module
import app.middleware.rate_limit as rate_limit_module
from app.config import get_settings


class _AsyncRedisClientStub:
    """Minimal async Redis client stub with close tracking."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.closed = False

    async def aclose(self) -> None:
        """Mark the stub as closed."""
        self.closed = True


class _AsyncEngineStub:
    """Minimal async SQLAlchemy engine stub with dispose tracking."""

    def __init__(self, url: str) -> None:
        self.url = url
        self.disposed = False

    async def dispose(self) -> None:
        """Mark the stub as disposed."""
        self.disposed = True


def _seed_minimal_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    database_url: str = "postgresql+asyncpg://user:pass@db.example.com:5432/auth_service",
    redis_url: str = "redis://redis.example.com:6379/0",
    access_ttl_seconds: str = "900",
    refresh_ttl_seconds: str = "604800",
) -> None:
    """Seed the minimum environment required to build Settings from env."""
    monkeypatch.setenv("APP__ENVIRONMENT", "development")
    monkeypatch.setenv("APP__SERVICE", "auth-service")
    monkeypatch.setenv("DATABASE__URL", database_url)
    monkeypatch.setenv("REDIS__URL", redis_url)
    monkeypatch.setenv("JWT__ALGORITHM", "RS256")
    monkeypatch.setenv("JWT__PRIVATE_KEY_PEM", "private-key")
    monkeypatch.setenv("JWT__PUBLIC_KEY_PEM", "public-key")
    monkeypatch.setenv("JWT__ACCESS_TOKEN_TTL_SECONDS", access_ttl_seconds)
    monkeypatch.setenv("JWT__REFRESH_TOKEN_TTL_SECONDS", refresh_ttl_seconds)
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


def _clear_reloadable_getters() -> None:
    """Clear the singleton getters touched by these tests."""
    get_settings.cache_clear()
    sessions_module.get_redis_client.cache_clear()
    sessions_module.get_session_service.cache_clear()
    rate_limit_module.get_rate_limit_redis_client.cache_clear()
    db_session_module.get_engine.cache_clear()
    db_session_module.get_session_factory.cache_clear()


def test_get_settings_refreshes_when_environment_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings should be rebuilt when the underlying environment changes."""
    _seed_minimal_env(monkeypatch, redis_url="redis://primary.example.com:6379/0")
    _clear_reloadable_getters()

    first = get_settings()
    monkeypatch.setenv("REDIS__URL", "redis://failover.example.com:6380/1")

    second = get_settings()

    assert first is not second
    assert first.redis.url == "redis://primary.example.com:6379/0"
    assert second.redis.url == "redis://failover.example.com:6380/1"


@pytest.mark.asyncio
async def test_get_redis_client_refreshes_on_config_change_and_enables_health_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Async Redis clients should be rebuilt on config change and configured to self-heal."""
    _seed_minimal_env(monkeypatch, redis_url="redis://primary.example.com:6379/0")
    _clear_reloadable_getters()
    calls: list[tuple[str, dict[str, object], _AsyncRedisClientStub]] = []

    def _from_url(url: str, **kwargs: object) -> _AsyncRedisClientStub:
        client = _AsyncRedisClientStub(url)
        calls.append((url, dict(kwargs), client))
        return client

    monkeypatch.setattr(sessions_module.redis_async, "from_url", _from_url)

    first = sessions_module.get_redis_client()
    monkeypatch.setenv("REDIS__URL", "redis://failover.example.com:6380/1")
    second = sessions_module.get_redis_client()
    await asyncio.sleep(0)

    assert first is not second
    assert first.closed is True
    assert [call[0] for call in calls] == [
        "redis://primary.example.com:6379/0",
        "redis://failover.example.com:6380/1",
    ]
    assert calls[0][1]["decode_responses"] is True
    assert calls[0][1]["socket_keepalive"] is True
    assert calls[0][1]["health_check_interval"] == 30


@pytest.mark.asyncio
async def test_get_rate_limit_redis_client_refreshes_when_environment_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rate-limit Redis clients should also rotate when the Redis URL changes."""
    _seed_minimal_env(monkeypatch, redis_url="redis://primary.example.com:6379/0")
    _clear_reloadable_getters()
    calls: list[tuple[str, dict[str, object], _AsyncRedisClientStub]] = []

    def _from_url(url: str, **kwargs: object) -> _AsyncRedisClientStub:
        client = _AsyncRedisClientStub(url)
        calls.append((url, dict(kwargs), client))
        return client

    monkeypatch.setattr(rate_limit_module.redis_async, "from_url", _from_url)

    first = rate_limit_module.get_rate_limit_redis_client()
    monkeypatch.setenv("REDIS__URL", "redis://failover.example.com:6380/1")
    second = rate_limit_module.get_rate_limit_redis_client()
    await asyncio.sleep(0)

    assert first is not second
    assert first.closed is True
    assert [call[0] for call in calls] == [
        "redis://primary.example.com:6379/0",
        "redis://failover.example.com:6380/1",
    ]
    assert calls[0][1]["decode_responses"] is True
    assert calls[0][1]["socket_keepalive"] is True
    assert calls[0][1]["health_check_interval"] == 30


@pytest.mark.asyncio
async def test_get_engine_refreshes_and_disposes_previous_engine_on_database_url_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Database engine singletons should rotate and dispose old pools after config changes."""
    _seed_minimal_env(
        monkeypatch,
        database_url="postgresql+asyncpg://user:pass@db-a.example.com:5432/auth_service",
    )
    _clear_reloadable_getters()
    created: list[_AsyncEngineStub] = []

    def _create_async_engine(url: str, **kwargs: object) -> _AsyncEngineStub:
        del kwargs
        engine = _AsyncEngineStub(url)
        created.append(engine)
        return engine

    monkeypatch.setattr(db_session_module, "create_async_engine", _create_async_engine)

    first = db_session_module.get_engine()
    monkeypatch.setenv(
        "DATABASE__URL",
        "postgresql+asyncpg://user:pass@db-b.example.com:5432/auth_service",
    )
    second = db_session_module.get_engine()
    await asyncio.sleep(0)

    assert first is not second
    assert first.disposed is True
    assert [engine.url for engine in created] == [
        "postgresql+asyncpg://user:pass@db-a.example.com:5432/auth_service",
        "postgresql+asyncpg://user:pass@db-b.example.com:5432/auth_service",
    ]


@pytest.mark.asyncio
async def test_get_session_service_refreshes_nested_dependencies_when_settings_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Higher-level services should not retain stale Redis clients or TTL values after reload."""
    _seed_minimal_env(
        monkeypatch,
        redis_url="redis://primary.example.com:6379/0",
        access_ttl_seconds="300",
        refresh_ttl_seconds="600",
    )
    _clear_reloadable_getters()

    def _from_url(url: str, **kwargs: object) -> _AsyncRedisClientStub:
        del kwargs
        return _AsyncRedisClientStub(url)

    monkeypatch.setattr(sessions_module.redis_async, "from_url", _from_url)

    first = sessions_module.get_session_service()
    monkeypatch.setenv("REDIS__URL", "redis://failover.example.com:6380/1")
    monkeypatch.setenv("JWT__ACCESS_TOKEN_TTL_SECONDS", "450")
    monkeypatch.setenv("JWT__REFRESH_TOKEN_TTL_SECONDS", "1200")
    second = sessions_module.get_session_service()
    await asyncio.sleep(0)

    assert first is not second
    assert first._redis is not second._redis
    assert first._access_token_ttl_seconds == 300
    assert second._access_token_ttl_seconds == 450
    assert first._refresh_token_ttl_seconds == 600
    assert second._refresh_token_ttl_seconds == 1200
