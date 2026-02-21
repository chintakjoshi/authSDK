"""Shared integration-test fixtures using Postgres and Redis testcontainers."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from datetime import datetime
from typing import Any
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

from docker.errors import DockerException


def _generate_rsa_keypair() -> tuple[str, str]:
    """Generate PEM-encoded RSA private/public keypair for integration settings."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def _clear_dependency_caches() -> None:
    """Clear all relevant singleton/lru-cache dependencies between test phases."""
    from app.config import get_settings
    from app.core.jwt import get_jwt_service
    from app.core.oauth import get_google_oauth_client
    from app.core.saml import get_saml_core
    from app.core.sessions import get_redis_client, get_session_service
    from app.db.session import get_engine, get_session_factory
    from app.middleware.rate_limit import get_rate_limit_redis_client
    from app.services.api_key_service import get_api_key_service
    from app.services.oauth_service import get_oauth_service
    from app.services.saml_service import get_saml_service
    from app.services.token_service import get_token_service

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    get_jwt_service.cache_clear()
    get_redis_client.cache_clear()
    get_rate_limit_redis_client.cache_clear()
    get_session_service.cache_clear()
    get_google_oauth_client.cache_clear()
    get_saml_core.cache_clear()
    get_token_service.cache_clear()
    get_api_key_service.cache_clear()
    get_oauth_service.cache_clear()
    get_saml_service.cache_clear()


async def _close_async_client(client: Any) -> None:
    """Close async client instances regardless of redis-py close API version."""
    close = getattr(client, "aclose", None)
    if callable(close):
        await close()
        return

    close = getattr(client, "close", None)
    if callable(close):
        result = close()
        if hasattr(result, "__await__"):
            await result


async def _dispose_async_singletons() -> None:
    """Dispose loop-bound async resources before changing event loops."""
    from app.core.sessions import get_redis_client
    from app.db.session import dispose_engine, get_engine
    from app.middleware.rate_limit import get_rate_limit_redis_client

    redis_client = get_redis_client() if get_redis_client.cache_info().currsize else None
    rate_limit_client = (
        get_rate_limit_redis_client() if get_rate_limit_redis_client.cache_info().currsize else None
    )

    if redis_client is not None:
        await _close_async_client(redis_client)
    if rate_limit_client is not None and rate_limit_client is not redis_client:
        await _close_async_client(rate_limit_client)
    if get_engine.cache_info().currsize:
        await dispose_engine()


def _redis_connection_url(redis: RedisContainer) -> str:
    """Return a redis:// URL across testcontainers versions."""
    get_url = getattr(redis, "get_connection_url", None)
    if callable(get_url):
        redis_url = get_url()
    else:
        host = redis.get_container_host_ip()
        port = redis.get_exposed_port(6379)
        redis_url = f"redis://{host}:{port}"
    if not redis_url.endswith("/0"):
        redis_url = f"{redis_url}/0"
    return redis_url


def _postgres_async_url(postgres: PostgresContainer) -> str:
    """Return a postgresql+asyncpg URL across testcontainers versions."""
    try:
        # testcontainers>=4 supports explicitly disabling default psycopg2 driver.
        postgres_url = postgres.get_connection_url(driver=None)
    except TypeError:
        postgres_url = postgres.get_connection_url()

    if postgres_url.startswith("postgresql+"):
        postgres_url = "postgresql://" + postgres_url.split("://", 1)[1]

    return postgres_url.replace("postgresql://", "postgresql+asyncpg://", 1)


def _set_env_values(env_values: dict[str, str]) -> tuple[dict[str, str], Callable[[], None]]:
    """Apply env vars and return a restore callback."""
    original: dict[str, str] = {}
    missing: set[str] = set()
    for key, value in env_values.items():
        current = os.environ.get(key)
        if current is None:
            missing.add(key)
            original[key] = ""
        else:
            original[key] = current
        os.environ[key] = value

    def _restore() -> None:
        for key in env_values:
            if key in missing:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original[key]

    return original, _restore


@pytest.fixture(scope="session")
def integration_env() -> Iterator[dict[str, str]]:
    """Start Postgres/Redis containers and configure app settings for integration tests."""
    try:
        postgres = PostgresContainer("postgres:16")
        redis = RedisContainer("redis:7")
        postgres.start()
        redis.start()
    except DockerException as exc:
        if os.environ.get("CI", "").lower() in {"1", "true", "yes"}:
            pytest.fail(
                f"Docker daemon unavailable in CI for testcontainers-backed integration tests: {exc}"
            )
        pytest.skip(f"Docker daemon unavailable for testcontainers-backed integration tests: {exc}")

    private_pem, public_pem = _generate_rsa_keypair()

    database_url = _postgres_async_url(postgres)
    redis_url = _redis_connection_url(redis)

    env_values = {
        "APP__ENVIRONMENT": "development",
        "APP__SERVICE": "auth-service",
        "APP__HOST": "0.0.0.0",
        "APP__PORT": "8000",
        "APP__LOG_LEVEL": "INFO",
        "DATABASE__URL": database_url,
        "REDIS__URL": redis_url,
        "JWT__ALGORITHM": "RS256",
        "JWT__PRIVATE_KEY_PEM": private_pem,
        "JWT__PUBLIC_KEY_PEM": public_pem,
        "JWT__ACCESS_TOKEN_TTL_SECONDS": "900",
        "JWT__REFRESH_TOKEN_TTL_SECONDS": "604800",
        "OAUTH__GOOGLE_CLIENT_ID": "integration-google-client-id",
        "OAUTH__GOOGLE_CLIENT_SECRET": "integration-google-client-secret",
        "OAUTH__GOOGLE_REDIRECT_URI": "http://localhost:8000/auth/oauth/google/callback",
        "OAUTH__REDIRECT_URI_ALLOWLIST": '["http://localhost:8000/auth/oauth/google/callback"]',
        "SAML__SP_ENTITY_ID": "integration-sp-entity",
        "SAML__SP_ACS_URL": "http://localhost:8000/auth/saml/callback",
        "SAML__SP_X509_CERT": "integration-sp-cert",
        "SAML__SP_PRIVATE_KEY": "integration-sp-private-key",
        "SAML__IDP_ENTITY_ID": "integration-idp-entity",
        "SAML__IDP_SSO_URL": "https://idp.example.com/sso",
        "SAML__IDP_X509_CERT": "integration-idp-cert",
        "RATE_LIMIT__DEFAULT_REQUESTS_PER_MINUTE": "10000",
        "RATE_LIMIT__LOGIN_REQUESTS_PER_MINUTE": "10000",
        "RATE_LIMIT__TOKEN_REQUESTS_PER_MINUTE": "10000",
    }

    _, restore_env = _set_env_values(env_values)
    _clear_dependency_caches()

    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(alembic_cfg, "head")

    try:
        yield {"database_url": database_url, "redis_url": redis_url}
    finally:
        try:
            _clear_dependency_caches()
        finally:
            restore_env()
            postgres.stop()
            redis.stop()


@pytest.fixture(scope="function")
async def db_session_factory(
    integration_env: dict[str, str],
    reset_state: None,
) -> async_sessionmaker[AsyncSession]:
    """Expose async session factory bound to integration Postgres."""
    del integration_env, reset_state
    from app.db.session import get_session_factory

    return get_session_factory()


@pytest.fixture(scope="function")
async def db_session(
    db_session_factory: async_sessionmaker[AsyncSession],
) -> Iterator[AsyncSession]:
    """Yield a write-capable async DB session for test seeding and assertions."""
    async with db_session_factory() as session:
        yield session


@pytest.fixture(scope="function", autouse=True)
async def reset_state(
    integration_env: dict[str, str],
) -> Iterator[None]:
    """Clear DB tables and flush Redis; isolate async singletons per event loop."""
    del integration_env
    from app.core.sessions import get_redis_client
    from app.db.session import get_session_factory
    from app.models.api_key import APIKey
    from app.models.session import Session
    from app.models.user import User, UserIdentity

    await _dispose_async_singletons()
    _clear_dependency_caches()

    session_factory = get_session_factory()
    async with session_factory() as session:
        await session.execute(delete(UserIdentity))
        await session.execute(delete(Session))
        await session.execute(delete(APIKey))
        await session.execute(delete(User))
        await session.commit()

    redis_client = get_redis_client()
    await redis_client.flushdb()
    try:
        yield
    finally:
        await _dispose_async_singletons()
        _clear_dependency_caches()


@pytest.fixture(scope="function")
def app_factory(integration_env: dict[str, str]) -> Callable[[], Any]:
    """Build isolated FastAPI app instances for integration tests."""
    del integration_env
    from app.main import create_app

    def _factory() -> Any:
        return create_app()

    return _factory


@pytest.fixture(scope="function")
async def user_factory(
    db_session: AsyncSession,
) -> Callable[[str, str], Any]:
    """Create canonical active user rows with hashed bcrypt passwords."""
    from app.models.user import User
    from app.services.user_service import UserService

    user_service = UserService()

    async def _create(email: str, password: str) -> User:
        user = User(
            email=email,
            password_hash=user_service.hash_password(password),
            is_active=True,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    return _create


@pytest.fixture(scope="function")
async def api_key_row_factory(
    db_session: AsyncSession,
) -> Callable[[str, str, UUID | None, datetime | None], Any]:
    """Create API key rows directly for failure-path introspection tests."""
    from app.core.api_keys import APIKeyCore
    from app.models.api_key import APIKey

    core = APIKeyCore()

    async def _create(
        raw_key: str,
        scope: str,
        user_id: UUID | None = None,
        expires_at: datetime | None = None,
    ) -> APIKey:
        row = APIKey(
            user_id=user_id,
            service="svc",
            hashed_key=core.hash_key(raw_key),
            key_prefix=core.key_prefix(raw_key),
            scope=scope,
            expires_at=expires_at,
            revoked_at=None,
        )
        db_session.add(row)
        await db_session.commit()
        await db_session.refresh(row)
        return row

    return _create
