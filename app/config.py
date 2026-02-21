"""Application settings and logging configuration."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Literal

import structlog
from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOG_CONTEXT: dict[str, str] = {"environment": "development", "service": "auth-service"}


class AppSettings(BaseModel):
    """Application identity and runtime settings."""

    environment: Literal["development", "staging", "production"]
    service: str = "auth-service"
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"


class DatabaseSettings(BaseModel):
    """Database connection settings."""

    url: str = Field(description="Async SQLAlchemy URL using asyncpg driver.")

    @field_validator("url")
    @classmethod
    def validate_asyncpg_url(cls, value: str) -> str:
        """Ensure SQLAlchemy uses the asyncpg driver."""
        if not value.startswith("postgresql+asyncpg://"):
            raise ValueError("database.url must start with 'postgresql+asyncpg://'.")
        return value


class RedisSettings(BaseModel):
    """Redis connection settings."""

    url: str = Field(description="Redis URL.")

    @field_validator("url")
    @classmethod
    def validate_redis_url(cls, value: str) -> str:
        """Ensure the Redis URL uses a supported scheme."""
        if not value.startswith(("redis://", "rediss://")):
            raise ValueError("redis.url must start with 'redis://' or 'rediss://'.")
        return value


class JWTSettings(BaseModel):
    """JWT signing and lifetime settings."""

    algorithm: Literal["RS256"] = "RS256"
    private_key_pem: SecretStr
    public_key_pem: SecretStr
    access_token_ttl_seconds: int = Field(default=900, ge=1)
    refresh_token_ttl_seconds: int = Field(default=604800, ge=1)


class OAuthSettings(BaseModel):
    """Google OAuth/OIDC and redirect validation settings."""

    google_client_id: str
    google_client_secret: SecretStr
    google_redirect_uri: AnyHttpUrl
    redirect_uri_allowlist: list[AnyHttpUrl] = Field(min_length=1)


class SAMLSettings(BaseModel):
    """SAML service provider and identity provider settings."""

    sp_entity_id: str
    sp_acs_url: AnyHttpUrl
    sp_x509_cert: SecretStr
    sp_private_key: SecretStr
    idp_entity_id: str
    idp_sso_url: AnyHttpUrl
    idp_x509_cert: SecretStr


class RateLimitSettings(BaseModel):
    """Rate limiting thresholds."""

    default_requests_per_minute: int = Field(default=120, ge=1)
    login_requests_per_minute: int = Field(default=10, ge=1)
    token_requests_per_minute: int = Field(default=30, ge=1)


class Settings(BaseSettings):
    """Root application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app: AppSettings
    database: DatabaseSettings
    redis: RedisSettings
    jwt: JWTSettings
    oauth: OAuthSettings
    saml: SAMLSettings
    rate_limit: RateLimitSettings


def _standard_log_fields(_: Any, __: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Inject required structured logging fields."""
    context_vars = structlog.contextvars.get_contextvars()
    event_dict.setdefault("correlation_id", str(context_vars.get("correlation_id", "unknown")))
    event_dict.setdefault("environment", _LOG_CONTEXT["environment"])
    event_dict.setdefault("service", _LOG_CONTEXT["service"])
    event_dict.setdefault("timestamp", datetime.now(UTC).isoformat())
    return event_dict


def configure_structlog(settings: Settings) -> None:
    """Configure structlog for JSON output with required fields."""
    _LOG_CONTEXT["environment"] = settings.app.environment
    _LOG_CONTEXT["service"] = settings.app.service

    log_level = getattr(logging, settings.app.log_level, logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            _standard_log_fields,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


@lru_cache
def get_settings() -> Settings:
    """Load and cache application settings from environment variables."""
    return Settings()
