"""Application settings and logging configuration."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import logging
import os
from collections import deque, namedtuple
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from threading import Lock, RLock
from typing import Any, Literal, TypeVar, cast

import structlog
from pydantic import AnyHttpUrl, BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOG_CONTEXT: dict[str, str] = {"environment": "development", "service": "auth-service"}
_CacheInfo = namedtuple("CacheInfo", "hits misses maxsize currsize")
_UNSET = object()
_PENDING_SINGLETON_CLEANUPS: deque[tuple[str, Callable[[Any], Any], Any]] = deque()
_PENDING_SINGLETON_CLEANUPS_LOCK = Lock()
_SCHEDULED_SINGLETON_CLEANUPS: set[asyncio.Task[None]] = set()
_SCHEDULED_SINGLETON_CLEANUPS_LOCK = Lock()
_REGISTERED_SINGLETON_CLEARERS: list[Callable[[], None]] = []
_REGISTERED_SINGLETON_CLEARERS_LOCK = Lock()
_cleanup_logger = logging.getLogger(__name__)
_T = TypeVar("_T")


class AppSettings(BaseModel):
    """Application identity and runtime settings."""

    environment: Literal["development", "staging", "production"]
    service: str = "auth-service"
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    expose_docs: bool = False

    @field_validator("trusted_proxy_cidrs", "allowed_hosts")
    @classmethod
    def normalize_string_lists(cls, value: list[str]) -> list[str]:
        """Drop blank entries and normalize whitespace in list settings."""
        return [item.strip() for item in value if item and item.strip()]


class DatabaseSettings(BaseModel):
    """Database connection settings."""

    url: str = Field(description="Async SQLAlchemy URL using asyncpg driver.")
    pool_size: int = Field(default=20, ge=1)
    max_overflow: int = Field(default=20, ge=0)
    pool_timeout_seconds: int = Field(default=30, ge=1)
    pool_recycle_seconds: int = Field(default=1800, ge=1)

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
    health_check_interval_seconds: int = Field(default=30, ge=0)

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


class AuthSettings(BaseModel):
    """Authentication policy controls."""

    require_verified_email_for_password_login: bool = True


class SessionSecuritySettings(BaseModel):
    """Security settings for persisted session verifiers."""

    refresh_token_hash_key: SecretStr | None = None


class BrowserSessionSettings(BaseModel):
    """Browser-cookie session settings for web application consumers."""

    enabled: bool = False
    infer_cookie_transport: bool = True
    transport_header_name: str = "X-Auth-Session-Transport"
    access_cookie_name: str = "__Host-auth_access"
    refresh_cookie_name: str = "__Host-auth_refresh"
    csrf_cookie_name: str = "__Host-auth_csrf"
    same_site: Literal["lax", "strict", "none"] = "lax"
    secure_only: bool = False
    cookie_domain: str | None = None
    access_cookie_path: str = "/"
    refresh_cookie_path: str = "/"
    csrf_cookie_path: str = "/"
    csrf_header_name: str = "X-CSRF-Token"

    @field_validator(
        "transport_header_name",
        "access_cookie_name",
        "refresh_cookie_name",
        "csrf_cookie_name",
        "access_cookie_path",
        "refresh_cookie_path",
        "csrf_cookie_path",
        "csrf_header_name",
    )
    @classmethod
    def normalize_required_strings(cls, value: str) -> str:
        """Normalize required string settings and reject blank values."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("browser_sessions string settings must be non-empty.")
        return normalized

    @field_validator("cookie_domain")
    @classmethod
    def normalize_cookie_domain(cls, value: str | None) -> str | None:
        """Treat blank cookie domains as unset."""
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def validate_cookie_prefix_constraints(self) -> BrowserSessionSettings:
        """Validate cookie-prefix semantics when browser sessions are enabled."""
        if not self.enabled:
            return self

        cookie_specs = (
            (
                "access_cookie_name",
                self.access_cookie_name,
                "access_cookie_path",
                self.access_cookie_path,
            ),
            (
                "refresh_cookie_name",
                self.refresh_cookie_name,
                "refresh_cookie_path",
                self.refresh_cookie_path,
            ),
            (
                "csrf_cookie_name",
                self.csrf_cookie_name,
                "csrf_cookie_path",
                self.csrf_cookie_path,
            ),
        )

        for field_name, cookie_name, path_field_name, cookie_path in cookie_specs:
            if cookie_name.startswith("__Secure-") and not self.secure_only:
                raise ValueError(
                    f"browser_sessions.{field_name} uses '__Secure-' and requires "
                    "browser_sessions.secure_only=true."
                )
            if not cookie_name.startswith("__Host-"):
                continue
            if not self.secure_only:
                raise ValueError(
                    f"browser_sessions.{field_name} uses '__Host-' and requires "
                    "browser_sessions.secure_only=true."
                )
            if self.cookie_domain is not None:
                raise ValueError(
                    f"browser_sessions.{field_name} uses '__Host-' and requires "
                    "browser_sessions.cookie_domain to be unset."
                )
            if cookie_path != "/":
                raise ValueError(
                    f"browser_sessions.{field_name} uses '__Host-' and requires "
                    f"browser_sessions.{path_field_name}='/'."
                )

        return self


class SigningKeySettings(BaseModel):
    """Signing-key rotation and encryption settings."""

    rotation_overlap_seconds: int = Field(default=900, ge=0)
    encryption_key: SecretStr | None = None


class EmailSettings(BaseModel):
    """Email delivery settings for local Mailhog workflows."""

    mailhog_host: str = "localhost"
    mailhog_port: int = Field(default=1025, ge=1, le=65535)
    email_from: str = "auth@localhost"
    public_base_url: AnyHttpUrl = "http://localhost:8000"
    email_verify_ttl_seconds: int = Field(default=86400, ge=1)
    password_reset_ttl_seconds: int = Field(default=3600, ge=1)
    otp_code_length: int = Field(default=6, ge=4, le=12)
    otp_ttl_seconds: int = Field(default=600, ge=1)
    otp_max_attempts: int = Field(default=5, ge=1)
    action_token_ttl_seconds: int = Field(default=300, ge=1)


class SmsSettings(BaseModel):
    """SMS delivery provider selection and local-provider tuning."""

    provider: Literal["local", "twilio", "sns"] = "local"
    local_ttl_seconds: int = Field(default=600, ge=60, le=3600)


class MfaRateLimits(BaseModel):
    """Configurable rate-limit thresholds applied to MFA flows."""

    sms_request_per_hour_per_user: int = Field(default=3, ge=1)
    sms_request_per_hour_per_ip: int = Field(default=5, ge=1)
    sms_resend_per_challenge: int = Field(default=3, ge=1)
    sms_verify_attempts_per_challenge: int = Field(default=5, ge=1)
    recovery_code_attempts_per_15min: int = Field(default=5, ge=1)


class MfaSettings(BaseModel):
    """SDK-managed MFA configuration for SMS + recovery-code flows."""

    sms: SmsSettings = SmsSettings()
    rate_limits: MfaRateLimits = MfaRateLimits()
    sms_code_length: int = Field(default=6, ge=4, le=12)
    sms_code_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    sms_max_attempts: int = Field(default=5, ge=1)
    challenge_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    action_token_ttl_seconds: int = Field(default=300, ge=60, le=3600)
    recovery_code_count: int = Field(default=10, ge=6, le=20)
    recovery_code_length: int = Field(default=10, ge=8, le=16)
    phone_encryption_key: SecretStr | None = None
    phone_lookup_hash_key: SecretStr | None = None


class WebhookSettings(BaseModel):
    """Webhook delivery, signing, and worker settings."""

    queue_name: str = "webhooks"
    request_timeout_seconds: int = Field(default=10, ge=1)
    response_body_max_chars: int = Field(default=1000, ge=1)
    worker_ttl_seconds: int = Field(default=120, ge=30)
    redis_health_check_interval_seconds: int = Field(default=30, ge=0)
    secret_encryption_key: SecretStr | None = None


class RetentionSettings(BaseModel):
    """Data-retention settings for purge support."""

    enable_retention_purge: bool = False
    audit_log_retention_days: int = Field(default=90, ge=1)
    session_log_retention_days: int = Field(default=30, ge=1)
    purge_cron: str = "0 3 * * *"

    @field_validator("purge_cron")
    @classmethod
    def normalize_purge_cron(cls, value: str) -> str:
        """Require a non-empty cron expression for scheduled retention runs."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("retention.purge_cron must be non-empty.")
        return normalized


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
    auth: AuthSettings = AuthSettings()
    session_security: SessionSecuritySettings = SessionSecuritySettings()
    browser_sessions: BrowserSessionSettings = BrowserSessionSettings()
    signing_keys: SigningKeySettings = SigningKeySettings()
    email: EmailSettings = EmailSettings()
    mfa: MfaSettings = MfaSettings()
    webhook: WebhookSettings = WebhookSettings()
    retention: RetentionSettings = RetentionSettings()
    admin_api_key: SecretStr | None = None

    @model_validator(mode="after")
    def validate_production_constraints(self) -> Settings:
        """Reject unsafe production deployments at process startup."""
        if self.app.environment != "production":
            return self

        if self.admin_api_key is not None:
            raise ValueError("admin_api_key cannot be configured in production.")
        if not self.app.allowed_hosts:
            raise ValueError("app.allowed_hosts must be configured in production.")
        if any(host == "*" for host in self.app.allowed_hosts):
            raise ValueError("app.allowed_hosts cannot include '*' in production.")
        if self.signing_keys.encryption_key is None:
            raise ValueError("signing_keys.encryption_key is required in production.")
        if self.session_security.refresh_token_hash_key is None:
            raise ValueError("session_security.refresh_token_hash_key is required in production.")
        if self.webhook.secret_encryption_key is None:
            raise ValueError("webhook.secret_encryption_key is required in production.")
        if self.oauth.google_redirect_uri.scheme != "https":
            raise ValueError("oauth.google_redirect_uri must use https in production.")
        if any(url.scheme != "https" for url in self.oauth.redirect_uri_allowlist):
            raise ValueError("oauth.redirect_uri_allowlist entries must use https in production.")
        if self.saml.sp_acs_url.scheme != "https":
            raise ValueError("saml.sp_acs_url must use https in production.")
        if self.saml.idp_sso_url.scheme != "https":
            raise ValueError("saml.idp_sso_url must use https in production.")
        if not str(self.email.public_base_url).startswith("https://"):
            raise ValueError("email.public_base_url must use https in production.")
        if self.browser_sessions.enabled and not self.browser_sessions.secure_only:
            raise ValueError("browser_sessions.secure_only must be true in production.")
        if self.mfa.sms.provider == "local":
            raise ValueError("mfa.sms.provider cannot be 'local' in production.")
        if self.mfa.phone_encryption_key is None:
            raise ValueError("mfa.phone_encryption_key is required in production.")
        if self.mfa.phone_lookup_hash_key is None:
            raise ValueError("mfa.phone_lookup_hash_key is required in production.")

        return self


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


def _settings_source_fingerprint() -> str:
    """Return a stable fingerprint for the active settings sources."""
    hasher = hashlib.sha256()

    for key, value in sorted(os.environ.items()):
        hasher.update(key.encode("utf-8", errors="surrogateescape"))
        hasher.update(b"\0")
        hasher.update(value.encode("utf-8", errors="surrogateescape"))
        hasher.update(b"\0")

    env_file = Settings.model_config.get("env_file")
    env_files = env_file if isinstance(env_file, list | tuple) else (env_file,)
    for raw_path in env_files:
        if raw_path in (None, "", "."):
            continue

        path = Path(raw_path)
        hasher.update(str(path.resolve(strict=False)).encode("utf-8", errors="surrogateescape"))
        try:
            stat = path.stat()
        except FileNotFoundError:
            hasher.update(b"\0")
            continue

        hasher.update(str(stat.st_mtime_ns).encode("ascii"))
        hasher.update(b":")
        hasher.update(str(stat.st_size).encode("ascii"))

    return hasher.hexdigest()


async def _run_singleton_cleanup(name: str, cleanup: Callable[[Any], Any], value: Any) -> None:
    """Run one registered singleton cleanup callback."""
    try:
        result = cleanup(value)
        if inspect.isawaitable(result):
            await cast(Awaitable[Any], result)
    except Exception:
        _cleanup_logger.exception("reloadable_singleton_cleanup_failed", extra={"name": name})


def _track_singleton_cleanup_task(task: asyncio.Task[None]) -> None:
    """Track one in-loop singleton cleanup task until it finishes."""
    with _SCHEDULED_SINGLETON_CLEANUPS_LOCK:
        _SCHEDULED_SINGLETON_CLEANUPS.add(task)

    def _discard(completed_task: asyncio.Task[None]) -> None:
        with _SCHEDULED_SINGLETON_CLEANUPS_LOCK:
            _SCHEDULED_SINGLETON_CLEANUPS.discard(completed_task)

    task.add_done_callback(_discard)


def _schedule_singleton_cleanup(name: str, cleanup: Callable[[Any], Any], value: Any) -> None:
    """Run cleanup immediately when possible or enqueue it for later draining."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        with _PENDING_SINGLETON_CLEANUPS_LOCK:
            _PENDING_SINGLETON_CLEANUPS.append((name, cleanup, value))
        return

    task = loop.create_task(_run_singleton_cleanup(name, cleanup, value))
    _track_singleton_cleanup_task(task)


async def _await_scheduled_singleton_cleanups() -> None:
    """Await tracked cleanup tasks bound to the current running loop."""
    running_loop = asyncio.get_running_loop()

    while True:
        with _SCHEDULED_SINGLETON_CLEANUPS_LOCK:
            tasks = [
                task
                for task in _SCHEDULED_SINGLETON_CLEANUPS
                if not task.done() and task.get_loop() is running_loop
            ]

        if not tasks:
            return

        await asyncio.gather(*tasks)


async def flush_pending_singleton_cleanups() -> None:
    """Drain deferred and in-flight singleton cleanup work."""
    while True:
        with _PENDING_SINGLETON_CLEANUPS_LOCK:
            pending = list(_PENDING_SINGLETON_CLEANUPS)
            _PENDING_SINGLETON_CLEANUPS.clear()

        for name, cleanup, value in pending:
            await _run_singleton_cleanup(name, cleanup, value)

        await _await_scheduled_singleton_cleanups()

        with _PENDING_SINGLETON_CLEANUPS_LOCK:
            has_pending = bool(_PENDING_SINGLETON_CLEANUPS)
        with _SCHEDULED_SINGLETON_CLEANUPS_LOCK:
            has_scheduled = any(
                not task.done() and task.get_loop() is asyncio.get_running_loop()
                for task in _SCHEDULED_SINGLETON_CLEANUPS
            )
        if not has_pending and not has_scheduled:
            return


def clear_reloadable_singletons() -> None:
    """Clear all registered reloadable singleton caches."""
    with _REGISTERED_SINGLETON_CLEARERS_LOCK:
        clearers = list(_REGISTERED_SINGLETON_CLEARERS)

    for clear in clearers:
        clear()


async def shutdown_reloadable_singletons() -> None:
    """Clear all reloadable singletons and close any pending resources."""
    clear_reloadable_singletons()
    await flush_pending_singleton_cleanups()


def reloadable_singleton(
    func: Callable[[], _T] | None = None,
    *,
    cleanup: Callable[[_T], Any] | None = None,
) -> Callable[[Callable[[], _T]], Callable[[], _T]] | Callable[[], _T]:
    """Cache one zero-argument dependency per settings-source fingerprint."""

    def decorator(factory: Callable[[], _T]) -> Callable[[], _T]:
        lock = RLock()
        cached_version: str | object = _UNSET
        cached_value: _T | object = _UNSET
        hits = 0
        misses = 0
        name = f"{factory.__module__}.{factory.__name__}"

        def _clear_cached_value() -> None:
            nonlocal cached_value, cached_version
            with lock:
                previous = cached_value
                cached_value = _UNSET
                cached_version = _UNSET
            if previous is not _UNSET and cleanup is not None:
                _schedule_singleton_cleanup(name, cast(Callable[[Any], Any], cleanup), previous)

        @wraps(factory)
        def wrapper() -> _T:
            nonlocal cached_value, cached_version, hits, misses

            version = _settings_source_fingerprint()
            if cached_value is not _UNSET and cached_version == version:
                hits += 1
                return cast(_T, cached_value)

            with lock:
                if cached_value is not _UNSET and cached_version == version:
                    hits += 1
                    return cast(_T, cached_value)

                previous = cached_value
                value = factory()
                cached_value = value
                cached_version = version
                misses += 1

            if previous is not _UNSET and cleanup is not None and previous is not value:
                _schedule_singleton_cleanup(name, cast(Callable[[Any], Any], cleanup), previous)

            return value

        def cache_clear() -> None:
            _clear_cached_value()

        def cache_info() -> Any:
            currsize = 0 if cached_value is _UNSET else 1
            return _CacheInfo(hits, misses, 1, currsize)

        wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
        wrapper.cache_info = cache_info  # type: ignore[attr-defined]

        with _REGISTERED_SINGLETON_CLEARERS_LOCK:
            _REGISTERED_SINGLETON_CLEARERS.append(cache_clear)

        return wrapper

    if func is None:
        return decorator
    return decorator(func)


@reloadable_singleton
def get_settings() -> Settings:
    """Load application settings from the current environment."""
    return Settings()
