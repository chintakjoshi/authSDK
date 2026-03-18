"""Unit tests for production-only configuration hardening."""

from __future__ import annotations

from copy import deepcopy

import pytest

from app.config import (
    AppSettings,
    DatabaseSettings,
    JWTSettings,
    OAuthSettings,
    RateLimitSettings,
    RedisSettings,
    SAMLSettings,
    Settings,
    SigningKeySettings,
    WebhookSettings,
)


def _build_settings(*, environment: str = "development") -> Settings:
    """Construct settings directly without reading process environment."""
    return Settings.model_construct(
        app=AppSettings(
            environment=environment,
            service="auth-service",
            host="0.0.0.0",
            port=8000,
            log_level="INFO",
            trusted_proxy_cidrs=[],
            allowed_hosts=[],
        ),
        database=DatabaseSettings(
            url="postgresql+asyncpg://user:pass@db.example.com:5432/auth_service"
        ),
        redis=RedisSettings(url="redis://redis.example.com:6379/0"),
        jwt=JWTSettings(
            algorithm="RS256",
            private_key_pem="private-key",
            public_key_pem="public-key",
            access_token_ttl_seconds=900,
            refresh_token_ttl_seconds=604800,
        ),
        oauth=OAuthSettings(
            google_client_id="client-id",
            google_client_secret="client-secret",
            google_redirect_uri="https://auth.example.com/auth/oauth/google/callback",
            redirect_uri_allowlist=["https://auth.example.com/auth/oauth/google/callback"],
        ),
        saml=SAMLSettings(
            sp_entity_id="sp-entity",
            sp_acs_url="https://auth.example.com/auth/saml/callback",
            sp_x509_cert="sp-cert",
            sp_private_key="sp-private-key",
            idp_entity_id="idp-entity",
            idp_sso_url="https://idp.example.com/sso",
            idp_x509_cert="idp-cert",
        ),
        rate_limit=RateLimitSettings(
            default_requests_per_minute=120,
            login_requests_per_minute=10,
            token_requests_per_minute=30,
        ),
        signing_keys=SigningKeySettings(rotation_overlap_seconds=900),
        webhook=WebhookSettings(queue_name="webhooks", request_timeout_seconds=10),
        admin_api_key=None,
    )


def test_development_settings_allow_empty_prod_only_fields() -> None:
    """Development keeps permissive defaults used by local workflows and tests."""
    settings = _build_settings()
    assert settings.app.environment == "development"
    assert settings.app.allowed_hosts == []
    assert settings.signing_keys.encryption_key is None
    assert settings.webhook.secret_encryption_key is None


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda settings: settings.app.allowed_hosts.append("auth.example.com"),
            "signing_keys.encryption_key is required in production.",
        ),
        (
            lambda settings: (
                settings.app.allowed_hosts.append("auth.example.com"),
                setattr(settings.signing_keys, "encryption_key", "signing-secret"),
            ),
            "webhook.secret_encryption_key is required in production.",
        ),
        (
            lambda settings: setattr(settings.signing_keys, "encryption_key", "signing-secret"),
            "app.allowed_hosts must be configured in production.",
        ),
    ],
)
def test_production_settings_fail_closed_without_required_controls(mutate, message: str) -> None:
    """Production should refuse to boot when key hardening controls are absent."""
    settings = _build_settings(environment="production")
    mutate(settings)

    with pytest.raises(ValueError, match=message):
        settings.validate_production_constraints()


def test_production_settings_reject_bootstrap_admin_key_and_insecure_urls() -> None:
    """Production must reject dev bootstrap access and non-HTTPS callback URLs."""
    settings = _build_settings(environment="production")
    settings.app.allowed_hosts = ["auth.example.com"]
    settings.signing_keys.encryption_key = "signing-secret"
    settings.webhook.secret_encryption_key = "webhook-secret"
    settings.admin_api_key = "dev-bootstrap-key"

    with pytest.raises(ValueError, match="admin_api_key cannot be configured in production."):
        settings.validate_production_constraints()

    insecure_settings = deepcopy(settings)
    insecure_settings.admin_api_key = None
    insecure_settings.oauth = OAuthSettings(
        google_client_id="client-id",
        google_client_secret="client-secret",
        google_redirect_uri="http://auth.example.com/callback",
        redirect_uri_allowlist=["https://auth.example.com/auth/oauth/google/callback"],
    )

    with pytest.raises(ValueError, match="oauth.google_redirect_uri must use https in production."):
        insecure_settings.validate_production_constraints()


def test_production_settings_accept_hardened_configuration() -> None:
    """A production-safe configuration still validates successfully."""
    settings = _build_settings(environment="production")
    settings.app.allowed_hosts = ["auth.example.com", "*.auth.example.com"]
    settings.signing_keys.encryption_key = "signing-secret"
    settings.webhook.secret_encryption_key = "webhook-secret"

    validated = settings.validate_production_constraints()

    assert validated is settings
    assert settings.app.allowed_hosts == ["auth.example.com", "*.auth.example.com"]
