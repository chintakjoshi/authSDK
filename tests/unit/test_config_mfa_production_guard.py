"""Unit tests for MFA and SMS configuration surface and production guards."""

from __future__ import annotations

import pytest

from app.config import (
    AppSettings,
    DatabaseSettings,
    EmailSettings,
    JWTSettings,
    MfaRateLimits,
    MfaSettings,
    OAuthSettings,
    RateLimitSettings,
    RedisSettings,
    SAMLSettings,
    Settings,
    SigningKeySettings,
    SmsSettings,
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
        email=EmailSettings(public_base_url="https://auth.example.com"),
        signing_keys=SigningKeySettings(rotation_overlap_seconds=900),
        webhook=WebhookSettings(queue_name="webhooks", request_timeout_seconds=10),
        mfa=MfaSettings(),
        admin_api_key=None,
    )


def _harden_production_settings(settings: Settings) -> None:
    """Apply the baseline production-safe hardening shared by MFA tests."""
    settings.app.allowed_hosts = ["auth.example.com"]
    settings.signing_keys.encryption_key = "signing-secret"
    settings.session_security.refresh_token_hash_key = "session-hash-secret"
    settings.webhook.secret_encryption_key = "webhook-secret"
    settings.mfa.phone_encryption_key = "phone-encryption-key-32b-minimum!!"
    settings.mfa.phone_lookup_hash_key = "phone-lookup-hash-key"


def test_mfa_settings_expose_expected_defaults() -> None:
    """MFA settings should expose configurable defaults aligned with smsplan."""
    mfa = MfaSettings()
    assert mfa.sms.provider == "local"
    assert mfa.sms.local_ttl_seconds == 600
    assert mfa.sms_code_length == 6
    assert mfa.sms_code_ttl_seconds == 600
    assert mfa.sms_max_attempts == 5
    assert mfa.challenge_ttl_seconds == 600
    assert mfa.action_token_ttl_seconds == 300
    assert mfa.recovery_code_count == 10
    assert mfa.recovery_code_length == 10
    assert mfa.phone_encryption_key is None
    assert mfa.phone_lookup_hash_key is None


def test_mfa_rate_limit_defaults_match_plan() -> None:
    """Default rate-limit thresholds must match the documented plan values."""
    rate_limits = MfaRateLimits()
    assert rate_limits.sms_request_per_hour_per_user == 3
    assert rate_limits.sms_request_per_hour_per_ip == 5
    assert rate_limits.sms_resend_per_challenge == 3
    assert rate_limits.sms_verify_attempts_per_challenge == 5
    assert rate_limits.recovery_code_attempts_per_15min == 5


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("sms_request_per_hour_per_user", 0),
        ("sms_request_per_hour_per_ip", 0),
        ("sms_resend_per_challenge", 0),
        ("sms_verify_attempts_per_challenge", 0),
        ("recovery_code_attempts_per_15min", 0),
    ],
)
def test_mfa_rate_limits_reject_non_positive_values(field_name: str, value: int) -> None:
    """Rate-limit thresholds must reject zero or negative values."""
    with pytest.raises(ValueError):
        MfaRateLimits(**{field_name: value})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("sms_code_length", 3),
        ("sms_code_length", 13),
        ("sms_code_ttl_seconds", 30),
        ("sms_code_ttl_seconds", 3601),
        ("challenge_ttl_seconds", 30),
        ("challenge_ttl_seconds", 3601),
        ("sms_max_attempts", 0),
        ("action_token_ttl_seconds", 30),
        ("action_token_ttl_seconds", 3601),
        ("recovery_code_count", 5),
        ("recovery_code_count", 21),
        ("recovery_code_length", 7),
        ("recovery_code_length", 17),
    ],
)
def test_mfa_settings_reject_out_of_range_values(field_name: str, value: int) -> None:
    """MFA scalar fields must refuse values outside the supported ranges."""
    with pytest.raises(ValueError):
        MfaSettings(**{field_name: value})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("local_ttl_seconds", 30),
        ("local_ttl_seconds", 3601),
    ],
)
def test_sms_settings_reject_invalid_local_ttl(field_name: str, value: int) -> None:
    """SMS settings must refuse TTL values outside the supported bounds."""
    with pytest.raises(ValueError):
        SmsSettings(**{field_name: value})


def test_sms_settings_reject_unknown_provider() -> None:
    """SMS provider literal must only accept the supported providers."""
    with pytest.raises(ValueError):
        SmsSettings(provider="carrier-pigeon")  # type: ignore[arg-type]


def test_development_defaults_allow_local_sms_provider() -> None:
    """Development must accept the default local SMS provider without extra keys."""
    settings = _build_settings()

    validated = settings.validate_production_constraints()

    assert validated is settings
    assert settings.mfa.sms.provider == "local"
    assert settings.mfa.phone_encryption_key is None


def test_production_rejects_local_sms_provider() -> None:
    """Production must refuse to boot when the SMS provider is set to local."""
    settings = _build_settings(environment="production")
    _harden_production_settings(settings)
    settings.mfa.sms.provider = "local"

    with pytest.raises(
        ValueError,
        match="mfa.sms.provider cannot be 'local' in production.",
    ):
        settings.validate_production_constraints()


def test_production_requires_phone_encryption_key() -> None:
    """Production must refuse to boot without a configured phone encryption key."""
    settings = _build_settings(environment="production")
    _harden_production_settings(settings)
    settings.mfa.sms.provider = "twilio"
    settings.mfa.phone_encryption_key = None

    with pytest.raises(
        ValueError,
        match="mfa.phone_encryption_key is required in production.",
    ):
        settings.validate_production_constraints()


def test_production_requires_phone_lookup_hash_key() -> None:
    """Production must refuse to boot without a configured phone lookup hash key."""
    settings = _build_settings(environment="production")
    _harden_production_settings(settings)
    settings.mfa.sms.provider = "twilio"
    settings.mfa.phone_lookup_hash_key = None

    with pytest.raises(
        ValueError,
        match="mfa.phone_lookup_hash_key is required in production.",
    ):
        settings.validate_production_constraints()


def test_production_accepts_hardened_mfa_configuration() -> None:
    """A production-safe configuration with MFA keys set must validate successfully."""
    settings = _build_settings(environment="production")
    _harden_production_settings(settings)
    settings.mfa.sms.provider = "twilio"

    validated = settings.validate_production_constraints()

    assert validated is settings
    assert settings.mfa.sms.provider == "twilio"
    assert settings.mfa.phone_encryption_key is not None
    assert settings.mfa.phone_lookup_hash_key is not None
