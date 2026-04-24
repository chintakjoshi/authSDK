"""Unit tests for the local SMS sender and production-guarded factory."""

from __future__ import annotations

import json
from collections import deque
from typing import Any

import pytest

from app.config import get_settings
from app.services.sms.base import SmsSender
from app.services.sms.factory import LOCAL_SMS_MAX_MESSAGES_PER_PHONE, get_sms_sender
from app.services.sms.local import LocalSmsSender


class _FakeRedis:
    """In-process Redis double supporting list writes used by LocalSmsSender."""

    def __init__(self) -> None:
        self.lists: dict[str, deque[str]] = {}
        self.ttls: dict[str, int] = {}
        self.fail_next: Exception | None = None

    def _guard(self) -> None:
        if self.fail_next is not None:
            raised = self.fail_next
            self.fail_next = None
            raise raised

    async def lpush(self, key: str, *values: str) -> int:
        self._guard()
        bucket = self.lists.setdefault(key, deque())
        for value in values:
            bucket.appendleft(value)
        return len(bucket)

    async def ltrim(self, key: str, start: int, stop: int) -> bool:
        self._guard()
        bucket = self.lists.get(key)
        if bucket is None:
            return True
        items = list(bucket)
        trimmed = items[start : stop + 1] if stop >= 0 else items[start:]
        self.lists[key] = deque(trimmed)
        return True

    async def expire(self, key: str, seconds: int) -> bool:
        self._guard()
        if key not in self.lists:
            return False
        self.ttls[key] = seconds
        return True

    async def lrange(self, key: str, start: int, stop: int) -> list[str]:
        self._guard()
        items = list(self.lists.get(key, deque()))
        if stop == -1:
            return items[start:]
        return items[start : stop + 1]


@pytest.fixture()
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture()
def local_sender(fake_redis: _FakeRedis) -> LocalSmsSender:
    return LocalSmsSender(redis_client=fake_redis, ttl_seconds=600)


@pytest.fixture(autouse=True)
def _clear_factory_singleton() -> None:
    """Ensure each test sees a fresh factory cache keyed to its env."""
    get_sms_sender.cache_clear()
    yield
    get_sms_sender.cache_clear()


class TestLocalSmsSender:
    """LocalSmsSender must persist dev messages in a Redis list with TTL."""

    @pytest.mark.asyncio
    async def test_send_persists_message_payload(
        self,
        local_sender: LocalSmsSender,
        fake_redis: _FakeRedis,
    ) -> None:
        await local_sender.send_otp_sms(
            to_phone_e164="+14155552671",
            code="123456",
            expires_in_seconds=600,
            purpose="login",
        )

        key = "sms:local:+14155552671"
        assert key in fake_redis.lists
        payloads = [json.loads(item) for item in fake_redis.lists[key]]
        assert len(payloads) == 1
        stored = payloads[0]
        assert stored["purpose"] == "login"
        assert stored["code"] == "123456"
        assert stored["expires_in_seconds"] == 600
        assert stored["to_phone_e164"] == "+14155552671"
        assert "sent_at" in stored

    @pytest.mark.asyncio
    async def test_send_applies_ttl(
        self,
        local_sender: LocalSmsSender,
        fake_redis: _FakeRedis,
    ) -> None:
        await local_sender.send_otp_sms(
            to_phone_e164="+14155552671",
            code="123456",
            expires_in_seconds=120,
            purpose="login",
        )

        assert fake_redis.ttls["sms:local:+14155552671"] == 600

    @pytest.mark.asyncio
    async def test_send_rejects_invalid_phone(
        self,
        local_sender: LocalSmsSender,
    ) -> None:
        from app.core.mfa.phone import PhoneValidationError

        with pytest.raises(PhoneValidationError):
            await local_sender.send_otp_sms(
                to_phone_e164="not-a-phone",
                code="123456",
                expires_in_seconds=600,
                purpose="login",
            )

    @pytest.mark.asyncio
    async def test_send_never_logs_code_or_full_phone(
        self,
        local_sender: LocalSmsSender,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging

        caplog.set_level(logging.DEBUG)
        await local_sender.send_otp_sms(
            to_phone_e164="+14155552671",
            code="987654",
            expires_in_seconds=600,
            purpose="login",
        )

        combined = "\n".join(record.getMessage() for record in caplog.records)
        assert "987654" not in combined
        assert "+14155552671" not in combined

    @pytest.mark.asyncio
    async def test_send_trims_old_messages(
        self,
        local_sender: LocalSmsSender,
        fake_redis: _FakeRedis,
    ) -> None:
        for index in range(LOCAL_SMS_MAX_MESSAGES_PER_PHONE + 5):
            await local_sender.send_otp_sms(
                to_phone_e164="+14155552671",
                code=str(index).zfill(6),
                expires_in_seconds=600,
                purpose="login",
            )

        payloads = fake_redis.lists["sms:local:+14155552671"]
        assert len(payloads) == LOCAL_SMS_MAX_MESSAGES_PER_PHONE


class TestFactoryEnvironmentGates:
    """Factory selection must honor environment + provider configuration."""

    def test_returns_local_sender_in_development(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP__ENVIRONMENT", "development")
        monkeypatch.setenv("MFA__SMS__PROVIDER", "local")
        get_settings.cache_clear()

        sender = get_sms_sender()

        assert isinstance(sender, LocalSmsSender)
        assert isinstance(sender, SmsSender) or hasattr(sender, "send_otp_sms")

    def test_raises_when_production_with_local_provider(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Defense in depth: even if the startup guard is bypassed, the factory refuses.

        The pydantic ``validate_production_constraints`` model validator already
        rejects ``MFA__SMS__PROVIDER=local`` at process startup. To exercise the
        factory's independent guard we construct a production-mode settings
        object via ``model_construct`` (skipping validators) and inject it
        through :mod:`app.config.get_settings`.
        """
        from app.config import (
            AppSettings,
            DatabaseSettings,
            EmailSettings,
            JWTSettings,
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

        forced_settings = Settings.model_construct(
            app=AppSettings(environment="production", service="auth-service"),
            database=DatabaseSettings(
                url="postgresql+asyncpg://user:pass@db.example.com:5432/auth_service"
            ),
            redis=RedisSettings(url="redis://redis.example.com:6379/0"),
            jwt=JWTSettings(
                private_key_pem="private-key",
                public_key_pem="public-key",
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
            rate_limit=RateLimitSettings(),
            email=EmailSettings(public_base_url="https://auth.example.com"),
            signing_keys=SigningKeySettings(),
            webhook=WebhookSettings(),
            mfa=MfaSettings(sms=SmsSettings(provider="local")),
            admin_api_key=None,
        )
        monkeypatch.setattr(
            "app.services.sms.factory.get_settings",
            lambda: forced_settings,
        )

        with pytest.raises(RuntimeError, match="LocalSmsSender is not permitted"):
            get_sms_sender()

    def test_raises_not_implemented_for_twilio_in_v1(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP__ENVIRONMENT", "development")
        monkeypatch.setenv("MFA__SMS__PROVIDER", "twilio")
        get_settings.cache_clear()

        with pytest.raises(NotImplementedError, match="twilio"):
            get_sms_sender()

    def test_raises_not_implemented_for_sns_in_v1(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP__ENVIRONMENT", "development")
        monkeypatch.setenv("MFA__SMS__PROVIDER", "sns")
        get_settings.cache_clear()

        with pytest.raises(NotImplementedError, match="sns"):
            get_sms_sender()


class TestFactoryCachesAcrossCalls:
    """Factory singleton semantics must align with the rest of the service."""

    def test_factory_returns_same_instance_when_settings_unchanged(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("APP__ENVIRONMENT", "development")
        monkeypatch.setenv("MFA__SMS__PROVIDER", "local")
        get_settings.cache_clear()

        first = get_sms_sender()
        second = get_sms_sender()

        assert first is second


class TestLocalSmsInspection:
    """Tests consuming LocalSmsSender should be able to read back messages."""

    @pytest.mark.asyncio
    async def test_latest_message_helper_returns_most_recent_payload(
        self,
        local_sender: LocalSmsSender,
    ) -> None:
        await local_sender.send_otp_sms(
            to_phone_e164="+14155552671",
            code="111111",
            expires_in_seconds=600,
            purpose="login",
        )
        await local_sender.send_otp_sms(
            to_phone_e164="+14155552671",
            code="222222",
            expires_in_seconds=600,
            purpose="login",
        )

        latest: dict[str, Any] | None = await local_sender.latest_message(
            to_phone_e164="+14155552671"
        )

        assert latest is not None
        assert latest["code"] == "222222"

    @pytest.mark.asyncio
    async def test_latest_message_returns_none_when_no_messages(
        self,
        local_sender: LocalSmsSender,
    ) -> None:
        latest = await local_sender.latest_message(to_phone_e164="+14155552671")
        assert latest is None
