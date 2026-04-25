"""Shared in-memory test environment for MfaService unit tests.

The environment uses real instances for components that are pure (JWTService,
PhoneCipher, PhoneHasher, MfaChallengeStore, OTPHasher) and lightweight fakes
for components that hit the network/database (Postgres-backed AsyncSession,
TokenService, SessionService, BruteForceProtectionService, SmsSender).

The fakes implement only the subset of behavior the MfaService actually
exercises in unit tests. Integration tests in later releases use the real
implementations against testcontainers Postgres + Redis.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
    WebhookSettings,
)
from app.core.jwt import JWTService
from app.core.mfa.challenge import MfaChallengeStore
from app.core.mfa.phone import PhoneCipher, PhoneHasher
from app.core.signing_keys import SigningKeyMaterial
from app.models.recovery_code import UserRecoveryCode
from app.models.user import User
from app.services.mfa_service import MfaService
from app.services.token_service import TokenPair

# ---------------------------------------------------------------------------
# In-memory Redis double mirroring the subset used by Release 4 components.
# ---------------------------------------------------------------------------


class FakeRedis:
    """Async Redis double covering hashes, lists, scalar counters, and TTLs."""

    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.scalars: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def hset(self, key: str, *, mapping: dict[str, str]) -> int:
        bucket = self.hashes.setdefault(key, {})
        added = sum(1 for field_name in mapping if field_name not in bucket)
        bucket.update({k: str(v) for k, v in mapping.items()})
        return added

    async def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.hashes.get(key, {}))

    async def hincrby(self, key: str, field_name: str, amount: int) -> int:
        bucket = self.hashes.setdefault(key, {})
        new_value = int(bucket.get(field_name, "0")) + amount
        bucket[field_name] = str(new_value)
        return new_value

    async def hset_field(self, key: str, field_name: str, value: str) -> None:
        bucket = self.hashes.setdefault(key, {})
        bucket[field_name] = value

    async def delete(self, *keys: str) -> int:
        removed = 0
        for key in keys:
            if key in self.hashes:
                del self.hashes[key]
                removed += 1
            if key in self.scalars:
                del self.scalars[key]
                removed += 1
            self.ttls.pop(key, None)
        return removed

    async def expire(self, key: str, seconds: int) -> bool:
        if key not in self.hashes and key not in self.scalars:
            return False
        self.ttls[key] = seconds
        return True

    async def get(self, key: str) -> str | None:
        return self.scalars.get(key)

    async def set(
        self,
        key: str,
        value: str,
        *,
        ex: int | None = None,
        nx: bool = False,
    ) -> bool:
        if nx and key in self.scalars:
            return False
        self.scalars[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def incr(self, key: str) -> int:
        new_value = int(self.scalars.get(key, "0")) + 1
        self.scalars[key] = str(new_value)
        return new_value

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -2)


# ---------------------------------------------------------------------------
# In-memory database double — captures only what MfaService reads/writes.
# ---------------------------------------------------------------------------


@dataclass
class FakeDb:
    """Stand-in for AsyncSession exposing the dict-backed user/recovery store."""

    users: dict[str, User] = field(default_factory=dict)
    recovery_codes: dict[UUID, UserRecoveryCode] = field(default_factory=dict)
    commits: int = 0

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        pass

    async def flush(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Fake SMS sender (captures payloads for assertions).
# ---------------------------------------------------------------------------


@dataclass
class FakeSmsSender:
    """Capture outbound SMS payloads for assertions in tests."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def send_otp_sms(
        self,
        *,
        to_phone_e164: str,
        code: str,
        expires_in_seconds: int,
        purpose: str,
    ) -> None:
        self.calls.append(
            {
                "to_phone_e164": to_phone_e164,
                "code": code,
                "expires_in_seconds": expires_in_seconds,
                "purpose": purpose,
            }
        )


# ---------------------------------------------------------------------------
# Fakes for downstream services.
# ---------------------------------------------------------------------------


@dataclass
class FakeBruteForceService:
    """Records calls; never triggers lockouts unless explicitly enabled."""

    locked: bool = False

    async def ensure_not_locked(self, user_id: str) -> None:
        if self.locked:
            from app.services.brute_force_service import BruteForceProtectionError

            raise BruteForceProtectionError(
                "Account temporarily locked.",
                "account_locked",
                401,
                headers={"Retry-After": "60"},
            )

    async def record_failed_otp_attempt(self, user_id: str) -> Any:
        from app.services.brute_force_service import FailureDecision

        return FailureDecision(locked=False, attempt_count=1)

    async def record_successful_login(
        self,
        user_id: str,
        *,
        ip_address: str | None,
        user_agent: str | None,
    ) -> Any:
        from app.services.brute_force_service import SuspiciousLoginResult

        return SuspiciousLoginResult(suspicious=False, metadata={})


@dataclass
class FakeTokenService:
    """Issues opaque token strings. The MfaService treats these as opaque blobs."""

    counter: int = 0

    async def issue_token_pair(
        self,
        db_session: Any,
        user_id: str,
        email: str | None = None,
        role: str = "user",
        email_verified: bool = False,
        mfa_enabled: bool = False,
        scopes: list[str] | None = None,
        auth_time: datetime | None = None,
        audience: Any = None,
    ) -> TokenPair:
        self.counter += 1
        return TokenPair(
            access_token=f"access-{self.counter}",
            refresh_token=f"refresh-{self.counter}",
        )


@dataclass
class FakeSessionService:
    """Records create_login_session calls; returns a deterministic UUID."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    async def create_login_session(
        self,
        *,
        db_session: Any,
        user_id: UUID,
        email: str,
        role: str,
        email_verified: bool,
        mfa_enabled: bool,
        scopes: list[str],
        raw_access_token: str,
        raw_refresh_token: str,
        ip_address: str | None,
        user_agent: str | None,
        is_suspicious: bool = False,
        suspicious_reasons: list[str] | None = None,
    ) -> UUID:
        session_id = uuid4()
        self.calls.append(
            {
                "user_id": user_id,
                "email": email,
                "session_id": session_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "is_suspicious": is_suspicious,
                "suspicious_reasons": suspicious_reasons or [],
            }
        )
        return session_id


@dataclass
class FakeSigningKeyService:
    """Returns a single fixed RSA keypair for the test environment."""

    material: SigningKeyMaterial

    async def get_active_signing_key(self, db_session: Any) -> SigningKeyMaterial:
        return self.material

    async def get_verification_public_keys(self, db_session: Any) -> dict[str, str]:
        return {self.material.kid: self.material.public_key_pem}


# ---------------------------------------------------------------------------
# Public test environment.
# ---------------------------------------------------------------------------


@dataclass
class MfaServiceTestEnvironment:
    """Bundle of collaborators wired into one MfaService for unit tests."""

    settings: Settings
    db: FakeDb
    redis: FakeRedis
    challenge_store: MfaChallengeStore
    phone_cipher: PhoneCipher
    phone_hasher: PhoneHasher
    sms: FakeSmsSender
    token_service: FakeTokenService
    session_service: FakeSessionService
    brute_force: FakeBruteForceService
    signing_keys: FakeSigningKeyService
    jwt_service: JWTService
    service: MfaService

    async def mint_action_token(self, *, user_id: str, action: str) -> str:
        """Sign an action_token JWT for use in step-up gated MFA endpoints."""
        return self.jwt_service.issue_token(
            subject=user_id,
            token_type="action_token",
            expires_in_seconds=300,
            additional_claims={"action": action},
            audience=self.settings.app.service,
            signing_private_key_pem=self.signing_keys.material.private_key_pem,
            signing_kid=self.signing_keys.material.kid,
        )

    def decode_action_token(self, token: str) -> dict[str, Any]:
        """Verify and decode an action_token issued by the test JWT service."""
        return self.jwt_service.verify_token(
            token,
            expected_type="action_token",
            public_keys_by_kid={
                self.signing_keys.material.kid: self.signing_keys.material.public_key_pem
            },
            expected_audience=self.settings.app.service,
        )

    def decode_challenge_token(self, token: str) -> dict[str, Any]:
        """Verify and decode the MFA login challenge JWT."""
        return self.jwt_service.verify_token(
            token,
            expected_type="otp_challenge",
            public_keys_by_kid={
                self.signing_keys.material.kid: self.signing_keys.material.public_key_pem
            },
            expected_audience=self.settings.app.service,
        )

    async def _persist_recovery_code(self, *, user_id: UUID, code_hash: str) -> UserRecoveryCode:
        """Insert a recovery-code row directly for tests setting up prior state."""
        row = UserRecoveryCode(id=uuid4(), user_id=user_id, code_hash=code_hash)
        self.db.recovery_codes[row.id] = row
        return row


def _generate_rsa_keypair() -> tuple[str, str]:
    """Generate a PEM-encoded RSA keypair suitable for JWT signing."""
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


def _build_settings() -> Settings:
    """Construct a development-mode Settings instance for unit tests."""
    return Settings.model_construct(
        app=AppSettings(environment="development", service="auth-service"),
        database=DatabaseSettings(
            url="postgresql+asyncpg://user:pass@db.example.com:5432/auth_service"
        ),
        redis=RedisSettings(url="redis://redis.example.com:6379/0"),
        jwt=JWTSettings(
            private_key_pem="placeholder",
            public_key_pem="placeholder",
        ),
        oauth=OAuthSettings(
            google_client_id="client-id",
            google_client_secret="client-secret",
            google_redirect_uri="http://localhost:8000/auth/oauth/callback",
            redirect_uri_allowlist=["http://localhost:8000/auth/oauth/callback"],
        ),
        saml=SAMLSettings(
            sp_entity_id="sp-entity",
            sp_acs_url="http://localhost:8000/auth/saml/callback",
            sp_x509_cert="sp-cert",
            sp_private_key="sp-private-key",
            idp_entity_id="idp-entity",
            idp_sso_url="http://localhost:9000/sso",
            idp_x509_cert="idp-cert",
        ),
        rate_limit=RateLimitSettings(),
        email=EmailSettings(public_base_url="http://localhost:8000"),
        signing_keys=SigningKeySettings(),
        webhook=WebhookSettings(),
        mfa=MfaSettings(),
        admin_api_key=None,
    )


def build_test_environment() -> MfaServiceTestEnvironment:
    """Assemble the in-memory MfaService environment for one test."""
    settings = _build_settings()
    redis = FakeRedis()
    db = FakeDb()
    sms = FakeSmsSender()
    challenge_store = MfaChallengeStore(redis_client=redis)  # type: ignore[arg-type]
    phone_cipher = PhoneCipher.from_key("test-phone-encryption-key-rotatable")
    phone_hasher = PhoneHasher.from_secret("test-phone-lookup-secret")
    token_service = FakeTokenService()
    session_service = FakeSessionService()
    brute_force = FakeBruteForceService()

    private_pem, public_pem = _generate_rsa_keypair()
    jwt_service = JWTService(private_key_pem=private_pem, public_key_pem=public_pem)
    signing_material = SigningKeyMaterial(
        kid="test-kid",
        public_key_pem=public_pem,
        private_key_pem=private_pem,
        status="active",  # type: ignore[arg-type]
        activated_at=datetime.now(UTC) - timedelta(seconds=60),
        retired_at=None,
    )
    signing_keys = FakeSigningKeyService(material=signing_material)

    service = MfaService(
        jwt_service=jwt_service,
        signing_key_service=signing_keys,  # type: ignore[arg-type]
        token_service=token_service,  # type: ignore[arg-type]
        session_service=session_service,  # type: ignore[arg-type]
        brute_force_service=brute_force,  # type: ignore[arg-type]
        redis_client=redis,  # type: ignore[arg-type]
        challenge_store=challenge_store,
        sms_sender=sms,  # type: ignore[arg-type]
        phone_cipher=phone_cipher,
        phone_hasher=phone_hasher,
        settings=settings,
    )

    return MfaServiceTestEnvironment(
        settings=settings,
        db=db,  # type: ignore[arg-type]
        redis=redis,
        challenge_store=challenge_store,
        phone_cipher=phone_cipher,
        phone_hasher=phone_hasher,
        sms=sms,
        token_service=token_service,
        session_service=session_service,
        brute_force=brute_force,
        signing_keys=signing_keys,
        jwt_service=jwt_service,
        service=service,
    )


__all__ = ["MfaServiceTestEnvironment", "build_test_environment", "FakeDb", "FakeRedis"]


# Backwards-compat for external imports of deque shim used by older tests.
_ = deque  # pragma: no cover
