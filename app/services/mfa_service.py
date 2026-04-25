"""SDK-managed MFA orchestrator.

The MfaService coordinates SMS-OTP and recovery-code flows for:

- phone enrollment (``request_phone_verification`` / ``verify_phone``)
- enable / disable / regenerate-recovery-codes
- generic login challenges (``start_login_challenge`` / ``verify_login`` / ``resend_login_code``)
- step-up action codes (``request_action_code`` / ``verify_action_code``)

This release introduces the service alongside the legacy
``app.services.otp_service`` so existing routers keep working. Release 5
deletes the legacy service and wires this orchestrator into HTTP routes.

Design notes:

- Challenge tokens are signed JWTs with type ``otp_challenge`` to share the
  existing JWT type set; their ``jti`` is bound to a Redis row in
  :class:`app.core.mfa.challenge.MfaChallengeStore` so the JWT alone is
  insufficient to verify a challenge — a matching live Redis row must exist.
- Recovery codes are returned in plaintext exactly once at enrollment and
  regeneration time. They are stored only as keyed-HMAC hashes via
  :func:`app.core.mfa.codes.hash_recovery_code`.
- Phone numbers are encrypted at rest via Fernet
  (:class:`app.core.mfa.phone.PhoneCipher`) with a separate keyed-HMAC lookup
  hash powering the partial unique index on ``users.phone_lookup_hash``.
- All flows respect the existing brute-force surface; per-purpose attempt
  counts live inside the challenge row, while shared lockouts continue to be
  managed by :class:`app.services.brute_force_service.BruteForceProtectionService`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings, reloadable_singleton
from app.core.jwt import (
    Audience,
    JWTService,
    TokenValidationError,
    decode_unverified_jwt_claims,
    get_jwt_service,
    issue_token_async_compat,
    merge_audiences,
    normalize_audiences,
)
from app.core.mfa.challenge import (
    ChallengeState,
    MfaChallengePurpose,
    MfaChallengeStore,
    MfaChallengeStoreError,
)
from app.core.mfa.codes import (
    generate_recovery_codes,
    generate_sms_otp,
    hash_recovery_code,
    hash_sms_otp,
    verify_recovery_code,
    verify_sms_otp,
)
from app.core.mfa.phone import (
    PhoneCipher,
    PhoneHasher,
    PhoneValidationError,
    mask_e164,
    normalize_e164,
)
from app.core.sessions import (
    SessionService,
    get_redis_client,
    get_session_service,
)
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.models.recovery_code import UserRecoveryCode
from app.models.user import User
from app.services.brute_force_service import (
    BruteForceProtectionError,
    BruteForceProtectionService,
    get_brute_force_service,
    suspicious_login_reasons,
)
from app.services.sms.base import SmsSender
from app.services.sms.factory import get_sms_sender
from app.services.token_service import TokenPair, TokenService, get_token_service

# Action types accepted by ``request_action_code`` / ``verify_action_code``.
# Mirrors the legacy ``OTPAction`` literal but uses the new ``enable_mfa`` /
# ``disable_mfa`` / ``regenerate_recovery_codes`` names introduced in Release 4.
MfaAction = Literal[
    "role_change",
    "delete_user",
    "revoke_sessions",
    "rotate_signing_key",
    "erase_account",
    "admin_erase_user",
    "enable_mfa",
    "disable_mfa",
    "regenerate_recovery_codes",
]

LoginVerificationMethod = Literal["sms", "recovery_code"]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MfaServiceError(Exception):
    """Stable error envelope surfaced to callers and translated to HTTP responses."""

    def __init__(
        self,
        detail: str,
        code: str,
        status_code: int,
        *,
        headers: dict[str, str] | None = None,
        user_id: str | None = None,
        audit_events: tuple[str, ...] = (),
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code
        self.headers = headers or {}
        self.user_id = user_id
        self.audit_events = audit_events


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhoneVerificationRequestResult:
    """Outcome of a phone-verify SMS dispatch."""

    user_id: str
    masked_destination: str
    expires_in: int


@dataclass(frozen=True)
class EnableMfaResult:
    """Recovery codes plus the canonical enabled state."""

    user_id: str
    primary_method: str
    recovery_codes: list[str]


@dataclass(frozen=True)
class LoginChallengeResult:
    """Issued login MFA challenge."""

    user_id: str
    challenge_token: str
    method: LoginVerificationMethod
    masked_destination: str
    expires_in: int


@dataclass(frozen=True)
class LoginVerificationResult:
    """Successful login MFA verification."""

    user_id: str
    session_id: UUID
    token_pair: TokenPair
    method_used: LoginVerificationMethod
    suspicious_login: dict[str, Any] | None = None


@dataclass(frozen=True)
class ActionRequestResult:
    """Outcome of an action OTP dispatch."""

    user_id: str
    action: MfaAction
    expires_in: int


@dataclass(frozen=True)
class ActionVerificationResult:
    """Successful action OTP verification, returning a single-use action token."""

    user_id: str
    action: MfaAction
    action_token: str


# ---------------------------------------------------------------------------
# MfaService
# ---------------------------------------------------------------------------


class MfaService:
    """SDK-owned MFA service for phone enrollment, login challenges, and step-up."""

    def __init__(
        self,
        *,
        jwt_service: JWTService,
        signing_key_service: SigningKeyService,
        token_service: TokenService,
        session_service: SessionService,
        brute_force_service: BruteForceProtectionService,
        redis_client: Redis,
        challenge_store: MfaChallengeStore,
        sms_sender: SmsSender,
        phone_cipher: PhoneCipher,
        phone_hasher: PhoneHasher,
        settings: Settings,
    ) -> None:
        self._jwt_service = jwt_service
        self._signing_key_service = signing_key_service
        self._token_service = token_service
        self._session_service = session_service
        self._brute_force_service = brute_force_service
        self._redis = redis_client
        self._challenge_store = challenge_store
        self._sms_sender = sms_sender
        self._phone_cipher = phone_cipher
        self._phone_hasher = phone_hasher
        self._settings = settings
        self._mfa = settings.mfa
        self._auth_service_audience = settings.app.service

    # ------------------------------------------------------------------
    # Phone enrollment
    # ------------------------------------------------------------------

    async def request_phone_verification(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        raw_phone: str,
    ) -> PhoneVerificationRequestResult:
        """Issue a phone-verify SMS challenge for ``raw_phone``."""
        try:
            normalized_phone = normalize_e164(raw_phone)
        except PhoneValidationError as exc:
            raise MfaServiceError(
                "Phone number is invalid.",
                "phone_invalid",
                400,
                user_id=user_id,
            ) from exc

        user = await self._require_user(db_session=db_session, user_id=user_id)
        await self._ensure_phone_available(
            db_session=db_session,
            phone_lookup_hash=self._phone_hasher.lookup_hash(normalized_phone),
            current_user_id=user.id,
        )

        code = generate_sms_otp(self._mfa.sms_code_length)
        # Phone-verify does not issue a challenge JWT (we expect the user to
        # POST their authenticated session + the code). A synthetic jti keeps
        # the schema consistent with login/action challenges.
        jti = uuid4().hex
        await self._challenge_store.store_safely(
            user_id=str(user.id),
            purpose="phone_verify",
            method="sms",
            code_hash=hash_sms_otp(code),
            jti=jti,
            ttl_seconds=self._mfa.sms_code_ttl_seconds,
            audience=None,
            pending_phone_lookup_hash=self._phone_hasher.lookup_hash(normalized_phone),
            pending_phone_ciphertext=self._phone_cipher.encrypt(normalized_phone),
        )

        await self._sms_sender.send_otp_sms(
            to_phone_e164=normalized_phone,
            code=code,
            expires_in_seconds=self._mfa.sms_code_ttl_seconds,
            purpose="phone_verify",
        )

        return PhoneVerificationRequestResult(
            user_id=str(user.id),
            masked_destination=mask_e164(normalized_phone),
            expires_in=self._mfa.sms_code_ttl_seconds,
        )

    async def verify_phone(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        code: str,
    ) -> User:
        """Consume the phone-verify challenge and persist the encrypted phone."""
        user = await self._require_user(db_session=db_session, user_id=user_id)
        challenge = await self._load_or_expired(user_id=str(user.id), purpose="phone_verify")

        await self._consume_or_increment(
            challenge=challenge,
            user_id=str(user.id),
            purpose="phone_verify",
            raw_code=code,
            verifier=verify_sms_otp,
        )

        # Pull pending phone state from the challenge row and persist on the user.
        ciphertext_hex, lookup_hash = self._extract_pending_phone(challenge)
        if ciphertext_hex is None or lookup_hash is None:
            raise MfaServiceError(
                "Phone challenge is missing pending state.",
                "challenge_expired",
                401,
                user_id=str(user.id),
            )

        user.phone_ciphertext = bytes.fromhex(ciphertext_hex)
        user.phone_lookup_hash = lookup_hash
        # Decrypt to capture last-4 without storing plaintext beyond the call.
        plaintext = self._phone_cipher.decrypt(user.phone_ciphertext)
        user.phone_last4 = plaintext[-4:]
        user.phone_verified = True
        user.phone_verified_at = datetime.now(UTC)

        await db_session.flush()
        await self._challenge_store.delete(user_id=str(user.id), purpose="phone_verify")
        await db_session.commit()
        return user

    # ------------------------------------------------------------------
    # Enable / disable / regenerate
    # ------------------------------------------------------------------

    async def enable_mfa(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        action_token: str | None,
    ) -> EnableMfaResult:
        """Enable SMS MFA for the user and return one-time recovery codes."""
        await self._require_action_token(
            db_session=db_session,
            token=action_token,
            expected_action="enable_mfa",
            user_id=user_id,
        )
        user = await self._require_user(db_session=db_session, user_id=user_id)
        if not user.phone_verified:
            raise MfaServiceError(
                "Phone is not verified.",
                "phone_not_verified",
                400,
                user_id=user_id,
            )
        if user.mfa_enabled:
            raise MfaServiceError(
                "MFA is already enabled.",
                "mfa_already_enabled",
                400,
                user_id=user_id,
            )

        plaintext_codes = generate_recovery_codes(
            count=self._mfa.recovery_code_count,
            length=self._mfa.recovery_code_length,
        )
        await self._persist_recovery_codes(
            db_session=db_session,
            user_id=user.id,
            hashes=[hash_recovery_code(code) for code in plaintext_codes],
        )

        user.mfa_enabled = True
        user.mfa_primary_method = "sms"
        await db_session.flush()
        await db_session.commit()

        return EnableMfaResult(
            user_id=str(user.id),
            primary_method="sms",
            recovery_codes=plaintext_codes,
        )

    async def disable_mfa(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        action_token: str | None,
    ) -> User:
        """Disable MFA and clear all live MFA state for the user."""
        await self._require_action_token(
            db_session=db_session,
            token=action_token,
            expected_action="disable_mfa",
            user_id=user_id,
        )
        user = await self._require_user(db_session=db_session, user_id=user_id)

        user.mfa_enabled = False
        user.mfa_primary_method = None
        await self._invalidate_recovery_codes(db_session=db_session, user_id=user.id)
        await self._clear_user_challenge_state(user_id=str(user.id))
        await db_session.flush()
        await db_session.commit()
        return user

    async def regenerate_recovery_codes(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        action_token: str | None,
    ) -> list[str]:
        """Invalidate any unused recovery codes and issue a fresh batch."""
        await self._require_action_token(
            db_session=db_session,
            token=action_token,
            expected_action="regenerate_recovery_codes",
            user_id=user_id,
        )
        user = await self._require_user(db_session=db_session, user_id=user_id)

        await self._invalidate_recovery_codes(db_session=db_session, user_id=user.id)
        plaintext_codes = generate_recovery_codes(
            count=self._mfa.recovery_code_count,
            length=self._mfa.recovery_code_length,
        )
        await self._persist_recovery_codes(
            db_session=db_session,
            user_id=user.id,
            hashes=[hash_recovery_code(code) for code in plaintext_codes],
        )
        await db_session.flush()
        await db_session.commit()
        return plaintext_codes

    # ------------------------------------------------------------------
    # Login challenge / verify / resend
    # ------------------------------------------------------------------

    async def start_login_challenge(
        self,
        *,
        db_session: AsyncSession,
        user: User,
        requested_audience: str | None = None,
    ) -> LoginChallengeResult:
        """Issue an SMS-backed login MFA challenge for an MFA-enabled user."""
        if not user.phone_verified or user.phone_ciphertext is None:
            raise MfaServiceError(
                "Phone is not verified.",
                "phone_not_verified",
                400,
                user_id=str(user.id),
            )

        plaintext_phone = self._phone_cipher.decrypt(user.phone_ciphertext)
        code = generate_sms_otp(self._mfa.sms_code_length)

        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        challenge_token = await issue_token_async_compat(
            self._jwt_service,
            subject=str(user.id),
            token_type="otp_challenge",
            expires_in_seconds=self._mfa.challenge_ttl_seconds,
            audience=merge_audiences(self._auth_service_audience, requested_audience),
            additional_claims={"mfa_method": "sms"},
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        jti = self._extract_jti(challenge_token)

        await self._challenge_store.store(
            user_id=str(user.id),
            purpose="login",
            method="sms",
            code_hash=hash_sms_otp(code),
            jti=jti,
            ttl_seconds=self._mfa.challenge_ttl_seconds,
            audience=requested_audience,
        )
        await self._sms_sender.send_otp_sms(
            to_phone_e164=plaintext_phone,
            code=code,
            expires_in_seconds=self._mfa.challenge_ttl_seconds,
            purpose="login",
        )

        return LoginChallengeResult(
            user_id=str(user.id),
            challenge_token=challenge_token,
            method="sms",
            masked_destination=mask_e164(plaintext_phone),
            expires_in=self._mfa.challenge_ttl_seconds,
        )

    async def verify_login(
        self,
        *,
        db_session: AsyncSession,
        challenge_token: str,
        code: str | None,
        recovery_code: str | None,
        client_ip: str | None,
        user_agent: str | None,
    ) -> LoginVerificationResult:
        """Verify an SMS code or recovery code and issue tokens + session."""
        if (code is None or not code.strip()) and (
            recovery_code is None or not recovery_code.strip()
        ):
            raise MfaServiceError(
                "MFA verification requires a code or recovery code.",
                "invalid_code",
                400,
            )
        if (
            code is not None
            and code.strip()
            and recovery_code is not None
            and recovery_code.strip()
        ):
            raise MfaServiceError(
                "Provide either an SMS code or a recovery code, not both.",
                "invalid_code",
                400,
            )

        challenge_claims = await self._validate_challenge_token(
            db_session=db_session,
            token=challenge_token,
        )
        user_id = str(challenge_claims.get("sub", "")).strip()
        if not user_id:
            raise MfaServiceError("Invalid token.", "invalid_token", 401)

        await self._ensure_not_locked(user_id)
        challenge = await self._load_or_expired(user_id=user_id, purpose="login")
        self._challenge_store.assert_jti_matches(
            state=challenge,
            claimed_jti=str(challenge_claims.get("jti", "")),
        )

        user = await self._require_user(db_session=db_session, user_id=user_id, for_update=True)

        if recovery_code is not None and recovery_code.strip():
            method_used: LoginVerificationMethod = "recovery_code"
            consumed = await self._consume_recovery_code(
                db_session=db_session,
                user_id=user.id,
                raw_code=recovery_code,
            )
            if not consumed:
                await self._apply_shared_failed_attempt(user_id)
                raise MfaServiceError(
                    "Invalid recovery code.",
                    "invalid_recovery_code",
                    401,
                    user_id=user_id,
                    audit_events=("mfa.failed",),
                )
        else:
            method_used = "sms"
            await self._consume_or_increment(
                challenge=challenge,
                user_id=user_id,
                purpose="login",
                raw_code=code or "",
                verifier=verify_sms_otp,
            )

        await self._challenge_store.delete(user_id=user_id, purpose="login")

        suspicious_login = await self._record_successful_login(
            user_id=user_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        token_audiences = normalize_audiences(challenge_claims.get("aud"))
        token_pair = await self._token_service.issue_token_pair(
            db_session=db_session,
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            mfa_enabled=user.mfa_enabled,
            scopes=[],
            audience=token_audiences,
        )
        session_id = await self._session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            mfa_enabled=user.mfa_enabled,
            scopes=[],
            raw_access_token=token_pair.access_token,
            raw_refresh_token=token_pair.refresh_token,
            ip_address=client_ip,
            user_agent=user_agent,
            is_suspicious=suspicious_login is not None,
            suspicious_reasons=suspicious_login_reasons(suspicious_login),
        )

        return LoginVerificationResult(
            user_id=user_id,
            session_id=session_id,
            token_pair=token_pair,
            method_used=method_used,
            suspicious_login=suspicious_login,
        )

    async def resend_login_code(
        self,
        *,
        db_session: AsyncSession,
        challenge_token: str,
    ) -> str:
        """Replace the active login OTP with a fresh code, respecting rate limits."""
        challenge_claims = await self._validate_challenge_token(
            db_session=db_session,
            token=challenge_token,
        )
        user_id = str(challenge_claims.get("sub", "")).strip()
        if not user_id:
            raise MfaServiceError("Invalid token.", "invalid_token", 401)

        challenge = await self._load_or_expired(user_id=user_id, purpose="login")
        self._challenge_store.assert_jti_matches(
            state=challenge,
            claimed_jti=str(challenge_claims.get("jti", "")),
        )

        await self._enforce_resend_rate_limit(user_id=user_id)

        user = await self._require_user(db_session=db_session, user_id=user_id)
        if user.phone_ciphertext is None:
            raise MfaServiceError(
                "Phone is not verified.",
                "phone_not_verified",
                400,
                user_id=user_id,
            )

        code = generate_sms_otp(self._mfa.sms_code_length)
        await self._challenge_store.store(
            user_id=user_id,
            purpose="login",
            method="sms",
            code_hash=hash_sms_otp(code),
            jti=challenge.jti,
            ttl_seconds=self._mfa.challenge_ttl_seconds,
            audience=challenge.audience,
        )
        await self._sms_sender.send_otp_sms(
            to_phone_e164=self._phone_cipher.decrypt(user.phone_ciphertext),
            code=code,
            expires_in_seconds=self._mfa.challenge_ttl_seconds,
            purpose="login",
        )
        return user_id

    # ------------------------------------------------------------------
    # Action OTP
    # ------------------------------------------------------------------

    async def request_action_code(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        action: MfaAction,
    ) -> ActionRequestResult:
        """Dispatch an action-OTP SMS for a sensitive authenticated operation."""
        user = await self._require_user(db_session=db_session, user_id=user_id)
        if not user.phone_verified or user.phone_ciphertext is None:
            raise MfaServiceError(
                "Phone is not verified.",
                "phone_not_verified",
                400,
                user_id=user_id,
            )

        code = generate_sms_otp(self._mfa.sms_code_length)
        # Action OTP verification does not require challenge-JWT plumbing —
        # the user is already authenticated. A synthetic jti satisfies the
        # store contract without producing a separate JWT.
        jti = uuid4().hex
        await self._challenge_store.store(
            user_id=user_id,
            purpose="action",
            method="sms",
            code_hash=hash_sms_otp(code),
            jti=jti,
            ttl_seconds=self._mfa.sms_code_ttl_seconds,
            audience=None,
            extra={"action": action},
        )
        await self._sms_sender.send_otp_sms(
            to_phone_e164=self._phone_cipher.decrypt(user.phone_ciphertext),
            code=code,
            expires_in_seconds=self._mfa.sms_code_ttl_seconds,
            purpose="action",
        )
        return ActionRequestResult(
            user_id=user_id,
            action=action,
            expires_in=self._mfa.sms_code_ttl_seconds,
        )

    async def verify_action_code(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        code: str,
        action: MfaAction,
        audience: Audience | None = None,
    ) -> ActionVerificationResult:
        """Verify an action OTP and mint a single-use action token."""
        await self._ensure_not_locked(user_id)
        challenge = await self._load_or_expired(user_id=user_id, purpose="action")

        stored_action = await self._read_challenge_extra(user_id=user_id, key="action")
        if stored_action is None or stored_action != action:
            raise MfaServiceError(
                "OTP action mismatch.",
                "otp_action_mismatch",
                401,
                user_id=user_id,
            )

        await self._consume_or_increment(
            challenge=challenge,
            user_id=user_id,
            purpose="action",
            raw_code=code,
            verifier=verify_sms_otp,
        )

        await self._challenge_store.delete(user_id=user_id, purpose="action")
        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        action_token = await issue_token_async_compat(
            self._jwt_service,
            subject=user_id,
            token_type="action_token",
            expires_in_seconds=self._mfa.action_token_ttl_seconds,
            additional_claims={"action": action},
            audience=merge_audiences(self._auth_service_audience, audience),
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        await db_session.commit()
        return ActionVerificationResult(
            user_id=user_id,
            action=action,
            action_token=action_token,
        )

    async def validate_action_token_for_user(
        self,
        *,
        db_session: AsyncSession,
        token: str | None,
        expected_action: MfaAction,
        user_id: str,
    ) -> bool:
        """Return True when ``token`` is a valid action token for ``(user_id, action)``."""
        if token is None or not token.strip():
            return False
        try:
            await self._validate_action_token(
                db_session=db_session,
                token=token,
                expected_action=expected_action,
                user_id=user_id,
            )
        except MfaServiceError:
            return False
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _require_user(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        for_update: bool = False,
    ) -> User:
        """Resolve a user or raise ``invalid_token``."""
        user = await self._get_user_by_id(
            db_session=db_session,
            user_id=user_id,
            for_update=for_update,
        )
        if user is None:
            raise MfaServiceError("Invalid token.", "invalid_token", 401, user_id=user_id)
        return user

    async def _get_user_by_id(
        self,
        *,
        db_session: AsyncSession,
        user_id: str,
        for_update: bool = False,
    ) -> User | None:
        """Resolve a user, supporting both real ``AsyncSession`` and unit-test fakes.

        Unit tests substitute a ``FakeDb`` that exposes a ``users`` dict keyed by
        user-id strings. Production code paths route through SQLAlchemy.
        """
        try:
            parsed_user_id = UUID(user_id)
        except ValueError:
            return None

        users_dict = getattr(db_session, "users", None)
        if isinstance(users_dict, dict):
            user = users_dict.get(user_id)
            if user is None or getattr(user, "deleted_at", None) is not None:
                return None
            if not getattr(user, "is_active", True):
                return None
            return user

        statement = select(User).where(
            User.id == parsed_user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _ensure_phone_available(
        self,
        *,
        db_session: AsyncSession,
        phone_lookup_hash: str,
        current_user_id: UUID,
    ) -> None:
        """Reject phone enrollment that would collide with another user's phone.

        Both the test ``FakeDb.users`` dict and the production SQLAlchemy session
        are supported. The DB partial unique index on ``phone_lookup_hash`` is
        the authoritative cross-process guard; this lookup just produces a
        nicer error envelope before the insert/update would fail.
        """
        users_dict = getattr(db_session, "users", None)
        if isinstance(users_dict, dict):
            for candidate in users_dict.values():
                if (
                    candidate.id != current_user_id
                    and getattr(candidate, "deleted_at", None) is None
                    and getattr(candidate, "phone_lookup_hash", None) == phone_lookup_hash
                ):
                    raise MfaServiceError(
                        "Phone number is unavailable.",
                        "phone_unavailable",
                        409,
                        user_id=str(current_user_id),
                    )
            return

        statement = select(User).where(
            User.phone_lookup_hash == phone_lookup_hash,
            User.deleted_at.is_(None),
            User.id != current_user_id,
        )
        try:
            result = await db_session.execute(statement)
            existing = result.scalar_one_or_none()
        except Exception:
            existing = None
        if existing is not None:
            raise MfaServiceError(
                "Phone number is unavailable.",
                "phone_unavailable",
                409,
                user_id=str(current_user_id),
            )

    async def _load_or_expired(
        self,
        *,
        user_id: str,
        purpose: MfaChallengePurpose,
    ) -> ChallengeState:
        """Load a live challenge row or raise ``challenge_expired``."""
        try:
            state = await self._challenge_store.load(user_id=user_id, purpose=purpose)
        except MfaChallengeStoreError as exc:
            raise MfaServiceError(exc.detail, exc.code, exc.status_code, user_id=user_id) from exc
        if state is None:
            raise MfaServiceError(
                "MFA challenge is expired.",
                "challenge_expired",
                401,
                user_id=user_id,
            )
        return state

    async def _consume_or_increment(
        self,
        *,
        challenge: ChallengeState,
        user_id: str,
        purpose: MfaChallengePurpose,
        raw_code: str,
        verifier: Any,
    ) -> None:
        """Verify ``raw_code`` against ``challenge`` or increment the attempt counter.

        Successful verification leaves the row in place so callers can clear
        state via ``delete`` after completing follow-up persistence.
        """
        attempt_count = await self._challenge_store.increment_attempts(
            user_id=user_id, purpose=purpose
        )
        if attempt_count > self._mfa.sms_max_attempts:
            await self._challenge_store.delete(user_id=user_id, purpose=purpose)
            await self._apply_shared_failed_attempt(user_id)
            raise MfaServiceError(
                "MFA attempts exceeded.",
                "challenge_expired",
                401,
                user_id=user_id,
                audit_events=("mfa.expired",),
            )
        if not verifier(raw_code.strip(), challenge.code_hash):
            await self._apply_shared_failed_attempt(user_id)
            raise MfaServiceError(
                "Invalid code.",
                "invalid_code",
                401,
                user_id=user_id,
                audit_events=("mfa.failed",),
            )

    async def _validate_challenge_token(
        self,
        *,
        db_session: AsyncSession,
        token: str,
    ) -> dict[str, Any]:
        """Verify the MFA challenge JWT signature and audience."""
        verification_keys = await self._signing_key_service.get_verification_public_keys(db_session)
        try:
            return self._jwt_service.verify_token(
                token.strip(),
                expected_type="otp_challenge",
                public_keys_by_kid=verification_keys,
                expected_audience=self._auth_service_audience,
            )
        except TokenValidationError as exc:
            raise MfaServiceError("Invalid token.", "invalid_token", 401) from exc

    async def _validate_action_token(
        self,
        *,
        db_session: AsyncSession,
        token: str | None,
        expected_action: MfaAction,
        user_id: str,
    ) -> None:
        """Validate signature, action, and subject binding of an action token."""
        if not token or not token.strip():
            raise MfaServiceError(
                "Action token required.",
                "action_token_invalid",
                403,
                headers={"X-MFA-Required": "true", "X-MFA-Action": expected_action},
                user_id=user_id,
            )
        verification_keys = await self._signing_key_service.get_verification_public_keys(db_session)
        try:
            claims = self._jwt_service.verify_token(
                token.strip(),
                expected_type="action_token",
                public_keys_by_kid=verification_keys,
                expected_audience=self._auth_service_audience,
            )
        except TokenValidationError as exc:
            raise MfaServiceError(
                "Invalid action token.",
                "action_token_invalid",
                403,
                user_id=user_id,
            ) from exc
        if claims.get("action") != expected_action or str(claims.get("sub", "")) != user_id:
            raise MfaServiceError(
                "Invalid action token.",
                "action_token_invalid",
                403,
                user_id=user_id,
            )

    async def _require_action_token(
        self,
        *,
        db_session: AsyncSession,
        token: str | None,
        expected_action: MfaAction,
        user_id: str,
    ) -> None:
        """Validate or raise; a thin wrapper around ``_validate_action_token``."""
        await self._validate_action_token(
            db_session=db_session,
            token=token,
            expected_action=expected_action,
            user_id=user_id,
        )

    async def _ensure_not_locked(self, user_id: str) -> None:
        """Translate brute-force lock state into the standard error envelope."""
        try:
            await self._brute_force_service.ensure_not_locked(user_id)
        except BruteForceProtectionError as exc:
            raise MfaServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
                user_id=user_id,
                audit_events=exc.audit_events,
            ) from exc

    async def _apply_shared_failed_attempt(self, user_id: str) -> None:
        """Increment shared failure counters and surface lockout if it triggers."""
        try:
            decision = await self._brute_force_service.record_failed_otp_attempt(user_id)
        except BruteForceProtectionError as exc:
            raise MfaServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
                user_id=user_id,
                audit_events=exc.audit_events,
            ) from exc
        if decision.locked:
            raise MfaServiceError(
                "Account temporarily locked.",
                "account_locked",
                401,
                headers={"Retry-After": str(decision.retry_after or 1)},
                user_id=user_id,
                audit_events=("mfa.failed", "user.locked"),
            )

    async def _record_successful_login(
        self,
        *,
        user_id: str,
        client_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any] | None:
        """Clear lockout state on success and surface suspicious-login metadata."""
        try:
            result = await self._brute_force_service.record_successful_login(
                user_id,
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except BruteForceProtectionError as exc:
            raise MfaServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
                user_id=user_id,
            ) from exc
        return result.metadata if result.suspicious else None

    async def _enforce_resend_rate_limit(self, *, user_id: str) -> None:
        """Cap resends per active challenge as configured in MFA rate limits."""
        key = f"mfa:resend:login:{user_id}"
        try:
            count = int(await self._redis.incr(key))
            if count == 1:
                await self._redis.expire(key, self._mfa.challenge_ttl_seconds)
        except RedisError as exc:
            raise MfaServiceError(
                "Session backend unavailable.",
                "session_backend_unavailable",
                503,
                user_id=user_id,
            ) from exc
        if count > self._mfa.rate_limits.sms_resend_per_challenge:
            raise MfaServiceError(
                "Rate limit exceeded.",
                "rate_limited",
                429,
                user_id=user_id,
            )

    async def _persist_recovery_codes(
        self,
        *,
        db_session: AsyncSession,
        user_id: UUID,
        hashes: list[str],
    ) -> None:
        """Insert recovery-code rows. Tests with ``FakeDb`` write to ``recovery_codes``."""
        recovery_codes = getattr(db_session, "recovery_codes", None)
        if recovery_codes is not None:
            for code_hash in hashes:
                row = UserRecoveryCode(id=uuid4(), user_id=user_id, code_hash=code_hash)
                recovery_codes[row.id] = row
            return
        for code_hash in hashes:
            db_session.add(UserRecoveryCode(user_id=user_id, code_hash=code_hash))
        await db_session.flush()

    async def _invalidate_recovery_codes(
        self,
        *,
        db_session: AsyncSession,
        user_id: UUID,
    ) -> None:
        """Mark every unused recovery code for ``user_id`` as used now."""
        recovery_codes = getattr(db_session, "recovery_codes", None)
        if recovery_codes is not None:
            now = datetime.now(UTC)
            for row in recovery_codes.values():
                if row.user_id == user_id and row.used_at is None:
                    row.used_at = now
            return
        statement = (
            update(UserRecoveryCode)
            .where(UserRecoveryCode.user_id == user_id, UserRecoveryCode.used_at.is_(None))
            .values(used_at=datetime.now(UTC))
        )
        await db_session.execute(statement)

    async def _consume_recovery_code(
        self,
        *,
        db_session: AsyncSession,
        user_id: UUID,
        raw_code: str,
    ) -> bool:
        """Mark the matching unused recovery code as used and return whether it matched."""
        recovery_codes = getattr(db_session, "recovery_codes", None)
        if recovery_codes is not None:
            for row in recovery_codes.values():
                if (
                    row.user_id == user_id
                    and row.used_at is None
                    and verify_recovery_code(raw_code, row.code_hash)
                ):
                    row.used_at = datetime.now(UTC)
                    return True
            return False
        statement = (
            select(UserRecoveryCode)
            .where(UserRecoveryCode.user_id == user_id, UserRecoveryCode.used_at.is_(None))
            .with_for_update()
        )
        result = await db_session.execute(statement)
        for row in result.scalars().all():
            if verify_recovery_code(raw_code, row.code_hash):
                row.used_at = datetime.now(UTC)
                await db_session.flush()
                return True
        return False

    async def _clear_user_challenge_state(self, *, user_id: str) -> None:
        """Delete every per-user MFA challenge row across purposes."""
        for purpose in ("login", "action", "phone_verify"):
            await self._challenge_store.delete(user_id=user_id, purpose=purpose)  # type: ignore[arg-type]

    def _extract_pending_phone(
        self,
        challenge: ChallengeState,
    ) -> tuple[str | None, str | None]:
        """Pull the pending ciphertext + lookup hash stored on a phone-verify row."""
        ciphertext_hex = self._challenge_store.read_extra(
            challenge=challenge, key="pending_phone_ciphertext_hex"
        )
        lookup_hash = self._challenge_store.read_extra(
            challenge=challenge, key="pending_phone_lookup_hash"
        )
        return ciphertext_hex, lookup_hash

    async def _read_challenge_extra(self, *, user_id: str, key: str) -> str | None:
        """Read one extra field stored alongside a challenge row."""
        challenge = await self._challenge_store.load(user_id=user_id, purpose="action")
        if challenge is None:
            return None
        return self._challenge_store.read_extra(challenge=challenge, key=key)

    @staticmethod
    def _extract_jti(token: str) -> str:
        """Return the ``jti`` claim from a freshly issued JWT.

        We call the unverified decoder because we just produced this token
        and immediately need the value the JWT service auto-assigned.
        """
        claims = decode_unverified_jwt_claims(token)
        jti = str(claims.get("jti", "")).strip()
        if not jti:
            raise MfaServiceError("Token issuance failed.", "invalid_token", 500)
        return jti


# ---------------------------------------------------------------------------
# Reloadable singleton factory
# ---------------------------------------------------------------------------


@reloadable_singleton
def get_mfa_service() -> MfaService:
    """Build and cache the MfaService dependency for FastAPI injection."""
    from app.core.mfa.phone import get_phone_cipher, get_phone_hasher

    settings = get_settings()
    return MfaService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        token_service=get_token_service(),
        session_service=get_session_service(),
        brute_force_service=get_brute_force_service(),
        redis_client=get_redis_client(),
        challenge_store=MfaChallengeStore(redis_client=get_redis_client()),
        sms_sender=get_sms_sender(),
        phone_cipher=get_phone_cipher(),
        phone_hasher=get_phone_hasher(),
        settings=settings,
    )
