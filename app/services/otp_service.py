"""Email OTP flows for login MFA and sensitive action gating."""

from __future__ import annotations

import asyncio
import smtplib
from dataclasses import dataclass
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Protocol
from uuid import UUID

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings, reloadable_singleton
from app.core.jwt import (
    Audience,
    JWTService,
    TokenValidationError,
    get_jwt_service,
    merge_audiences,
    normalize_audiences,
)
from app.core.otp import generate_otp, hash_otp, mask_email, verify_otp
from app.core.sessions import (
    SessionService,
    SessionStateError,
    get_redis_client,
    get_session_service,
)
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.models.user import User
from app.schemas.otp import OTPAction
from app.services.brute_force_service import (
    BruteForceProtectionError,
    BruteForceProtectionService,
    get_brute_force_service,
)
from app.services.token_service import TokenPair, TokenService, get_token_service

_OTP_FAILURE_TTL_SECONDS = 3600
_OTP_ISSUANCE_BLOCK_TTL_SECONDS = 900


class OTPServiceError(Exception):
    """Raised for OTP flow failures with stable API payload details."""

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


class OTPEmailSender(Protocol):
    """Contract for login/action OTP email delivery adapters."""

    async def send_login_otp_email(self, to_email: str, code: str, expires_in_seconds: int) -> None:
        """Send a login verification email containing the OTP code."""

    async def send_action_otp_email(
        self,
        to_email: str,
        action: OTPAction,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        """Send an action verification email containing the OTP code."""


@dataclass(frozen=True)
class MailhogOTPEmailSender:
    """SMTP sender targeting local Mailhog for OTP delivery."""

    host: str
    port: int
    email_from: str

    async def send_login_otp_email(self, to_email: str, code: str, expires_in_seconds: int) -> None:
        await asyncio.to_thread(
            self._send_blocking,
            to_email=to_email,
            subject="Your login verification code",
            body=(
                f"Your verification code is: {code}. "
                f"It expires in {expires_in_seconds // 60} minutes."
            ),
        )

    async def send_action_otp_email(
        self,
        to_email: str,
        action: OTPAction,
        code: str,
        expires_in_seconds: int,
    ) -> None:
        await asyncio.to_thread(
            self._send_blocking,
            to_email=to_email,
            subject=f"Verification code for {action}",
            body=(
                f"Your verification code is: {code}. "
                f"It expires in {expires_in_seconds // 60} minutes."
            ),
        )

    def _send_blocking(self, to_email: str, subject: str, body: str) -> None:
        """Send plaintext email using stdlib SMTP client."""
        message = EmailMessage()
        message["From"] = self.email_from
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)

        with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
            smtp.send_message(message)


@dataclass(frozen=True)
class LoginOTPChallengeResult:
    """Issued login OTP challenge payload."""

    user_id: str
    challenge_token: str
    masked_email: str


@dataclass(frozen=True)
class LoginOTPVerificationResult:
    """Successful login OTP verification result."""

    user_id: str
    session_id: UUID
    token_pair: TokenPair
    suspicious_login: dict[str, object] | None = None


@dataclass(frozen=True)
class ActionOTPRequestResult:
    """Successful action OTP issuance result."""

    user_id: str
    action: OTPAction
    expires_in: int


@dataclass(frozen=True)
class ActionOTPVerificationResult:
    """Successful action OTP verification result."""

    user_id: str
    action: OTPAction
    action_token: str


class OTPService:
    """Service responsible for login OTP, action OTP, and enrollment toggles."""

    def __init__(
        self,
        jwt_service: JWTService,
        signing_key_service: SigningKeyService,
        token_service: TokenService,
        session_service: SessionService,
        brute_force_service: BruteForceProtectionService,
        redis_client: Redis,
        email_sender: OTPEmailSender,
        otp_code_length: int,
        otp_ttl_seconds: int,
        otp_max_attempts: int,
        action_token_ttl_seconds: int,
        auth_service_audience: str,
    ) -> None:
        self._jwt_service = jwt_service
        self._signing_key_service = signing_key_service
        self._token_service = token_service
        self._session_service = session_service
        self._brute_force_service = brute_force_service
        self._redis = redis_client
        self._email_sender = email_sender
        self._otp_code_length = otp_code_length
        self._otp_ttl_seconds = otp_ttl_seconds
        self._otp_max_attempts = otp_max_attempts
        self._action_token_ttl_seconds = action_token_ttl_seconds
        self._login_resend_limit = 3
        self._auth_service_audience = auth_service_audience

    async def validate_access_token(
        self,
        db_session: AsyncSession,
        token: str,
    ) -> dict[str, object]:
        """Validate an access token for OTP-protected endpoints."""
        verification_keys = await self._signing_key_service.get_verification_public_keys(db_session)
        try:
            claims = self._jwt_service.verify_token(
                token,
                expected_type="access",
                public_keys_by_kid=verification_keys,
                expected_audience=self._auth_service_audience,
            )
        except TokenValidationError as exc:
            raise OTPServiceError("Invalid token.", "invalid_token", 401) from exc
        await self._ensure_access_token_not_revoked(claims)
        try:
            await self._session_service.validate_access_token_session(
                db_session=db_session,
                access_jti=str(claims.get("jti", "")).strip(),
            )
        except SessionStateError as exc:
            raise OTPServiceError(exc.detail, exc.code, exc.status_code) from exc
        return claims

    async def start_login_challenge(
        self,
        db_session: AsyncSession,
        user: User,
        *,
        requested_audience: str | None = None,
    ) -> LoginOTPChallengeResult:
        """Issue a login OTP challenge instead of immediate auth tokens."""
        user_id = str(user.id)
        await self._ensure_issuance_not_blocked(user_id)

        code = generate_otp(self._otp_code_length)
        await self._store_hash(
            self._login_otp_key(user_id),
            {
                "code_hash": hash_otp(code),
                "attempt_count": "0",
                "created_at": datetime.now(UTC).isoformat(),
            },
            ttl_seconds=self._otp_ttl_seconds,
        )
        await self._email_sender.send_login_otp_email(
            to_email=user.email,
            code=code,
            expires_in_seconds=self._otp_ttl_seconds,
        )

        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        challenge_token = self._jwt_service.issue_token(
            subject=user_id,
            token_type="otp_challenge",
            expires_in_seconds=self._otp_ttl_seconds,
            audience=merge_audiences(self._auth_service_audience, requested_audience),
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        await db_session.commit()
        return LoginOTPChallengeResult(
            user_id=user_id,
            challenge_token=challenge_token,
            masked_email=mask_email(user.email),
        )

    async def verify_login_code(
        self,
        db_session: AsyncSession,
        challenge_token: str,
        code: str,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> LoginOTPVerificationResult:
        """Verify a login OTP and issue the real access/refresh token pair."""
        challenge_claims = await self._validate_challenge_token(db_session, challenge_token)
        user_id = str(challenge_claims.get("sub", "")).strip()
        if not user_id:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)
        await self._ensure_not_locked(user_id)

        key = self._login_otp_key(user_id)
        otp_payload = await self._get_hash(key)
        if not otp_payload or "code_hash" not in otp_payload:
            raise OTPServiceError("OTP expired.", "otp_expired", 401, user_id=user_id)

        attempt_count = await self._increment_hash_counter(key, "attempt_count")
        if attempt_count > self._otp_max_attempts:
            await self._delete_keys(key)
            await self._apply_shared_failed_attempt(user_id)
            raise OTPServiceError(
                "OTP attempts exceeded.",
                "otp_max_attempts_exceeded",
                401,
                user_id=user_id,
                audit_events=("otp.expired",),
            )

        if not verify_otp(code.strip(), otp_payload["code_hash"]):
            await self._apply_shared_failed_attempt(user_id)
            blocked_now = await self._increment_failed_counter(user_id)
            events = ("otp.failed", "otp.excessive_failures") if blocked_now else ("otp.failed",)
            raise OTPServiceError(
                "Invalid OTP.",
                "invalid_otp",
                401,
                user_id=user_id,
                audit_events=events,
            )

        await self._delete_keys(key)

        user = await self._get_user_by_id(db_session=db_session, user_id=user_id, for_update=True)
        if user is None:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)

        suspicious_login = await self._record_successful_login(
            user_id=str(user.id),
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
            email_otp_enabled=user.email_otp_enabled,
            scopes=[],
            audience=token_audiences,
        )
        session_id = await self._session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
            scopes=[],
            raw_access_token=token_pair.access_token,
            raw_refresh_token=token_pair.refresh_token,
        )
        return LoginOTPVerificationResult(
            user_id=str(user.id),
            session_id=session_id,
            token_pair=token_pair,
            suspicious_login=suspicious_login,
        )

    async def resend_login_code(
        self,
        db_session: AsyncSession,
        challenge_token: str,
    ) -> str:
        """Replace the active login OTP and resend it through Mailhog."""
        challenge_claims = await self._validate_challenge_token(db_session, challenge_token)
        user_id = str(challenge_claims.get("sub", "")).strip()
        if not user_id:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)

        otp_key = self._login_otp_key(user_id)
        existing = await self._get_hash(otp_key)
        if not existing or "code_hash" not in existing:
            raise OTPServiceError("OTP expired.", "otp_expired", 401, user_id=user_id)

        resend_key = f"otp_resend_login:{user_id}"
        resend_count = await self._increment_counter(resend_key, ttl_seconds=self._otp_ttl_seconds)
        if resend_count > self._login_resend_limit:
            raise OTPServiceError("Rate limit exceeded.", "rate_limited", 429, user_id=user_id)

        user = await self._get_user_by_id(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)

        code = generate_otp(self._otp_code_length)
        await self._store_hash(
            otp_key,
            {
                "code_hash": hash_otp(code),
                "attempt_count": "0",
                "created_at": datetime.now(UTC).isoformat(),
            },
            ttl_seconds=self._otp_ttl_seconds,
        )
        await self._email_sender.send_login_otp_email(
            to_email=user.email,
            code=code,
            expires_in_seconds=self._otp_ttl_seconds,
        )
        return str(user.id)

    async def request_action_code(
        self,
        db_session: AsyncSession,
        user_id: str,
        action: OTPAction,
    ) -> ActionOTPRequestResult:
        """Issue an OTP for a sensitive authenticated action."""
        user = await self._get_user_by_id(db_session=db_session, user_id=user_id, for_update=False)
        if user is None:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)
        if not user.email_verified:
            raise OTPServiceError("Email is not verified.", "email_not_verified", 400)

        await self._ensure_issuance_not_blocked(user_id)

        code = generate_otp(self._otp_code_length)
        await self._store_hash(
            self._action_otp_key(user_id),
            {
                "code_hash": hash_otp(code),
                "attempt_count": "0",
                "created_at": datetime.now(UTC).isoformat(),
                "action": action,
            },
            ttl_seconds=self._otp_ttl_seconds,
        )
        await self._email_sender.send_action_otp_email(
            to_email=user.email,
            action=action,
            code=code,
            expires_in_seconds=self._otp_ttl_seconds,
        )
        return ActionOTPRequestResult(
            user_id=user_id, action=action, expires_in=self._otp_ttl_seconds
        )

    async def verify_action_code(
        self,
        db_session: AsyncSession,
        user_id: str,
        code: str,
        action: OTPAction,
        *,
        audience: Audience | None = None,
    ) -> ActionOTPVerificationResult:
        """Verify action OTP and return a short-lived action token."""
        await self._ensure_not_locked(user_id)
        key = self._action_otp_key(user_id)
        otp_payload = await self._get_hash(key)
        if not otp_payload or "code_hash" not in otp_payload:
            raise OTPServiceError("OTP expired.", "otp_expired", 401, user_id=user_id)

        stored_action = otp_payload.get("action")
        if stored_action != action:
            raise OTPServiceError(
                "OTP action mismatch.", "otp_action_mismatch", 401, user_id=user_id
            )

        attempt_count = await self._increment_hash_counter(key, "attempt_count")
        if attempt_count > self._otp_max_attempts:
            await self._delete_keys(key)
            await self._apply_shared_failed_attempt(user_id)
            raise OTPServiceError(
                "OTP attempts exceeded.",
                "otp_max_attempts_exceeded",
                401,
                user_id=user_id,
                audit_events=("otp.expired",),
            )

        if not verify_otp(code.strip(), otp_payload["code_hash"]):
            await self._apply_shared_failed_attempt(user_id)
            blocked_now = await self._increment_failed_counter(user_id)
            events = ("otp.failed", "otp.excessive_failures") if blocked_now else ("otp.failed",)
            raise OTPServiceError(
                "Invalid OTP.",
                "invalid_otp",
                401,
                user_id=user_id,
                audit_events=events,
            )

        await self._delete_keys(key)
        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        action_token = self._jwt_service.issue_token(
            subject=user_id,
            token_type="action_token",
            expires_in_seconds=self._action_token_ttl_seconds,
            additional_claims={"action": action},
            audience=merge_audiences(self._auth_service_audience, audience),
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        await db_session.commit()
        return ActionOTPVerificationResult(
            user_id=user_id, action=action, action_token=action_token
        )

    async def validate_action_token_for_user(
        self,
        db_session: AsyncSession,
        *,
        token: str | None,
        expected_action: OTPAction,
        user_id: str,
    ) -> bool:
        """Return True when a supplied action token is valid for the user/action pair."""
        if not token or not token.strip():
            return False
        try:
            await self._validate_action_token(
                db_session=db_session,
                token=token,
                expected_action=expected_action,
                user_id=user_id,
            )
        except OTPServiceError:
            return False
        return True

    async def require_action_token_for_user(
        self,
        db_session: AsyncSession,
        *,
        token: str | None,
        expected_action: OTPAction,
        user_id: str,
    ) -> None:
        """Require one valid action token for the user/action pair."""
        await self._validate_action_token(
            db_session=db_session,
            token=token,
            expected_action=expected_action,
            user_id=user_id,
        )

    async def enable_email_otp(
        self,
        db_session: AsyncSession,
        user_id: str,
        action_token: str | None,
        *,
        require_action_token: bool = True,
    ) -> User:
        """Enable login OTP for a verified user after action-token validation."""
        user = await self._get_user_by_id(db_session=db_session, user_id=user_id, for_update=True)
        if user is None:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)
        if require_action_token:
            await self._validate_action_token(
                db_session=db_session,
                token=action_token,
                expected_action="enable_otp",
                user_id=user_id,
            )
        if not user.email_verified:
            raise OTPServiceError("Email is not verified.", "email_not_verified", 400)

        user.email_otp_enabled = True
        await db_session.flush()
        await db_session.commit()
        return user

    async def disable_email_otp(
        self,
        db_session: AsyncSession,
        user_id: str,
        action_token: str | None,
        *,
        require_action_token: bool = True,
    ) -> User:
        """Disable login OTP and clear active OTP Redis state."""
        user = await self._get_user_by_id(db_session=db_session, user_id=user_id, for_update=True)
        if user is None:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)
        if require_action_token:
            await self._validate_action_token(
                db_session=db_session,
                token=action_token,
                expected_action="disable_otp",
                user_id=user_id,
            )

        user.email_otp_enabled = False
        await db_session.flush()
        await self.clear_user_otp_state(user_id)
        await db_session.commit()
        return user

    async def clear_user_otp_state(self, user_id: str) -> None:
        """Delete all OTP-related Redis state for one user."""
        await self._delete_keys(
            self._login_otp_key(user_id),
            self._action_otp_key(user_id),
            self._failed_otp_key(user_id),
            self._issuance_block_key(user_id),
            self._login_resend_key(user_id),
        )

    async def _validate_challenge_token(
        self,
        db_session: AsyncSession,
        token: str,
    ) -> dict[str, object]:
        """Validate an OTP login challenge token."""
        verification_keys = await self._signing_key_service.get_verification_public_keys(db_session)
        try:
            return self._jwt_service.verify_token(
                token.strip(),
                expected_type="otp_challenge",
                public_keys_by_kid=verification_keys,
                expected_audience=self._auth_service_audience,
            )
        except TokenValidationError as exc:
            raise OTPServiceError("Invalid token.", "invalid_token", 401) from exc

    async def _validate_action_token(
        self,
        db_session: AsyncSession,
        token: str | None,
        expected_action: OTPAction,
        user_id: str,
    ) -> None:
        """Validate action token signature, action claim, and subject binding."""
        if not token or not token.strip():
            raise OTPServiceError(
                "Action token required.",
                "action_token_invalid",
                403,
                headers={"X-OTP-Required": "true", "X-OTP-Action": expected_action},
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
            raise OTPServiceError("Invalid action token.", "action_token_invalid", 403) from exc

        if claims.get("action") != expected_action or str(claims.get("sub", "")) != user_id:
            raise OTPServiceError("Invalid action token.", "action_token_invalid", 403)

    async def _get_user_by_id(
        self,
        db_session: AsyncSession,
        user_id: str,
        *,
        for_update: bool,
    ) -> User | None:
        """Fetch one active, non-deleted user by ID."""
        try:
            parsed_user_id = UUID(user_id)
        except ValueError:
            return None

        statement = select(User).where(
            User.id == parsed_user_id,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        return result.scalar_one_or_none()

    async def _ensure_not_locked(self, user_id: str) -> None:
        """Reject OTP verification attempts while account lockout is active."""
        try:
            await self._brute_force_service.ensure_not_locked(user_id)
        except BruteForceProtectionError as exc:
            raise OTPServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
                user_id=user_id,
                audit_events=exc.audit_events,
            ) from exc

    async def _apply_shared_failed_attempt(self, user_id: str) -> None:
        """Increment shared failed-attempt counters for OTP verification failures."""
        try:
            decision = await self._brute_force_service.record_failed_otp_attempt(user_id)
        except BruteForceProtectionError as exc:
            raise OTPServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
                user_id=user_id,
                audit_events=exc.audit_events,
            ) from exc

        if decision.locked:
            raise OTPServiceError(
                "Account temporarily locked.",
                "account_locked",
                401,
                headers={"Retry-After": str(decision.retry_after or 1)},
                user_id=user_id,
                audit_events=("otp.failed", "user.locked"),
            )

    async def _record_successful_login(
        self,
        user_id: str,
        *,
        client_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, object] | None:
        """Clear lockout state after a successful OTP-backed login."""
        try:
            result = await self._brute_force_service.record_successful_login(
                user_id,
                ip_address=client_ip,
                user_agent=user_agent,
            )
        except BruteForceProtectionError as exc:
            raise OTPServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
                user_id=user_id,
            ) from exc
        return result.metadata if result.suspicious else None

    async def _ensure_issuance_not_blocked(self, user_id: str) -> None:
        """Reject OTP issuance while a temporary block is active."""
        key = self._issuance_block_key(user_id)
        try:
            blocked = await self._redis.get(key)
            ttl = await self._redis.ttl(key) if blocked is not None else -2
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

        if blocked is not None:
            retry_after = ttl if ttl and ttl > 0 else _OTP_ISSUANCE_BLOCK_TTL_SECONDS
            raise OTPServiceError(
                "OTP issuance temporarily blocked.",
                "otp_issuance_blocked",
                429,
                headers={"Retry-After": str(retry_after)},
                user_id=user_id,
            )

    async def _ensure_access_token_not_revoked(self, claims: dict[str, object]) -> None:
        """Reject access tokens that have already been blocklisted."""
        jti = str(claims.get("jti", "")).strip()
        if not jti:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)

        try:
            blocklisted = await self._redis.get(f"blocklist:jti:{jti}")
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

        if blocklisted is not None:
            raise OTPServiceError("Invalid token.", "invalid_token", 401)

    async def _increment_failed_counter(self, user_id: str) -> bool:
        """Increment the cumulative OTP failure counter and set issuance block if needed."""
        key = self._failed_otp_key(user_id)
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, _OTP_FAILURE_TTL_SECONDS)
            blocked_now = False
            if count > 10:
                blocked_now = bool(
                    await self._redis.set(
                        self._issuance_block_key(user_id),
                        "1",
                        ex=_OTP_ISSUANCE_BLOCK_TTL_SECONDS,
                        nx=True,
                    )
                )
            return blocked_now
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

    async def _increment_counter(self, key: str, *, ttl_seconds: int) -> int:
        """Increment a Redis integer counter with first-write TTL initialization."""
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, ttl_seconds)
            return int(count)
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

    async def _increment_hash_counter(self, key: str, field: str) -> int:
        """Atomically increment a counter stored inside a Redis hash."""
        try:
            return int(await self._redis.hincrby(key, field, 1))
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

    async def _get_hash(self, key: str) -> dict[str, str] | None:
        """Return a Redis hash payload or None when missing."""
        try:
            payload = await self._redis.hgetall(key)
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc
        return payload or None

    async def _store_hash(
        self,
        key: str,
        payload: dict[str, str],
        *,
        ttl_seconds: int,
    ) -> None:
        """Overwrite a Redis hash payload and apply TTL."""
        try:
            await self._redis.delete(key)
            await self._redis.hset(key, mapping=payload)
            await self._redis.expire(key, ttl_seconds)
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

    async def _delete_keys(self, *keys: str) -> None:
        """Delete one or more Redis keys, failing closed on backend errors."""
        try:
            if keys:
                await self._redis.delete(*keys)
        except RedisError as exc:
            raise OTPServiceError("Session backend unavailable.", "session_expired", 503) from exc

    @staticmethod
    def _login_otp_key(user_id: str) -> str:
        return f"otp:login:{user_id}"

    @staticmethod
    def _action_otp_key(user_id: str) -> str:
        return f"otp:action:{user_id}"

    @staticmethod
    def _failed_otp_key(user_id: str) -> str:
        return f"otp_failed:{user_id}"

    @staticmethod
    def _issuance_block_key(user_id: str) -> str:
        return f"otp_issuance_blocked:{user_id}"

    @staticmethod
    def _login_resend_key(user_id: str) -> str:
        return f"otp_resend_login:{user_id}"


@reloadable_singleton
def get_otp_email_sender() -> OTPEmailSender:
    """Create and cache default Mailhog-backed OTP email sender."""
    settings = get_settings()
    return MailhogOTPEmailSender(
        host=settings.email.mailhog_host,
        port=settings.email.mailhog_port,
        email_from=settings.email.email_from,
    )


@reloadable_singleton
def get_otp_service() -> OTPService:
    """Create and cache OTP service dependency."""
    settings = get_settings()
    return OTPService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        token_service=get_token_service(),
        session_service=get_session_service(),
        brute_force_service=get_brute_force_service(),
        redis_client=get_redis_client(),
        email_sender=get_otp_email_sender(),
        otp_code_length=settings.email.otp_code_length,
        otp_ttl_seconds=settings.email.otp_ttl_seconds,
        otp_max_attempts=settings.email.otp_max_attempts,
        action_token_ttl_seconds=settings.email.action_token_ttl_seconds,
        auth_service_audience=settings.app.service,
    )
