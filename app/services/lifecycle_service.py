"""Account lifecycle service for signup email verification flows."""

from __future__ import annotations

import asyncio
import html
import secrets
import smtplib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from hashlib import sha256
from typing import Protocol
from urllib.parse import urljoin
from uuid import UUID

import structlog
from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings, reloadable_singleton
from app.core.jwt import JWTService, TokenValidationError, get_jwt_service, normalize_audiences
from app.core.sessions import (
    SessionService,
    SessionStateError,
    get_redis_client,
    get_session_service,
)
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.models.user import User
from app.services.brute_force_service import (
    BruteForceProtectionError,
    BruteForceProtectionService,
    get_brute_force_service,
)
from app.services.token_service import TokenService, get_token_service
from app.services.user_service import UserService, get_user_service

logger = structlog.get_logger(__name__)


class LifecycleServiceError(Exception):
    """Raised for lifecycle flow failures."""

    def __init__(
        self,
        detail: str,
        code: str,
        status_code: int,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code
        self.headers = headers or {}


@dataclass(frozen=True)
class SignupPasswordResult:
    """Outcome for one public password-signup attempt."""

    accepted_email: str
    created_user: User | None = None
    verification_link: str | None = None

    @property
    def created(self) -> bool:
        """Return True when the signup created a new user record."""
        return self.created_user is not None


class LifecycleEmailSender(Protocol):
    """Contract for lifecycle-related email delivery adapters."""

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        """Deliver a verification email."""

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        """Deliver a password reset email."""

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        """Deliver a password reset confirmation email."""


@dataclass(frozen=True)
class MailhogVerificationEmailSender:
    """SMTP sender targeting local Mailhog."""

    host: str
    port: int
    email_from: str

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        """Send a signup verification email through SMTP."""
        subject = "Verify your email"
        await asyncio.to_thread(
            self._send_blocking,
            to_email=to_email,
            subject=subject,
            body=f"Open this link to verify your account: {verification_link}",
            html_body=self._html_link_message(
                intro_text="Open this link to verify your account:",
                link=verification_link,
            ),
        )

    async def send_password_reset_email(self, to_email: str, reset_link: str) -> None:
        """Send a password reset email through SMTP."""
        await asyncio.to_thread(
            self._send_blocking,
            to_email=to_email,
            subject="Reset your password",
            body=f"Open this link to reset your password: {reset_link}",
            html_body=self._html_link_message(
                intro_text="Open this link to reset your password:",
                link=reset_link,
            ),
        )

    async def send_password_reset_confirmation_email(self, to_email: str) -> None:
        """Send a password reset confirmation email through SMTP."""
        await asyncio.to_thread(
            self._send_blocking,
            to_email=to_email,
            subject="Your password has been reset",
            body="Your password was reset successfully. If this was not you, contact support.",
        )

    def _send_blocking(
        self,
        to_email: str,
        subject: str,
        body: str,
        html_body: str | None = None,
    ) -> None:
        """Send plaintext email using stdlib SMTP client."""
        message = EmailMessage()
        message["From"] = self.email_from
        message["To"] = to_email
        message["Subject"] = subject
        message.set_content(body)
        if html_body is not None:
            message.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
            smtp.send_message(message)

    @staticmethod
    def _html_link_message(*, intro_text: str, link: str) -> str:
        """Build one HTML paragraph pair with a safely escaped anchor."""
        escaped_intro = html.escape(intro_text, quote=False)
        escaped_link = html.escape(link, quote=True)
        return f'<p>{escaped_intro}</p><p><a href="{escaped_link}">{escaped_link}</a></p>'


class LifecycleService:
    """Lifecycle orchestration for signup verification and resend flows."""

    def __init__(
        self,
        jwt_service: JWTService,
        signing_key_service: SigningKeyService,
        user_service: UserService,
        redis_client: Redis,
        email_sender: LifecycleEmailSender,
        email_verify_ttl_seconds: int,
        session_service: SessionService | None = None,
        password_reset_ttl_seconds: int = 3600,
        token_service: TokenService | None = None,
        brute_force_service: BruteForceProtectionService | None = None,
        auth_service_audience: str = "auth-service",
        public_base_url: str = "http://localhost:8000",
    ) -> None:
        self._jwt_service = jwt_service
        self._signing_key_service = signing_key_service
        self._user_service = user_service
        self._token_service = token_service
        self._brute_force_service = brute_force_service
        self._session_service = session_service
        self._redis = redis_client
        self._email_sender = email_sender
        self._email_verify_ttl_seconds = email_verify_ttl_seconds
        self._password_reset_ttl_seconds = password_reset_ttl_seconds
        self._resend_limit_ttl_seconds = 3600
        self._resend_limit_count = 3
        self._dummy_password_hash = self._user_service.hash_password("auth-service-dummy-password")
        self._auth_service_audience = auth_service_audience
        self._public_base_url = public_base_url.rstrip("/")

    async def signup_password(
        self,
        db_session: AsyncSession,
        email: str,
        password: str,
    ) -> SignupPasswordResult:
        """Accept a public signup request without revealing whether the email exists."""
        normalized_email = email.strip().lower()
        if not normalized_email:
            raise LifecycleServiceError("Invalid email.", "invalid_credentials", 400)

        user = User(
            email=normalized_email,
            password_hash=self._user_service.hash_password(password),
            is_active=True,
            role="user",
            email_verified=False,
        )
        db_session.add(user)
        verification_link: str | None = None
        try:
            await db_session.flush()
            verification_token, expires_at = await self._issue_email_verify_token(
                db_session=db_session,
                user_id=str(user.id),
            )
            user.email_verify_token_hash = self._hash_verification_token(verification_token)
            user.email_verify_token_expires = expires_at
            verification_link = self._verification_link(verification_token)
            await db_session.flush()
            await db_session.commit()
        except IntegrityError:
            await db_session.rollback()
            if await self._signup_email_exists(db_session=db_session, email=normalized_email):
                self._perform_dummy_password_workload(password)
                return SignupPasswordResult(accepted_email=normalized_email)
            raise
        except Exception:
            await db_session.rollback()
            raise
        return SignupPasswordResult(
            accepted_email=user.email,
            created_user=user,
            verification_link=verification_link,
        )

    async def verify_email_token(
        self,
        db_session: AsyncSession,
        token: str,
    ) -> User:
        """Consume verification token and mark user email as verified."""
        normalized_token = token.strip()
        if not normalized_token:
            raise LifecycleServiceError("Invalid verification token.", "invalid_verify_token", 400)

        await self._verify_email_jwt(db_session=db_session, token=normalized_token)
        token_hash = self._hash_verification_token(normalized_token)
        statement = (
            select(User)
            .where(
                User.email_verify_token_hash == token_hash,
                User.deleted_at.is_(None),
            )
            .with_for_update()
        )
        result = await db_session.execute(statement)
        user = result.scalar_one_or_none()
        now = datetime.now(UTC)
        if (
            user is None
            or user.email_verify_token_expires is None
            or user.email_verify_token_expires <= now
        ):
            raise LifecycleServiceError("Invalid verification token.", "invalid_verify_token", 400)

        user.email_verified = True
        user.email_verify_token_hash = None
        user.email_verify_token_expires = None
        try:
            await db_session.flush()
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise
        return user

    async def validate_access_token(
        self,
        db_session: AsyncSession,
        token: str,
    ) -> dict[str, object]:
        """Validate access token for lifecycle authenticated operations."""
        verification_keys = await self._signing_key_service.get_verification_public_keys(db_session)
        try:
            claims = self._jwt_service.verify_token(
                token,
                expected_type="access",
                public_keys_by_kid=verification_keys,
                expected_audience=self._auth_service_audience,
            )
        except TokenValidationError as exc:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401) from exc
        await self._ensure_access_token_not_revoked(claims)
        if self._session_service is not None:
            try:
                await self._session_service.validate_access_token_session(
                    db_session=db_session,
                    access_jti=str(claims.get("jti", "")).strip(),
                )
            except SessionStateError as exc:
                raise LifecycleServiceError(exc.detail, exc.code, exc.status_code) from exc
        return claims

    async def resend_verification_email(
        self,
        db_session: AsyncSession,
        user_id: str,
    ) -> None:
        """Resend signup verification link with per-user rate limiting."""
        normalized_user_id = user_id.strip()
        try:
            parsed_user_id = UUID(normalized_user_id)
        except ValueError as exc:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401) from exc

        statement = (
            select(User)
            .where(
                User.id == parsed_user_id,
                User.deleted_at.is_(None),
            )
            .with_for_update()
        )
        result = await db_session.execute(statement)
        user = result.scalar_one_or_none()
        if user is None:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401)
        if user.email_verified:
            raise LifecycleServiceError("Email is already verified.", "already_verified", 400)
        await self._enforce_resend_rate_limit(f"user:{normalized_user_id}")
        await self._resend_verification_email_for_user(
            db_session=db_session,
            user=user,
            user_id=normalized_user_id,
        )

    async def request_verification_email_resend(
        self,
        db_session: AsyncSession,
        email: str,
    ) -> str | None:
        """Request a verification-email resend using only the email address."""
        normalized_email = self._normalize_email(email)
        if not normalized_email:
            self._perform_dummy_password_workload("missing-user")
            return None

        await self._enforce_resend_rate_limit(
            f"email:{self._hash_public_resend_identifier(normalized_email)}"
        )
        user = await self._user_service.get_user_by_email(
            db_session=db_session,
            email=normalized_email,
        )
        if user is None:
            self._perform_dummy_password_workload(normalized_email)
            return None
        if user.email_verified:
            return None

        user_id = str(user.id)
        await self._resend_verification_email_for_user(
            db_session=db_session,
            user=user,
            user_id=user_id,
        )
        return user_id

    async def request_password_reset(
        self,
        db_session: AsyncSession,
        email: str,
    ) -> str | None:
        """Issue a single active password reset token when the email exists."""
        normalized_email = email.strip().lower()
        user = None
        if normalized_email:
            user = await self._user_service.get_user_by_email(
                db_session=db_session,
                email=normalized_email,
            )

        if user is None:
            self._perform_dummy_password_workload(normalized_email or "missing-user")
            return None

        reset_token = secrets.token_urlsafe(32)
        user.password_reset_token_hash = self._hash_password_reset_token(reset_token)
        user.password_reset_token_expires = datetime.now(UTC) + timedelta(
            seconds=self._password_reset_ttl_seconds
        )
        try:
            await db_session.flush()
            await self._email_sender.send_password_reset_email(
                to_email=user.email,
                reset_link=self._password_reset_link(reset_token),
            )
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise
        return str(user.id)

    async def validate_password_reset_token(
        self,
        db_session: AsyncSession,
        token: str,
    ) -> None:
        """Validate a raw password reset token without consuming it."""
        user = await self._get_user_by_password_reset_token(
            db_session=db_session,
            token=token,
            for_update=False,
        )
        if user is None:
            raise LifecycleServiceError("Invalid reset token.", "invalid_reset_token", 400)

    async def complete_password_reset(
        self,
        db_session: AsyncSession,
        token: str,
        new_password: str,
    ) -> User:
        """Consume reset token, update password, and synchronously revoke sessions."""
        user = await self._get_user_by_password_reset_token(
            db_session=db_session,
            token=token,
            for_update=True,
        )
        if user is None:
            raise LifecycleServiceError("Invalid reset token.", "invalid_reset_token", 400)
        if self._session_service is None:
            raise RuntimeError("LifecycleService requires session_service for password reset.")

        user.password_hash = self._user_service.hash_password(new_password)
        user.password_reset_token_hash = None
        user.password_reset_token_expires = None
        try:
            await db_session.flush()
            await self._session_service.revoke_user_sessions(
                db_session=db_session,
                user_id=user.id,
                commit=False,
            )
            await db_session.commit()
        except SessionStateError as exc:
            raise LifecycleServiceError(exc.detail, exc.code, exc.status_code) from exc
        except Exception:
            await db_session.rollback()
            raise

        try:
            await self._email_sender.send_password_reset_confirmation_email(to_email=user.email)
        except Exception as exc:
            logger.error(
                "password_reset_confirmation_email_failed",
                user_id=str(user.id),
                error=str(exc),
            )
        return user

    async def reauthenticate(
        self,
        db_session: AsyncSession,
        *,
        access_token: str,
        password: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> str:
        """Re-verify the user's password and mint a fresh access token."""
        claims = await self.validate_access_token(db_session=db_session, token=access_token)
        user_id = str(claims.get("sub", "")).strip()
        access_jti = str(claims.get("jti", "")).strip()
        if not user_id or not access_jti:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401)
        if bool(claims.get("email_otp_enabled", False)):
            raise LifecycleServiceError("OTP required.", "otp_required", 403)
        if self._token_service is None or self._brute_force_service is None:
            raise RuntimeError("LifecycleService requires reauth dependencies.")

        user = await self._get_user_by_id(db_session=db_session, user_id=user_id, for_update=True)
        if user is None or user.password_hash is None:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401)

        try:
            await self._brute_force_service.ensure_not_locked(user_id)
        except BruteForceProtectionError as exc:
            raise LifecycleServiceError(
                exc.detail,
                exc.code,
                exc.status_code,
                headers=exc.headers,
            ) from exc

        if not self._user_service.verify_password(
            password=password, password_hash=user.password_hash
        ):
            try:
                decision = await self._brute_force_service.record_failed_password_attempt(
                    user_id,
                    ip_address=client_ip,
                )
            except BruteForceProtectionError as exc:
                raise LifecycleServiceError(
                    exc.detail,
                    exc.code,
                    exc.status_code,
                    headers=exc.headers,
                ) from exc
            if decision.locked:
                raise LifecycleServiceError(
                    "Account temporarily locked.",
                    "account_locked",
                    401,
                    headers={"Retry-After": str(decision.retry_after or 1)},
                )
            raise LifecycleServiceError("Invalid email or password.", "invalid_credentials", 401)

        auth_time = datetime.now(UTC)
        access_token_result = await self._token_service.issue_access_token(
            db_session=db_session,
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            email_verified=user.email_verified,
            email_otp_enabled=user.email_otp_enabled,
            scopes=(
                [str(scope) for scope in claims.get("scopes", [])]
                if isinstance(claims.get("scopes", []), list)
                else []
            ),
            auth_time=auth_time,
            audience=normalize_audiences(claims.get("aud")),
        )
        if self._session_service is None:
            raise RuntimeError("LifecycleService requires session_service for re-authentication.")
        try:
            await self._session_service.reauthenticate_session(
                db_session=db_session,
                current_access_jti=access_jti,
                new_access_token=access_token_result.access_token,
                auth_time=auth_time,
            )
        except SessionStateError as exc:
            raise LifecycleServiceError(exc.detail, exc.code, exc.status_code) from exc
        return access_token_result.access_token

    async def _issue_email_verify_token(
        self,
        db_session: AsyncSession,
        user_id: str,
    ) -> tuple[str, datetime]:
        """Issue signed email verification token with configured TTL."""
        active_key = await self._signing_key_service.get_active_signing_key(db_session)
        token = self._jwt_service.issue_token(
            subject=user_id,
            token_type="email_verify",
            expires_in_seconds=self._email_verify_ttl_seconds,
            audience=self._auth_service_audience,
            signing_private_key_pem=active_key.private_key_pem,
            signing_kid=active_key.kid,
        )
        expires_at = datetime.now(UTC) + timedelta(seconds=self._email_verify_ttl_seconds)
        return token, expires_at

    async def _verify_email_jwt(self, db_session: AsyncSession, token: str) -> dict[str, object]:
        """Verify email verification token signature, exp, and type."""
        verification_keys = await self._signing_key_service.get_verification_public_keys(db_session)
        try:
            return self._jwt_service.verify_token(
                token,
                expected_type="email_verify",
                public_keys_by_kid=verification_keys,
                expected_audience=self._auth_service_audience,
            )
        except TokenValidationError as exc:
            if exc.code in {"invalid_token", "token_expired"}:
                raise LifecycleServiceError(
                    "Invalid verification token.",
                    "invalid_verify_token",
                    400,
                ) from exc
            raise

    async def _enforce_resend_rate_limit(self, subject: str) -> None:
        """Allow at most 3 resend requests per subject each hour."""
        key = f"email_verify_resend:{subject}"
        try:
            count = await self._redis.incr(key)
            if count == 1:
                await self._redis.expire(key, self._resend_limit_ttl_seconds)
        except RedisError as exc:
            raise LifecycleServiceError(
                "Session backend unavailable.",
                "session_expired",
                503,
            ) from exc

        if count > self._resend_limit_count:
            raise LifecycleServiceError(
                "Rate limit exceeded.",
                "rate_limited",
                429,
            )

    async def _resend_verification_email_for_user(
        self,
        db_session: AsyncSession,
        *,
        user: User,
        user_id: str,
    ) -> None:
        """Issue, persist, and send a fresh verification link for one user."""
        verification_token, expires_at = await self._issue_email_verify_token(
            db_session=db_session,
            user_id=user_id,
        )
        user.email_verify_token_hash = self._hash_verification_token(verification_token)
        user.email_verify_token_expires = expires_at
        try:
            await db_session.flush()
            await self._email_sender.send_verification_email(
                to_email=user.email,
                verification_link=self._verification_link(verification_token),
            )
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    async def send_signup_verification_email(
        self,
        *,
        user_id: str,
        to_email: str,
        verification_link: str,
    ) -> None:
        """Deliver a signup verification email outside the request's latency path."""
        try:
            await self._email_sender.send_verification_email(
                to_email=to_email,
                verification_link=verification_link,
            )
        except Exception:
            logger.exception("signup_verification_email_failed", user_id=user_id)

    async def _ensure_access_token_not_revoked(self, claims: dict[str, object]) -> None:
        """Reject access tokens that have been blocklisted on logout."""
        jti = str(claims.get("jti", "")).strip()
        if not jti:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401)

        try:
            blocklisted = await self._redis.get(f"blocklist:jti:{jti}")
        except RedisError as exc:
            raise LifecycleServiceError(
                "Session backend unavailable.",
                "session_expired",
                503,
            ) from exc

        if blocklisted is not None:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401)

    async def _get_user_by_password_reset_token(
        self,
        db_session: AsyncSession,
        token: str,
        *,
        for_update: bool,
    ) -> User | None:
        """Look up a non-expired password reset token without distinguishing invalid states."""
        normalized_token = token.strip()
        if not normalized_token:
            return None
        token_hash = self._hash_password_reset_token(normalized_token)
        statement = select(User).where(
            User.password_reset_token_hash == token_hash,
            User.deleted_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        user = result.scalar_one_or_none()
        if (
            user is None
            or user.password_reset_token_expires is None
            or user.password_reset_token_expires <= datetime.now(UTC)
        ):
            return None
        return user

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

    async def _signup_email_exists(self, db_session: AsyncSession, email: str) -> bool:
        """Return True when any persisted row already uses the email."""
        statement = select(User.id).where(func.lower(User.email) == email.lower())
        result = await db_session.execute(statement)
        return result.scalar_one_or_none() is not None

    @staticmethod
    def _hash_verification_token(token: str) -> str:
        """Hash verification token for database storage."""
        return sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _hash_password_reset_token(token: str) -> str:
        """Hash password reset token for database storage."""
        return sha256(token.encode("utf-8")).hexdigest()

    def _perform_dummy_password_workload(self, candidate: str) -> None:
        """Execute constant-time-ish bcrypt work when the email is absent."""
        self._user_service.verify_password(candidate, self._dummy_password_hash)

    @staticmethod
    def _normalize_email(email: str) -> str:
        """Normalize an email for case-insensitive comparisons."""
        return email.strip().lower()

    @staticmethod
    def _hash_public_resend_identifier(value: str) -> str:
        """Hash public resend identifiers before using them in Redis keys."""
        return sha256(value.encode("utf-8")).hexdigest()

    def _verification_link(self, token: str) -> str:
        """Build signup verification endpoint path."""
        return urljoin(f"{self._public_base_url}/", f"auth/verify-email?token={token}")

    def _password_reset_link(self, token: str) -> str:
        """Build password reset validation endpoint path."""
        return urljoin(f"{self._public_base_url}/", f"auth/password/reset?token={token}")


@reloadable_singleton
def get_verification_email_sender() -> LifecycleEmailSender:
    """Create and cache default Mailhog SMTP sender."""
    settings = get_settings()
    return MailhogVerificationEmailSender(
        host=settings.email.mailhog_host,
        port=settings.email.mailhog_port,
        email_from=settings.email.email_from,
    )


@reloadable_singleton
def get_lifecycle_service() -> LifecycleService:
    """Create and cache lifecycle service dependency."""
    settings = get_settings()
    return LifecycleService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        user_service=get_user_service(),
        token_service=get_token_service(),
        brute_force_service=get_brute_force_service(),
        session_service=get_session_service(),
        redis_client=get_redis_client(),
        email_sender=get_verification_email_sender(),
        email_verify_ttl_seconds=settings.email.email_verify_ttl_seconds,
        password_reset_ttl_seconds=settings.email.password_reset_ttl_seconds,
        auth_service_audience=settings.app.service,
        public_base_url=str(settings.email.public_base_url),
    )
