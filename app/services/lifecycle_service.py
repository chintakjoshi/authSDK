"""Account lifecycle service for signup email verification flows."""

from __future__ import annotations

import asyncio
import smtplib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from functools import lru_cache
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.jwt import JWTService, TokenValidationError, get_jwt_service
from app.core.sessions import get_redis_client
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.models.user import User
from app.services.user_service import UserService


class LifecycleServiceError(Exception):
    """Raised for lifecycle flow failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class VerificationEmailSender(Protocol):
    """Contract for verification-email delivery adapters."""

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        """Deliver a verification email."""


@dataclass(frozen=True)
class MailhogVerificationEmailSender:
    """SMTP sender targeting local Mailhog."""

    host: str
    port: int
    email_from: str

    async def send_verification_email(self, to_email: str, verification_link: str) -> None:
        """Send a signup verification email through SMTP."""
        subject = "Verify your email"
        body = f"Open this link to verify your account: {verification_link}"
        await asyncio.to_thread(
            self._send_blocking,
            to_email=to_email,
            subject=subject,
            body=body,
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


class LifecycleService:
    """Lifecycle orchestration for signup verification and resend flows."""

    def __init__(
        self,
        jwt_service: JWTService,
        signing_key_service: SigningKeyService,
        user_service: UserService,
        redis_client: Redis,
        email_sender: VerificationEmailSender,
        email_verify_ttl_seconds: int,
    ) -> None:
        self._jwt_service = jwt_service
        self._signing_key_service = signing_key_service
        self._user_service = user_service
        self._redis = redis_client
        self._email_sender = email_sender
        self._email_verify_ttl_seconds = email_verify_ttl_seconds
        self._resend_limit_ttl_seconds = 3600
        self._resend_limit_count = 3

    async def signup_password(
        self,
        db_session: AsyncSession,
        email: str,
        password: str,
    ) -> User:
        """Create password user and send signup verification link."""
        normalized_email = email.strip().lower()
        if not normalized_email:
            raise LifecycleServiceError("Invalid email.", "invalid_credentials", 400)

        existing = await self._user_service.get_user_by_email(
            db_session=db_session,
            email=normalized_email,
        )
        if existing is not None:
            raise LifecycleServiceError("Email already registered.", "invalid_credentials", 409)

        user = User(
            email=normalized_email,
            password_hash=self._user_service.hash_password(password),
            is_active=True,
            role="user",
            email_verified=False,
        )
        db_session.add(user)
        try:
            await db_session.flush()
            verification_token, expires_at = await self._issue_email_verify_token(
                db_session=db_session,
                user_id=str(user.id),
            )
            user.email_verify_token_hash = self._hash_verification_token(verification_token)
            user.email_verify_token_expires = expires_at
            await db_session.flush()
            await self._email_sender.send_verification_email(
                to_email=user.email,
                verification_link=self._verification_link(verification_token),
            )
            await db_session.commit()
        except IntegrityError as exc:
            await db_session.rollback()
            raise LifecycleServiceError("Email already registered.", "invalid_credentials", 409) from exc
        except Exception:
            await db_session.rollback()
            raise
        return user

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
            )
        except TokenValidationError as exc:
            raise LifecycleServiceError("Invalid token.", "invalid_token", 401) from exc
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
        await self._enforce_resend_rate_limit(normalized_user_id)

        verification_token, expires_at = await self._issue_email_verify_token(
            db_session=db_session,
            user_id=normalized_user_id,
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
            )
        except TokenValidationError as exc:
            if exc.code in {"invalid_token", "token_expired"}:
                raise LifecycleServiceError(
                    "Invalid verification token.",
                    "invalid_verify_token",
                    400,
                ) from exc
            raise

    async def _enforce_resend_rate_limit(self, user_id: str) -> None:
        """Allow at most 3 resend requests per user each hour."""
        key = f"email_verify_resend:{user_id}"
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

    @staticmethod
    def _hash_verification_token(token: str) -> str:
        """Hash verification token for database storage."""
        return sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _verification_link(token: str) -> str:
        """Build signup verification endpoint path."""
        return f"/auth/verify-email?token={token}"


@lru_cache
def get_verification_email_sender() -> VerificationEmailSender:
    """Create and cache default Mailhog SMTP sender."""
    settings = get_settings()
    return MailhogVerificationEmailSender(
        host=settings.email.mailhog_host,
        port=settings.email.mailhog_port,
        email_from=settings.email.email_from,
    )


@lru_cache
def get_lifecycle_service() -> LifecycleService:
    """Create and cache lifecycle service dependency."""
    settings = get_settings()
    return LifecycleService(
        jwt_service=get_jwt_service(),
        signing_key_service=get_signing_key_service(),
        user_service=UserService(),
        redis_client=get_redis_client(),
        email_sender=get_verification_email_sender(),
        email_verify_ttl_seconds=settings.email.email_verify_ttl_seconds,
    )
