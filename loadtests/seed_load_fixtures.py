"""Seed reusable load-test fixtures for OTP, admin, M2M, and webhooks."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models.oauth_client import OAuthClient
from app.models.user import User
from app.models.webhook_endpoint import WebhookEndpoint
from app.services.m2m_service import M2MService
from app.services.user_service import UserService

DEFAULT_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/auth_service"
DEFAULT_HOST = "http://localhost:8000"


@dataclass(frozen=True)
class SeedSummary:
    """High-level fixture summary printed at the end of the run."""

    login_email: str
    otp_count: int
    admin_email: str
    m2m_client_id: str | None
    m2m_client_secret: str | None
    webhook_id: str | None


def _session_factory(database_url: str) -> async_sessionmaker[AsyncSession]:
    """Create one async session factory for the provided database URL."""
    engine = create_async_engine(database_url, pool_pre_ping=True)
    return async_sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _otp_email(template: str, index: int) -> str:
    """Render one OTP load-user email from the configured template."""
    return template.format(index=index)


async def _get_user_by_email(db_session: AsyncSession, email: str) -> User | None:
    """Fetch a user row case-insensitively, including soft-deleted rows."""
    result = await db_session.execute(select(User).where(func.lower(User.email) == email.lower()))
    return result.scalar_one_or_none()


async def _upsert_user(
    db_session: AsyncSession,
    *,
    email: str,
    password: str,
    role: str,
    email_verified: bool,
    mfa_enabled: bool,
) -> User:
    """Create or restore a password user for load-testing purposes."""
    user_service = UserService()
    user = await _get_user_by_email(db_session, email)
    if user is None:
        user = User(email=email)
        db_session.add(user)
        await db_session.flush()

    user.password_hash = user_service.hash_password(password)
    user.deleted_at = None
    user.is_active = True
    user.role = role
    user.email_verified = email_verified or mfa_enabled
    user.mfa_enabled = mfa_enabled
    user.email_verify_token_hash = None
    user.email_verify_token_expires = None
    user.password_reset_token_hash = None
    user.password_reset_token_expires = None
    await db_session.flush()
    return user


async def _upsert_m2m_client(
    db_session: AsyncSession,
    *,
    name: str,
    scopes: list[str],
    token_ttl_seconds: int,
) -> tuple[str, str]:
    """Create or rotate one named M2M client and return usable credentials."""
    result = await db_session.execute(select(OAuthClient).where(OAuthClient.name == name))
    client = result.scalar_one_or_none()
    raw_secret = M2MService.generate_client_secret()

    if client is None:
        client = OAuthClient(
            client_id=f"client_seed_{name.lower().replace(' ', '_')}",
            client_secret_hash=M2MService.hash_client_secret(raw_secret),
            client_secret_prefix=M2MService.client_secret_prefix(raw_secret),
            name=name,
            scopes=scopes,
            role="service",
            is_active=True,
            token_ttl_seconds=token_ttl_seconds,
        )
        db_session.add(client)
        await db_session.flush()
        return client.client_id, raw_secret

    client.client_secret_hash = M2MService.hash_client_secret(raw_secret)
    client.client_secret_prefix = M2MService.client_secret_prefix(raw_secret)
    client.scopes = scopes
    client.token_ttl_seconds = token_ttl_seconds
    client.is_active = True
    client.deleted_at = None
    await db_session.flush()
    return client.client_id, raw_secret


async def _register_or_reuse_webhook(
    *,
    host: str,
    name: str,
    url: str,
    secret: str,
    events: list[str],
    database_url: str,
) -> str:
    """Reuse a matching webhook by name or register a new one through the app."""
    session_factory = _session_factory(database_url)
    async with session_factory() as db_session:
        existing = await db_session.execute(
            select(WebhookEndpoint).where(
                WebhookEndpoint.name == name,
                WebhookEndpoint.deleted_at.is_(None),
            )
        )
        endpoint = existing.scalar_one_or_none()
        if endpoint is not None:
            return str(endpoint.id)

    async with httpx.AsyncClient(base_url=host.rstrip("/"), timeout=10.0) as client:
        response = await client.post(
            "/webhooks",
            json={
                "name": name,
                "url": url,
                "secret": secret,
                "events": events,
            },
        )
        response.raise_for_status()
        return str(response.json()["id"])


async def seed_fixtures(args: argparse.Namespace) -> SeedSummary:
    """Create or update all requested load-test fixtures."""
    session_factory = _session_factory(args.database_url)
    async with session_factory() as db_session:
        await _upsert_user(
            db_session,
            email=args.email,
            password=args.password,
            role="user",
            email_verified=True,
            mfa_enabled=False,
        )
        await _upsert_user(
            db_session,
            email=args.admin_email,
            password=args.admin_password,
            role="admin",
            email_verified=True,
            mfa_enabled=False,
        )
        for index in range(1, args.otp_user_count + 1):
            await _upsert_user(
                db_session,
                email=_otp_email(args.otp_email_template, index),
                password=args.otp_password,
                role="user",
                email_verified=True,
                mfa_enabled=True,
            )

        m2m_client_id: str | None = None
        m2m_client_secret: str | None = None
        if args.m2m_name:
            m2m_client_id, m2m_client_secret = await _upsert_m2m_client(
                db_session,
                name=args.m2m_name,
                scopes=args.m2m_scopes,
                token_ttl_seconds=args.m2m_token_ttl_seconds,
            )

        await db_session.commit()

    webhook_id: str | None = None
    if args.webhook_url:
        webhook_id = await _register_or_reuse_webhook(
            host=args.host,
            name=args.webhook_name,
            url=args.webhook_url,
            secret=args.webhook_secret,
            events=args.webhook_events,
            database_url=args.database_url,
        )

    return SeedSummary(
        login_email=args.email,
        otp_count=args.otp_user_count,
        admin_email=args.admin_email,
        m2m_client_id=m2m_client_id,
        m2m_client_secret=m2m_client_secret,
        webhook_id=webhook_id,
    )


def _parse_args() -> argparse.Namespace:
    """Parse CLI options for fixture seeding."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", default=DEFAULT_DATABASE_URL)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--email", default="loadtest@example.com")
    parser.add_argument("--password", default="Password123!")
    parser.add_argument("--admin-email", default="load-admin@example.com")
    parser.add_argument("--admin-password", default="Password123!")
    parser.add_argument("--otp-email-template", default="otp-load-{index}@example.com")
    parser.add_argument("--otp-password", default="Password123!")
    parser.add_argument("--otp-user-count", type=int, default=100)
    parser.add_argument("--m2m-name", default="locust-load-client")
    parser.add_argument("--m2m-scopes", nargs="+", default=["metrics:read"])
    parser.add_argument("--m2m-token-ttl-seconds", type=int, default=3600)
    parser.add_argument("--webhook-url")
    parser.add_argument("--webhook-name", default="locust-load-webhook")
    parser.add_argument("--webhook-secret", default="load-webhook-secret")
    parser.add_argument("--webhook-events", nargs="+", default=["session.created"])
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""
    args = _parse_args()
    summary = asyncio.run(seed_fixtures(args))
    print(f"login user ready: {summary.login_email}")
    print(f"otp users ready: {summary.otp_count}")
    print(f"admin user ready: {summary.admin_email}")
    if summary.m2m_client_id and summary.m2m_client_secret:
        print(f"m2m client id: {summary.m2m_client_id}")
        print(f"m2m client secret: {summary.m2m_client_secret}")
    if summary.webhook_id:
        print(f"webhook endpoint id: {summary.webhook_id}")


if __name__ == "__main__":
    main()
