"""Audit service backed by immutable database events."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import structlog
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session_factory
from app.models.audit_event import AuditActorType, AuditEvent

logger = structlog.get_logger(__name__)

_REDACTED = "***REDACTED***"
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "email",
    "otp",
    "password",
    "secret",
    "token",
)
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _is_sensitive_key(key: str) -> bool:
    """Return True when metadata key likely contains sensitive data."""
    normalized = key.strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _is_email_like(value: str) -> bool:
    """Return True when value appears to be an email address."""
    return bool(_EMAIL_PATTERN.match(value.strip()))


def _coerce_uuid(value: str | UUID | None, deterministic: bool = False) -> UUID | None:
    """Normalize UUID-like values and optionally derive deterministic UUIDs."""
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    text = value.strip()
    if not text:
        return None
    try:
        return UUID(text)
    except ValueError:
        if deterministic:
            return uuid5(NAMESPACE_URL, text)
        return None


def _coerce_ip(value: str | None) -> str | None:
    """Normalize IP address strings to canonical values."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _extract_client_ip(request: Request) -> str | None:
    """Extract canonical client IP from forwarding headers or peer address."""
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        first_hop = forwarded_for.split(",")[0].strip()
        parsed = _coerce_ip(first_hop)
        if parsed is not None:
            return parsed

    client = request.client
    if client is None:
        return None
    return _coerce_ip(client.host)


def _extract_correlation_id(request: Request) -> UUID | None:
    """Resolve request correlation ID into UUID form for storage."""
    raw_value = getattr(request.state, "correlation_id", None) or request.headers.get(
        "x-correlation-id"
    )
    if raw_value is None:
        return None
    return _coerce_uuid(str(raw_value), deterministic=True)


def _sanitize_metadata_value(value: Any) -> Any:
    """Coerce metadata values to JSON-safe primitives with PII redaction."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, str):
        return _REDACTED if _is_email_like(value) else value
    if isinstance(value, dict):
        return _sanitize_metadata(value)
    if isinstance(value, list):
        return [_sanitize_metadata_value(item) for item in value]
    return str(value)


def _sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    """Redact sensitive fields and drop credential-bearing keys from metadata."""
    if metadata is None:
        return None
    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        if _is_sensitive_key(key):
            sanitized[key] = _REDACTED
            continue
        sanitized[key] = _sanitize_metadata_value(value)
    return sanitized or None


class AuditService:
    """Persist immutable audit events without affecting auth outcomes."""

    async def record(
        self,
        db: AsyncSession,
        event_type: str,
        actor_type: str,
        success: bool,
        request: Request,
        actor_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        failure_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Write one append-only audit row and swallow write failures."""
        try:
            normalized_actor_type = AuditActorType(actor_type)
        except ValueError:
            normalized_actor_type = AuditActorType.SYSTEM

        audit_event = AuditEvent(
            event_type=event_type.strip(),
            actor_id=_coerce_uuid(actor_id),
            actor_type=normalized_actor_type,
            target_id=_coerce_uuid(target_id),
            target_type=target_type.strip() if target_type else None,
            ip_address=_extract_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            correlation_id=_extract_correlation_id(request),
            success=success,
            failure_reason=failure_reason.strip() if failure_reason else None,
            event_metadata=_sanitize_metadata(metadata),
        )

        try:
            if isinstance(db, AsyncSession):
                session_factory = get_session_factory()
                async with session_factory() as audit_db:
                    audit_db.add(audit_event)
                    await audit_db.commit()
            else:
                db.add(audit_event)
                await db.commit()
        except Exception as exc:
            if not isinstance(db, AsyncSession):
                try:
                    await db.rollback()
                except Exception:
                    pass
            logger.error(
                "audit_write_failed",
                event_type=event_type,
                actor_type=normalized_actor_type.value,
                success=success,
                error=str(exc),
            )


@lru_cache
def get_audit_service() -> AuditService:
    """Create and cache audit service dependency."""
    return AuditService()


async def record(
    db: AsyncSession,
    event_type: str,
    actor_type: str,
    success: bool,
    request: Request,
    actor_id: str | None = None,
    target_id: str | None = None,
    target_type: str | None = None,
    failure_reason: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Module-level contract wrapper for the audit record operation."""
    await get_audit_service().record(
        db=db,
        event_type=event_type,
        actor_type=actor_type,
        success=success,
        request=request,
        actor_id=actor_id,
        target_id=target_id,
        target_type=target_type,
        failure_reason=failure_reason,
        metadata=metadata,
    )
