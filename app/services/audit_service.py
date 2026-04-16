"""Audit service backed by immutable database events."""

from __future__ import annotations

import ipaddress
import re
from copy import deepcopy
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

import structlog
from fastapi import BackgroundTasks, Request
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import reloadable_singleton
from app.core.client_ip import extract_client_ip as extract_trusted_client_ip
from app.db.session import get_session_factory
from app.models.audit_event import AuditActorType, AuditEvent
from app.services.pagination import (
    CursorPage,
    apply_created_at_cursor,
    build_page,
    decode_cursor,
)

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


@dataclass(frozen=True)
class AuditRequestSnapshot:
    """Serializable request context captured for deferred audit writes."""

    headers: dict[str, str]
    client_host: str | None
    correlation_id: str | None

    @classmethod
    def capture(cls, request: Request) -> AuditRequestSnapshot:
        """Capture the minimum request fields needed for a later audit write."""
        raw_correlation_id = getattr(getattr(request, "state", None), "correlation_id", None)
        if raw_correlation_id is None:
            raw_correlation_id = request.headers.get("x-correlation-id")

        return cls(
            headers={str(key).lower(): value for key, value in request.headers.items()},
            client_host=getattr(getattr(request, "client", None), "host", None),
            correlation_id=None if raw_correlation_id is None else str(raw_correlation_id),
        )

    def to_request_like(self) -> Any:
        """Build a lightweight request-like object for existing extraction helpers."""
        client = None
        if self.client_host is not None:
            client = SimpleNamespace(host=self.client_host)

        return SimpleNamespace(
            headers=self.headers,
            client=client,
            state=SimpleNamespace(correlation_id=self.correlation_id),
        )


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

    def enqueue_record(
        self,
        background_tasks: BackgroundTasks,
        *,
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
        """Schedule one audit write to run after the response has been sent."""
        try:
            background_tasks.add_task(
                self.record,
                db=None,
                event_type=event_type,
                actor_type=actor_type,
                success=success,
                request=AuditRequestSnapshot.capture(request),
                actor_id=actor_id,
                target_id=target_id,
                target_type=target_type,
                failure_reason=failure_reason,
                metadata=deepcopy(metadata) if metadata is not None else None,
            )
        except Exception as exc:
            logger.error(
                "audit_enqueue_failed",
                event_type=event_type,
                actor_type=actor_type,
                success=success,
                error=str(exc),
            )

    async def list_events_page(
        self,
        db_session: AsyncSession,
        *,
        actor_id: UUID | None = None,
        target_id: UUID | None = None,
        actor_or_target_id: UUID | None = None,
        event_type_prefix: str | None = None,
        event_types: list[str] | None = None,
        success: bool | None = None,
        date_from=None,
        date_to=None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[AuditEvent]:
        """Return one cursor-paginated audit-event page for admin inspection."""
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
        if actor_id is not None:
            statement = statement.where(AuditEvent.actor_id == actor_id)
        if target_id is not None:
            statement = statement.where(AuditEvent.target_id == target_id)
        if actor_or_target_id is not None:
            statement = statement.where(
                or_(
                    AuditEvent.actor_id == actor_or_target_id,
                    AuditEvent.target_id == actor_or_target_id,
                )
            )
        if event_type_prefix is not None:
            statement = statement.where(AuditEvent.event_type.like(f"{event_type_prefix}%"))
        if event_types:
            statement = statement.where(AuditEvent.event_type.in_(event_types))
        if success is not None:
            statement = statement.where(AuditEvent.success.is_(success))
        if date_from is not None:
            statement = statement.where(AuditEvent.created_at >= date_from)
        if date_to is not None:
            statement = statement.where(AuditEvent.created_at <= date_to)
        statement = apply_created_at_cursor(
            statement,
            model=AuditEvent,
            cursor=cursor_position,
        ).limit(limit + 1)
        result = await db_session.execute(statement)
        return build_page(list(result.scalars().all()), limit=limit)

    async def record(
        self,
        db: AsyncSession | Any | None,
        event_type: str,
        actor_type: str,
        success: bool,
        request: Request | AuditRequestSnapshot,
        actor_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        failure_reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Write one append-only audit row and swallow write failures."""
        request_like = (
            request.to_request_like() if isinstance(request, AuditRequestSnapshot) else request
        )

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
            ip_address=_coerce_ip(extract_trusted_client_ip(request_like)),
            user_agent=request_like.headers.get("user-agent"),
            correlation_id=_extract_correlation_id(request_like),
            success=success,
            failure_reason=failure_reason.strip() if failure_reason else None,
            event_metadata=_sanitize_metadata(metadata),
        )

        try:
            if db is None or isinstance(db, AsyncSession):
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


@reloadable_singleton
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
