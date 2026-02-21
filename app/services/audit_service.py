"""Centralized structured auth event logging."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

import structlog

SENSITIVE_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "refresh_token",
    "set-cookie",
    "token",
    "x-api-key",
}
REDACTED = "***REDACTED***"

logger = structlog.get_logger(__name__)


def _is_sensitive_key(key: str) -> bool:
    """Return True when key likely carries credential material."""
    normalized = key.lower().replace("-", "_")
    if normalized in SENSITIVE_KEYS:
        return True
    return "token" in normalized or "password" in normalized or "api_key" in normalized


def _redact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact credential material from event payload fields."""
    redacted: dict[str, Any] = {}
    for key, value in values.items():
        if _is_sensitive_key(key):
            redacted[key] = REDACTED
        elif isinstance(value, dict):
            redacted[key] = _redact_mapping(value)
        elif isinstance(value, list):
            redacted[key] = [
                _redact_mapping(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            redacted[key] = value
    return redacted


class AuditService:
    """Emit structured authentication audit events."""

    def emit_auth_event(
        self,
        event_type: str,
        provider: str,
        ip_address: str,
        correlation_id: str,
        success: bool,
        user_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Emit one auth event with required fields and credential redaction."""
        level = "info" if success else "warning"
        payload = {
            "event_type": event_type,
            "user_id": user_id,
            "provider": provider,
            "ip_address": ip_address,
            "success": success,
            "correlation_id": correlation_id,
            "level": level,
            "timestamp": datetime.now(UTC).isoformat(),
            **_redact_mapping(extra),
        }
        if success:
            logger.info("auth_event", **payload)
            return
        logger.warning("auth_event", **payload)

    def log_login_attempt(
        self,
        provider: str,
        ip_address: str,
        correlation_id: str,
        success: bool,
        user_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Log login attempt result."""
        self.emit_auth_event(
            event_type="login_attempt",
            provider=provider,
            ip_address=ip_address,
            correlation_id=correlation_id,
            success=success,
            user_id=user_id,
            **extra,
        )

    def log_token_issuance(
        self,
        provider: str,
        ip_address: str,
        correlation_id: str,
        success: bool,
        user_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Log token issuance result."""
        self.emit_auth_event(
            event_type="token_issuance",
            provider=provider,
            ip_address=ip_address,
            correlation_id=correlation_id,
            success=success,
            user_id=user_id,
            **extra,
        )

    def log_token_refresh(
        self,
        provider: str,
        ip_address: str,
        correlation_id: str,
        success: bool,
        user_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Log token refresh result."""
        self.emit_auth_event(
            event_type="token_refresh",
            provider=provider,
            ip_address=ip_address,
            correlation_id=correlation_id,
            success=success,
            user_id=user_id,
            **extra,
        )

    def log_logout(
        self,
        provider: str,
        ip_address: str,
        correlation_id: str,
        success: bool,
        user_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Log logout result."""
        self.emit_auth_event(
            event_type="logout",
            provider=provider,
            ip_address=ip_address,
            correlation_id=correlation_id,
            success=success,
            user_id=user_id,
            **extra,
        )

    def log_api_key_usage(
        self,
        ip_address: str,
        correlation_id: str,
        success: bool,
        user_id: str | None = None,
        **extra: Any,
    ) -> None:
        """Log API key usage result."""
        self.emit_auth_event(
            event_type="api_key_usage",
            provider="api_key",
            ip_address=ip_address,
            correlation_id=correlation_id,
            success=success,
            user_id=user_id,
            **extra,
        )


@lru_cache
def get_audit_service() -> AuditService:
    """Create and cache auth audit service dependency."""
    return AuditService()
