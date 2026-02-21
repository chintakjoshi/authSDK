"""Unit tests for centralized auth audit event logging."""

from __future__ import annotations

from typing import Any

from app.services import audit_service as audit_module
from app.services.audit_service import REDACTED, AuditService


class _CaptureLogger:
    """Capture structlog-like logger calls for assertions."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def info(self, event: str, **kwargs: Any) -> None:
        """Capture info-level calls."""
        self.calls.append(("info", event, kwargs))

    def warning(self, event: str, **kwargs: Any) -> None:
        """Capture warning-level calls."""
        self.calls.append(("warning", event, kwargs))


def test_emit_auth_event_redacts_sensitive_fields(monkeypatch) -> None:
    """Credential-like payload keys are redacted before log emission."""
    capture = _CaptureLogger()
    monkeypatch.setattr(audit_module, "logger", capture)
    service = AuditService()

    service.emit_auth_event(
        event_type="api_key_usage",
        provider="api_key",
        ip_address="127.0.0.1",
        correlation_id="cid-1",
        success=True,
        user_id="user-1",
        api_key="sk_secret_value",
        nested={"refresh_token": "refresh-secret", "ok": "value"},
    )

    assert len(capture.calls) == 1
    level, event, payload = capture.calls[0]
    assert level == "info"
    assert event == "auth_event"
    assert payload["event_type"] == "api_key_usage"
    assert payload["provider"] == "api_key"
    assert payload["ip_address"] == "127.0.0.1"
    assert payload["correlation_id"] == "cid-1"
    assert payload["user_id"] == "user-1"
    assert payload["success"] is True
    assert payload["level"] == "info"
    assert payload["timestamp"]
    assert payload["api_key"] == REDACTED
    assert payload["nested"]["refresh_token"] == REDACTED
    assert payload["nested"]["ok"] == "value"
    serialized = str(payload)
    assert "sk_secret_value" not in serialized
    assert "refresh-secret" not in serialized


def test_log_token_refresh_failure_uses_warning_level(monkeypatch) -> None:
    """Failed token refresh events are emitted at warning level."""
    capture = _CaptureLogger()
    monkeypatch.setattr(audit_module, "logger", capture)
    service = AuditService()

    service.log_token_refresh(
        provider="password",
        ip_address="127.0.0.1",
        correlation_id="cid-2",
        success=False,
        error_code="session_expired",
    )

    assert len(capture.calls) == 1
    level, event, payload = capture.calls[0]
    assert level == "warning"
    assert event == "auth_event"
    assert payload["event_type"] == "token_refresh"
    assert payload["success"] is False
    assert payload["error_code"] == "session_expired"
    assert payload["level"] == "warning"
