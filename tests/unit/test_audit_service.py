"""Unit tests for DB-backed audit service behavior."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from app.services import audit_service as audit_module
from app.services.audit_service import AuditService


class _RequestStub:
    """Minimal request-like object used by audit service unit tests."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        client_host: str = "127.0.0.1",
        correlation_id: str | None = None,
    ) -> None:
        self.headers = headers or {}
        self.client = SimpleNamespace(host=client_host)
        self.state = SimpleNamespace(correlation_id=correlation_id)


class _SessionStub:
    """AsyncSession-like stub capturing persisted audit events."""

    def __init__(self, fail_commit: bool = False) -> None:
        self.fail_commit = fail_commit
        self.added: list[Any] = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def add(self, value: Any) -> None:
        """Capture ORM object added by the service."""
        self.added.append(value)

    async def commit(self) -> None:
        """Commit or raise configured failure."""
        self.commit_calls += 1
        if self.fail_commit:
            raise RuntimeError("db down")

    async def rollback(self) -> None:
        """Track rollback invocations."""
        self.rollback_calls += 1


class _CaptureLogger:
    """Structlog-like sink for error assertions."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def error(self, event: str, **kwargs: Any) -> None:
        """Capture error event payload."""
        self.calls.append((event, kwargs))


async def test_record_persists_event_and_redacts_sensitive_metadata() -> None:
    """record() stores one audit row with redacted metadata and parsed request fields."""
    service = AuditService()
    session = _SessionStub()
    user_id = str(uuid4())
    key_id = str(uuid4())
    request = _RequestStub(
        headers={"user-agent": "pytest-agent/1.0"},
        correlation_id="cid-123",
    )

    await service.record(
        db=session,  # type: ignore[arg-type]
        event_type="api_key.used",
        actor_type="user",
        success=True,
        request=request,  # type: ignore[arg-type]
        actor_id=user_id,
        target_id=key_id,
        target_type="api_key",
        metadata={
            "provider": "password",
            "email": "alice@example.com",
            "access_token": "secret-token",
            "nested": {"contact": "ops@example.com", "ok": "value"},
        },
    )

    assert session.commit_calls == 1
    assert session.rollback_calls == 0
    assert len(session.added) == 1
    event = session.added[0]
    assert event.event_type == "api_key.used"
    assert event.actor_type.value == "user"
    assert event.actor_id == UUID(user_id)
    assert event.target_id == UUID(key_id)
    assert event.target_type == "api_key"
    assert event.ip_address == "127.0.0.1"
    assert event.user_agent == "pytest-agent/1.0"
    assert event.success is True
    assert event.correlation_id is not None
    assert event.event_metadata["provider"] == "password"
    assert event.event_metadata["email"] == "***REDACTED***"
    assert event.event_metadata["access_token"] == "***REDACTED***"
    assert event.event_metadata["nested"]["contact"] == "***REDACTED***"
    assert event.event_metadata["nested"]["ok"] == "value"


async def test_record_logs_and_swallows_write_failures(monkeypatch) -> None:
    """record() never raises to callers when audit persistence fails."""
    capture = _CaptureLogger()
    monkeypatch.setattr(audit_module, "logger", capture)

    service = AuditService()
    session = _SessionStub(fail_commit=True)
    request = _RequestStub(headers={"user-agent": "pytest-agent/1.0"})

    await service.record(
        db=session,  # type: ignore[arg-type]
        event_type="user.login.failure",
        actor_type="invalid-actor",
        success=False,
        request=request,  # type: ignore[arg-type]
        failure_reason="invalid_credentials",
    )

    assert session.commit_calls == 1
    assert session.rollback_calls == 1
    assert len(capture.calls) == 1
    event_name, payload = capture.calls[0]
    assert event_name == "audit_write_failed"
    assert payload["event_type"] == "user.login.failure"
    assert payload["actor_type"] == "system"
    assert payload["success"] is False
