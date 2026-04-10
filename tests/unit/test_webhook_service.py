"""Unit tests for webhook signing and SSRF validation."""

from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.services.audit_service import AuditService
from app.services.webhook_service import (
    WebhookSender,
    WebhookSendResult,
    WebhookService,
    sign_payload,
)


class _SenderStub:
    """Sender stub for webhook service unit tests."""

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        del url, payload, secret
        return WebhookSendResult(status_code=200, body="ok", delivered=True)


class _QueueStub:
    """Queue stub for webhook service unit tests."""

    def enqueue(self, func: str, *args: object, **kwargs: object) -> object:
        del func, args, kwargs
        return object()


class _SchedulerStub:
    """Scheduler stub for webhook service unit tests."""

    def enqueue_at(self, scheduled_time, func: str, *args: object, **kwargs: object) -> object:  # type: ignore[no-untyped-def]
        del scheduled_time, func, args, kwargs
        return object()


def _build_service() -> WebhookService:
    """Create webhook service with inert dependencies for unit checks."""
    return WebhookService(
        session_factory=cast(async_sessionmaker[AsyncSession], object()),
        sender=cast(WebhookSender, _SenderStub()),
        queue=_QueueStub(),
        scheduler=_SchedulerStub(),
        audit_service=AuditService(),
        response_body_max_chars=1000,
        secret_encryption_key="unit-test-secret",
        encryption_fallback_seed="fallback-seed",
    )


def test_sign_payload_matches_documented_signature_format() -> None:
    """Webhook signatures use sha256=<hex digest> format."""
    payload = {
        "id": "delivery-1",
        "event": "session.created",
        "created_at": "2024-01-01T00:00:00Z",
        "data": {"user_id": "user-1"},
    }

    signature = sign_payload(payload, "top-secret")

    assert signature.startswith("sha256=")
    assert len(signature) == 71


@pytest.mark.asyncio
async def test_webhook_service_rejects_localhost_and_private_ip_urls() -> None:
    """Registration-time SSRF validation blocks localhost and private-network destinations."""
    service = _build_service()

    assert await service._is_safe_webhook_url("https://example.com/ingest") is True
    assert await service._is_safe_webhook_url("http://localhost:8080/hook") is False
    assert await service._is_safe_webhook_url("http://127.0.0.1:8000/hook") is False
    assert await service._is_safe_webhook_url("http://192.168.1.10/hook") is False
