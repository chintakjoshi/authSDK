"""Integration tests for webhook registration and delivery flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_session_factory
from app.models.audit_event import AuditEvent
from app.models.webhook_delivery import WebhookDelivery, WebhookDeliveryStatus
from app.services.audit_service import AuditService
from app.services.webhook_service import (
    WebhookSendResult,
    WebhookService,
    WebhookUnsafeTargetError,
    get_webhook_service,
    sign_payload,
)


@dataclass
class _RecordedSend:
    """Captured outbound webhook call."""

    url: str
    payload: dict[str, Any]
    secret: str


class _FakeSender:
    """Configurable sender stub for integration tests."""

    def __init__(self, results: list[WebhookSendResult]) -> None:
        self._results = results
        self.calls: list[_RecordedSend] = []

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        self.calls.append(_RecordedSend(url=url, payload=payload, secret=secret))
        if self._results:
            return self._results.pop(0)
        return WebhookSendResult(status_code=200, body="ok", delivered=True)


class _UnsafeSender:
    """Sender stub that simulates send-time SSRF target rejection."""

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        del url, payload, secret
        raise WebhookUnsafeTargetError("Invalid webhook URL.")


@dataclass
class _FakeQueue:
    """Immediate queue stub capturing enqueued delivery IDs."""

    enqueued_delivery_ids: list[UUID] = field(default_factory=list)

    def enqueue(self, func: str, *args: object, **kwargs: object) -> object:
        del func, kwargs
        self.enqueued_delivery_ids.append(UUID(str(args[0])))
        return object()


@dataclass
class _ScheduledRetry:
    """Captured scheduled retry metadata."""

    delivery_id: UUID
    scheduled_time: datetime


@dataclass
class _FakeScheduler:
    """Scheduler stub capturing delayed retries."""

    scheduled: list[_ScheduledRetry] = field(default_factory=list)

    def enqueue_at(
        self, scheduled_time: datetime, func: str, *args: object, **kwargs: object
    ) -> object:
        del func, kwargs
        self.scheduled.append(
            _ScheduledRetry(delivery_id=UUID(str(args[0])), scheduled_time=scheduled_time)
        )
        return object()


def _build_webhook_service(
    *,
    sender: _FakeSender,
    queue: _FakeQueue,
    scheduler: _FakeScheduler,
) -> WebhookService:
    """Build webhook service against the real integration DB with fake I/O adapters."""
    return WebhookService(
        session_factory=get_session_factory(),
        sender=sender,
        queue=queue,
        scheduler=scheduler,
        audit_service=AuditService(),
        response_body_max_chars=1000,
        secret_encryption_key="integration-webhook-secret",
        encryption_fallback_seed="integration-webhook-seed",
    )


@pytest.mark.asyncio
async def test_webhook_registration_and_login_emit_session_created_delivery(
    app_factory,
    user_factory,
    db_session: AsyncSession,
) -> None:
    """Registering a webhook and logging in creates and delivers session.created webhook."""
    sender = _FakeSender([WebhookSendResult(status_code=202, body="accepted", delivered=True)])
    queue = _FakeQueue()
    scheduler = _FakeScheduler()
    webhook_service = _build_webhook_service(sender=sender, queue=queue, scheduler=scheduler)

    app: FastAPI = app_factory()
    app.dependency_overrides[get_webhook_service] = lambda: webhook_service
    await user_factory("hook-user@example.com", "Password123!", email_verified=True)
    await user_factory(
        "hook-admin@example.com",
        "Password123!",
        role="admin",
        email_verified=True,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_response = await client.post(
            "/auth/login",
            json={"email": "hook-admin@example.com", "password": "Password123!"},
        )
        assert login_response.status_code == 200
        headers = {"authorization": f"Bearer {login_response.json()['access_token']}"}

        register = await client.post(
            "/webhooks",
            json={
                "name": "session hooks",
                "url": "https://example.com/ingest",
                "secret": "super-secret-hook",
                "events": ["session.created"],
            },
            headers=headers,
        )
        assert register.status_code == 200
        endpoint_id = register.json()["id"]

        login = await client.post(
            "/auth/login",
            json={"email": "hook-user@example.com", "password": "Password123!"},
        )
        assert login.status_code == 200

        deliveries_response = await client.get(
            f"/webhooks/{endpoint_id}/deliveries",
            headers=headers,
        )
        assert deliveries_response.status_code == 200
        deliveries = deliveries_response.json()
        assert len(deliveries) == 1
        assert deliveries[0]["event_type"] == "session.created"

    assert len(queue.enqueued_delivery_ids) == 1
    delivery_id = queue.enqueued_delivery_ids[0]

    await webhook_service.process_delivery(delivery_id=delivery_id)
    await webhook_service.process_delivery(delivery_id=delivery_id)

    assert len(sender.calls) == 1
    assert sender.calls[0].payload["event"] == "session.created"
    assert sign_payload(sender.calls[0].payload, sender.calls[0].secret).startswith("sha256=")

    delivery = await db_session.get(WebhookDelivery, delivery_id)
    assert delivery is not None
    assert delivery.status == WebhookDeliveryStatus.DELIVERED.value


@pytest.mark.asyncio
async def test_webhook_failures_retry_with_backoff_and_abandon_after_five_attempts(
    db_session: AsyncSession,
) -> None:
    """Failed deliveries back off with the documented schedule and abandon on the fifth failure."""
    sender = _FakeSender(
        [
            WebhookSendResult(status_code=500, body="fail-1", delivered=False),
            WebhookSendResult(status_code=500, body="fail-2", delivered=False),
            WebhookSendResult(status_code=500, body="fail-3", delivered=False),
            WebhookSendResult(status_code=500, body="fail-4", delivered=False),
            WebhookSendResult(status_code=500, body="fail-5", delivered=False),
        ]
    )
    queue = _FakeQueue()
    scheduler = _FakeScheduler()
    webhook_service = _build_webhook_service(sender=sender, queue=queue, scheduler=scheduler)

    endpoint = await webhook_service.register_endpoint(
        db_session=db_session,
        name="retry hooks",
        url="https://example.com/retry",
        secret="retry-secret",
        events=["session.created"],
    )
    await webhook_service.emit_event(
        event_type="session.created", data={"endpoint_id": str(endpoint.id)}
    )
    delivery_id = queue.enqueued_delivery_ids[0]

    expected_delays = [60, 300, 1800, 7200]
    for attempt_index, expected_delay in enumerate(expected_delays, start=1):
        await webhook_service.process_delivery(delivery_id=delivery_id)
        db_session.expire_all()
        delivery = await db_session.get(WebhookDelivery, delivery_id)
        assert delivery is not None
        assert delivery.attempt_count == attempt_index
        assert delivery.status == WebhookDeliveryStatus.FAILED.value
        assert delivery.next_retry_at is not None
        delta = int((delivery.next_retry_at - delivery.last_attempted_at).total_seconds())
        assert delta == expected_delay
        delivery.next_retry_at = datetime.now(UTC) - timedelta(seconds=1)
        await db_session.commit()

    await webhook_service.process_delivery(delivery_id=delivery_id)

    db_session.expire_all()
    delivery = await db_session.get(WebhookDelivery, delivery_id)
    assert delivery is not None
    assert delivery.attempt_count == 5
    assert delivery.status == WebhookDeliveryStatus.ABANDONED.value
    assert delivery.next_retry_at is None

    audit_rows = list(
        (
            await db_session.execute(
                select(AuditEvent).where(AuditEvent.event_type == "webhook.failed")
            )
        )
        .scalars()
        .all()
    )
    assert audit_rows


@pytest.mark.asyncio
async def test_webhook_registration_blocks_localhost_urls(
    app_factory,
    user_factory,
) -> None:
    """Webhook registration rejects localhost/private URLs to mitigate SSRF."""
    sender = _FakeSender([])
    queue = _FakeQueue()
    scheduler = _FakeScheduler()
    webhook_service = _build_webhook_service(sender=sender, queue=queue, scheduler=scheduler)
    app: FastAPI = app_factory()
    app.dependency_overrides[get_webhook_service] = lambda: webhook_service
    await user_factory(
        "hook-admin-block@example.com",
        "Password123!",
        role="admin",
        email_verified=True,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        login_response = await client.post(
            "/auth/login",
            json={"email": "hook-admin-block@example.com", "password": "Password123!"},
        )
        headers = {"authorization": f"Bearer {login_response.json()['access_token']}"}
        response = await client.post(
            "/webhooks",
            json={
                "name": "blocked",
                "url": "http://127.0.0.1:8000/hook",
                "secret": "secret-value",
                "events": ["session.created"],
            },
            headers=headers,
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid webhook URL.", "code": "invalid_webhook_url"}


@pytest.mark.asyncio
async def test_webhook_delivery_abandons_send_time_unsafe_target(
    db_session: AsyncSession,
) -> None:
    """A webhook that becomes unsafe at send time is abandoned instead of retried."""
    webhook_service = _build_webhook_service(
        sender=_UnsafeSender(),
        queue=_FakeQueue(),
        scheduler=_FakeScheduler(),
    )

    endpoint = await webhook_service.register_endpoint(
        db_session=db_session,
        name="rebinding hooks",
        url="https://example.com/rebinding",
        secret="rebind-secret",
        events=["session.created"],
    )
    await webhook_service.emit_event(
        event_type="session.created", data={"endpoint_id": str(endpoint.id)}
    )

    delivery = (
        await db_session.execute(
            select(WebhookDelivery).where(WebhookDelivery.endpoint_id == endpoint.id)
        )
    ).scalar_one()
    delivery_id = delivery.id
    await webhook_service.process_delivery(delivery_id=delivery_id)

    db_session.expire_all()
    delivery = await db_session.get(WebhookDelivery, delivery_id)
    assert delivery is not None
    assert delivery.status == WebhookDeliveryStatus.ABANDONED.value
    assert delivery.attempt_count == 0
    assert delivery.next_retry_at is None
    assert delivery.response_status is None

    failed_audits = list(
        (
            await db_session.execute(
                select(AuditEvent).where(
                    AuditEvent.event_type == "webhook.failed",
                    AuditEvent.failure_reason == "invalid_webhook_url",
                )
            )
        )
        .scalars()
        .all()
    )
    assert failed_audits
