"""Integration tests for reusable cursor pagination foundations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.services.api_key_service import get_api_key_service
from app.services.audit_service import AuditService
from app.services.webhook_service import WebhookSendResult, WebhookService


@dataclass
class _FakeSender:
    """No-op sender for webhook pagination tests."""

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        del url, payload, secret
        return WebhookSendResult(status_code=200, body="ok", delivered=True)


@dataclass
class _FakeQueue:
    """No-op queue for webhook pagination tests."""

    enqueued: list[str] = field(default_factory=list)

    def enqueue(self, func: str, *args: object, **kwargs: object) -> object:
        del func, kwargs
        self.enqueued.append(str(args[0]))
        return object()


@dataclass
class _FakeScheduler:
    """No-op scheduler for webhook pagination tests."""

    scheduled: list[str] = field(default_factory=list)

    def enqueue_at(self, scheduled_time, func: str, *args: object, **kwargs: object) -> object:  # type: ignore[no-untyped-def]
        del scheduled_time, func, kwargs
        self.scheduled.append(str(args[0]))
        return object()


def _build_webhook_service(session_factory) -> WebhookService:  # type: ignore[no-untyped-def]
    """Build webhook service with fake I/O collaborators."""
    return WebhookService(
        session_factory=session_factory,
        sender=_FakeSender(),
        queue=_FakeQueue(),
        scheduler=_FakeScheduler(),
        audit_service=AuditService(),
        response_body_max_chars=1000,
        secret_encryption_key="pagination-webhook-secret",
        encryption_fallback_seed="pagination-webhook-seed",
    )


@pytest.mark.asyncio
async def test_api_key_service_list_keys_page_uses_cursor(
    db_session: AsyncSession,
) -> None:
    """API key listing supports stable cursor pagination for admin endpoints."""
    api_key_service = get_api_key_service()

    first = await api_key_service.create_key(
        db_session=db_session,
        name="First Key",
        service="orders",
        scope="orders:read",
        user_id=None,
        expires_at=None,
    )
    second = await api_key_service.create_key(
        db_session=db_session,
        name="Second Key",
        service="billing",
        scope="billing:write",
        user_id=None,
        expires_at=None,
    )

    first_page = await api_key_service.list_keys_page(db_session=db_session, limit=1)

    assert len(first_page.items) == 1
    assert first_page.has_more is True
    assert first_page.items[0].id == second.key_id
    assert first_page.next_cursor is not None

    second_page = await api_key_service.list_keys_page(
        db_session=db_session,
        cursor=first_page.next_cursor,
        limit=1,
    )

    assert len(second_page.items) == 1
    assert second_page.items[0].id == first.key_id
    assert second_page.has_more is False
    assert second_page.next_cursor is None


@pytest.mark.asyncio
async def test_webhook_service_list_endpoints_page_uses_cursor(
    db_session: AsyncSession,
    db_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Webhook endpoint listing supports stable cursor pagination for admin endpoints."""
    webhook_service = _build_webhook_service(db_session_factory)

    await webhook_service.register_endpoint(
        db_session=db_session,
        name="First Endpoint",
        url="https://example.com/first",
        secret="first-secret-value",
        events=["session.created"],
    )
    second = await webhook_service.register_endpoint(
        db_session=db_session,
        name="Second Endpoint",
        url="https://example.com/second",
        secret="second-secret-value",
        events=["session.created"],
    )

    first_page = await webhook_service.list_endpoints_page(db_session=db_session, limit=1)

    assert len(first_page.items) == 1
    assert first_page.has_more is True
    assert first_page.items[0].id == second.id
    assert first_page.next_cursor is not None

    second_page = await webhook_service.list_endpoints_page(
        db_session=db_session,
        cursor=first_page.next_cursor,
        limit=1,
    )

    assert len(second_page.items) == 1
    assert second_page.has_more is False
    assert second_page.next_cursor is None
