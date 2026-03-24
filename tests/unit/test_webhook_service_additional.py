"""Additional unit tests for webhook service branches."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.webhook_delivery import WebhookDelivery, WebhookDeliveryStatus
from app.models.webhook_endpoint import WebhookEndpoint
from app.services.audit_service import AuditService
from app.services.webhook_service import (
    HTTPXWebhookSender,
    ResolvedWebhookTarget,
    WebhookSendResult,
    WebhookService,
    WebhookServiceError,
    WebhookUnsafeTargetError,
    sign_payload,
)


class _ResultStub:
    def __init__(self, value: object) -> None:
        self.value = value

    def scalar_one_or_none(self):  # type: ignore[no-untyped-def]
        return self.value

    def scalars(self):  # type: ignore[no-untyped-def]
        return self

    def all(self):  # type: ignore[no-untyped-def]
        if isinstance(self.value, list):
            return self.value
        return []

    def one_or_none(self):  # type: ignore[no-untyped-def]
        return self.value


class _DBSessionStub:
    def __init__(self, execute_results: list[object] | None = None) -> None:
        self.execute_results = execute_results or []
        self.added: list[object] = []
        self.flush_count = 0
        self.commit_count = 0

    def add(self, instance: object) -> None:
        self.added.append(instance)

    async def execute(self, statement):  # type: ignore[no-untyped-def]
        del statement
        return _ResultStub(self.execute_results.pop(0) if self.execute_results else None)

    async def flush(self) -> None:
        self.flush_count += 1

    async def commit(self) -> None:
        self.commit_count += 1


class _QueueStub:
    def __init__(self) -> None:
        self.enqueued: list[str] = []

    def enqueue(self, func: str, *args: object, **kwargs: object) -> object:
        del func, kwargs
        self.enqueued.append(str(args[0]))
        return object()


class _SchedulerStub:
    def __init__(self) -> None:
        self.scheduled: list[str] = []

    def enqueue_at(
        self, scheduled_time: datetime, func: str, *args: object, **kwargs: object
    ) -> object:
        del scheduled_time, func, kwargs
        self.scheduled.append(str(args[0]))
        return object()


class _SenderStub:
    def __init__(self, result: WebhookSendResult | None = None) -> None:
        self.result = result or WebhookSendResult(status_code=200, body="ok", delivered=True)

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        del url, payload, secret
        return self.result


def _service() -> WebhookService:
    return WebhookService(
        session_factory=cast(async_sessionmaker[AsyncSession], object()),
        sender=_SenderStub(),
        queue=_QueueStub(),
        scheduler=_SchedulerStub(),
        audit_service=AuditService(),
        response_body_max_chars=20,
        secret_encryption_key="unit-secret",
        encryption_fallback_seed="fallback-seed",
    )


@pytest.mark.asyncio
async def test_httpx_sender_success_and_http_error(monkeypatch) -> None:
    """HTTPX sender truncates bodies and maps transport errors to delivered=False."""
    sender = HTTPXWebhookSender(timeout_seconds=5, response_body_max_chars=4)
    target = ResolvedWebhookTarget(
        url="https://93.184.216.34/webhook",
        host_header="example.com",
        sni_hostname="example.com",
    )

    async def _resolve_target(url: str) -> ResolvedWebhookTarget:
        del url
        return target

    sender._resolve_target = _resolve_target  # type: ignore[method-assign,assignment]

    post_calls: list[tuple[str, dict[str, str], dict[str, str] | None]] = []

    class _Response:
        status_code = 202
        text = "accepted"

    class _Client:
        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return self

        async def __aexit__(self, exc_type, exc, tb):  # type: ignore[no-untyped-def]
            return False

        async def post(
            self,
            url: str,
            content: str,
            headers: dict[str, str],
            extensions: dict[str, str] | None = None,
        ) -> _Response:
            del content
            post_calls.append((url, headers, extensions))
            return _Response()

    monkeypatch.setattr("app.services.webhook_service.httpx.AsyncClient", lambda timeout: _Client())
    result = await sender.send(url="https://example.com", payload={"event": "x"}, secret="s")
    assert result == WebhookSendResult(status_code=202, body="acce", delivered=True)
    assert post_calls == [
        (
            "https://93.184.216.34/webhook",
            {
                "Content-Type": "application/json",
                "Host": "example.com",
                "X-Webhook-Signature": sign_payload({"event": "x"}, "s"),
                "X-Webhook-Event": "x",
            },
            {"sni_hostname": "example.com"},
        )
    ]

    class _BadClient(_Client):
        async def post(
            self,
            url: str,
            content: str,
            headers: dict[str, str],
            extensions: dict[str, str] | None = None,
        ) -> _Response:
            del url, content, headers, extensions
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(
        "app.services.webhook_service.httpx.AsyncClient", lambda timeout: _BadClient()
    )
    result = await sender.send(url="https://example.com", payload={"event": "x"}, secret="s")
    assert result.delivered is False
    assert result.status_code is None

    sender._resolve_target = _raise_unsafe_target  # type: ignore[method-assign,assignment]
    with pytest.raises(WebhookUnsafeTargetError):
        await sender.send(url="https://example.com", payload={"event": "x"}, secret="s")


async def _raise_unsafe_target(url: str) -> ResolvedWebhookTarget:
    del url
    raise WebhookUnsafeTargetError("Invalid webhook URL.")


@pytest.mark.asyncio
async def test_register_get_update_delete_and_retry_endpoint_flows() -> None:
    """Webhook service handles CRUD and retry helpers with stable errors."""
    service = _service()
    db_session = _DBSessionStub()

    async def _safe(url: str) -> bool:
        return url.startswith("https://")

    service._is_safe_webhook_url = _safe  # type: ignore[assignment]

    with pytest.raises(WebhookServiceError):
        await service.register_endpoint(
            db_session=db_session,  # type: ignore[arg-type]
            name=" ",
            url="https://example.com",
            secret="secret",
            events=[],
        )

    endpoint = await service.register_endpoint(
        db_session=db_session,  # type: ignore[arg-type]
        name="Orders Hook",
        url="https://example.com",
        secret="top-secret",
        events=["session.created", "session.created"],
    )
    assert endpoint.name == "Orders Hook"
    assert endpoint.events == ["session.created"]
    assert db_session.commit_count == 1

    row = WebhookEndpoint(
        name="Hook", url="https://example.com", secret="secret", events=[], is_active=True
    )
    row.id = uuid4()
    row.created_at = datetime.now(UTC)
    found = await service.get_endpoint(
        db_session=_DBSessionStub(execute_results=[row]),  # type: ignore[arg-type]
        endpoint_id=row.id,
        for_update=False,
    )
    assert found is row

    with pytest.raises(WebhookServiceError):
        await service.get_endpoint(
            db_session=_DBSessionStub(execute_results=[None]),  # type: ignore[arg-type]
            endpoint_id=uuid4(),
        )

    async def _get_endpoint(**kwargs: object) -> WebhookEndpoint:
        return row

    service.get_endpoint = _get_endpoint  # type: ignore[assignment]
    updated = await service.update_endpoint(
        db_session=_DBSessionStub(),  # type: ignore[arg-type]
        endpoint_id=row.id,
        name="Updated Hook",
        url="https://example.com/next",
        events=["user.created"],
        is_active=False,
    )
    assert updated.name == "Updated Hook"
    assert updated.events == ["user.created"]
    assert updated.is_active is False

    delivery = WebhookDelivery(
        endpoint_id=row.id,
        event_type="session.created",
        payload={"id": "d1"},
        status=WebhookDeliveryStatus.PENDING.value,
        attempt_count=0,
    )
    delivery.id = uuid4()
    deleted = await service.delete_endpoint(
        db_session=_DBSessionStub(execute_results=[[delivery]]),  # type: ignore[arg-type]
        endpoint_id=row.id,
    )
    assert deleted.abandoned_delivery_ids == [delivery.id]
    assert delivery.status == WebhookDeliveryStatus.ABANDONED.value

    retry_row = WebhookDelivery(
        endpoint_id=row.id,
        event_type="session.created",
        payload={"id": "d2"},
        status=WebhookDeliveryStatus.FAILED.value,
        attempt_count=3,
    )
    retry_row.id = uuid4()
    retry_service = _service()
    retried = await retry_service.retry_delivery(
        db_session=_DBSessionStub(execute_results=[retry_row]),  # type: ignore[arg-type]
        delivery_id=retry_row.id,
    )
    assert retried.status == WebhookDeliveryStatus.PENDING.value
    assert retry_row.attempt_count == 0

    with pytest.raises(WebhookServiceError):
        await retry_service.retry_delivery(
            db_session=_DBSessionStub(execute_results=[None]),  # type: ignore[arg-type]
            delivery_id=uuid4(),
        )


@pytest.mark.asyncio
async def test_safe_url_and_secret_helpers_cover_edge_cases(monkeypatch) -> None:
    """Webhook SSRF and secret helpers reject unsafe hosts and bad ciphertext."""
    service = _service()
    assert await service._is_safe_webhook_url("ftp://example.com") is False
    assert await service._is_safe_webhook_url("https://localhost/path") is False
    assert await service._is_safe_webhook_url("https:///missing-host") is False

    async def _resolved(hostname: str) -> list[object]:
        del hostname
        return []

    service._resolve_host_ips = _resolved  # type: ignore[assignment]
    assert await service._is_safe_webhook_url("https://example.com") is False

    encrypted = service._encrypt_secret("secret-value")
    assert service._decrypt_secret(encrypted) == "secret-value"
    assert service._decrypt_secret("plain-secret") == "plain-secret"
    with pytest.raises(ValueError):
        service._decrypt_secret(f"{service._ENCRYPTION_PREFIX}not-valid")

    request = service._build_system_request()
    assert isinstance(request, Request)
    assert request.url.path == "/workers/webhook"
    assert service._isoformat_z(datetime.now(UTC)).endswith("Z")
