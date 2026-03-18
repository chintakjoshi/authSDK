"""Additional unit tests for health and webhook route wrappers."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.routers import health as health_router
from app.routers import webhooks as webhooks_router
from app.services.admin_service import AdminServiceError
from app.services.webhook_service import WebhookServiceError


class _RedisReadyStub:
    def __init__(self, value: bool | Exception) -> None:
        self.value = value

    async def ping(self) -> bool:
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


class _WebhookRouteStub:
    def __init__(self) -> None:
        self.error: WebhookServiceError | None = None

    async def register_endpoint(self, **kwargs: object) -> object:
        if self.error is not None:
            raise self.error
        return SimpleNamespace(
            id=uuid4(),
            name=kwargs["name"],
            url=kwargs["url"],
            events=kwargs["events"],
            is_active=True,
            created_at=datetime.now(UTC),
        )

    async def list_endpoints(self, **kwargs: object) -> list[object]:
        del kwargs
        return [
            SimpleNamespace(
                id=uuid4(),
                name="orders",
                url="https://example.com/orders",
                events=["user.created"],
                is_active=True,
                created_at=datetime.now(UTC),
            )
        ]

    async def list_deliveries(self, **kwargs: object) -> list[object]:
        return [
            SimpleNamespace(
                id=uuid4(),
                endpoint_id=kwargs["endpoint_id"],
                event_type="user.created",
                status="pending",
                attempt_count=0,
                last_attempted_at=None,
                next_retry_at=None,
                response_status=None,
                response_body=None,
                created_at=datetime.now(UTC),
            )
        ]

    async def retry_delivery(self, **kwargs: object) -> object:
        if self.error is not None:
            raise self.error
        return SimpleNamespace(id=kwargs["delivery_id"])


class _AdminServiceStub:
    async def validate_admin_access_token(
        self, *, db_session: object, token: str | None
    ) -> dict[str, object]:
        del db_session, token
        return {"sub": "admin-1", "role": "admin", "email": "admin@example.com"}


def _db() -> object:
    return object()


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/webhooks",
            "headers": [(b"authorization", b"Bearer token")],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
        }
    )


@pytest.mark.asyncio
async def test_health_helpers_cover_success_and_failure_paths(monkeypatch) -> None:
    """Health router helpers cover ready checks and 503 readiness failures."""

    class _Conn:
        async def __aenter__(self) -> _Conn:
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            return None

        async def execute(self, statement):  # type: ignore[no-untyped-def]
            del statement
            return None

    monkeypatch.setattr(
        "app.routers.health.get_engine",
        lambda: type("Engine", (), {"connect": lambda self: _Conn()})(),
    )
    assert await health_router.check_postgres_ready() is True
    monkeypatch.setattr(
        "app.routers.health.get_engine",
        lambda: type(
            "Engine",
            (),
            {"connect": lambda self: (_ for _ in ()).throw(RuntimeError("down"))},
        )(),
    )
    assert await health_router.check_postgres_ready() is False
    monkeypatch.setattr("app.routers.health.get_redis_client", lambda: _RedisReadyStub(True))
    assert await health_router.check_redis_ready() is True
    monkeypatch.setattr(
        "app.routers.health.get_redis_client",
        lambda: _RedisReadyStub(RuntimeError("down")),
    )
    assert await health_router.check_redis_ready() is False
    with pytest.raises(HTTPException):
        await health_router.ready(postgres_ready=False, redis_ready=True)


@pytest.mark.asyncio
async def test_webhook_routes_cover_success_and_error_wrappers(monkeypatch) -> None:
    """Webhook router wrappers cover register, list, delivery listing, and retry errors."""
    monkeypatch.setattr(
        "app.routers._admin_access.get_settings",
        lambda: SimpleNamespace(app=SimpleNamespace(environment="production"), admin_api_key=None),
    )
    webhook_service = _WebhookRouteStub()
    admin_service = _AdminServiceStub()
    created = await webhooks_router.register_webhook(
        request=_request(),
        payload=webhooks_router.WebhookEndpointCreateRequest(
            name="orders",
            url="https://example.com/orders",
            secret="secret123",
            events=["user.created"],
        ),
        db_session=_db(),  # type: ignore[arg-type]
        admin_service=admin_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert created.name == "orders"

    listed = await webhooks_router.list_webhooks(
        request=_request(),
        db_session=_db(),  # type: ignore[arg-type]
        admin_service=admin_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert listed[0].name == "orders"

    endpoint_id = uuid4()
    deliveries = await webhooks_router.list_webhook_deliveries(
        endpoint_id=endpoint_id,
        request=_request(),
        db_session=_db(),  # type: ignore[arg-type]
        admin_service=admin_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert deliveries[0].endpoint_id == endpoint_id

    retried = await webhooks_router.retry_webhook_delivery(
        delivery_id=endpoint_id,
        request=_request(),
        db_session=_db(),  # type: ignore[arg-type]
        admin_service=admin_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert retried.delivery_id == endpoint_id

    webhook_service.error = WebhookServiceError("missing", "invalid_credentials", 404)
    failed = await webhooks_router.retry_webhook_delivery(
        delivery_id=endpoint_id,
        request=_request(),
        db_session=_db(),  # type: ignore[arg-type]
        admin_service=admin_service,  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert failed.status_code == 404

    class _RejectingAdminService:
        async def validate_admin_access_token(
            self,
            *,
            db_session: object,
            token: str | None,
        ) -> dict[str, object]:
            del db_session, token
            raise AdminServiceError("Insufficient role.", "insufficient_role", 403)

    denied = await webhooks_router.list_webhooks(
        request=_request(),
        db_session=_db(),  # type: ignore[arg-type]
        admin_service=_RejectingAdminService(),  # type: ignore[arg-type]
        webhook_service=webhook_service,  # type: ignore[arg-type]
    )
    assert denied.status_code == 403
