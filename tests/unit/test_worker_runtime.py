"""Unit tests for webhook worker runtime hardening."""

from __future__ import annotations

from types import SimpleNamespace

import worker as worker_module
from app.services import webhook_service


def test_get_webhook_redis_connection_enables_keepalive_and_health_checks(monkeypatch) -> None:
    """Webhook Redis clients enable keepalive and periodic health checks."""
    captured: dict[str, object] = {}

    def _from_url(cls, url: str, **kwargs: object) -> object:
        captured["url"] = url
        captured["kwargs"] = kwargs
        return object()

    webhook_service.get_webhook_redis_connection.cache_clear()
    monkeypatch.setattr(
        webhook_service,
        "get_settings",
        lambda: SimpleNamespace(
            redis=SimpleNamespace(url="redis://redis.example.com:6379/0"),
            webhook=SimpleNamespace(redis_health_check_interval_seconds=30),
        ),
    )
    monkeypatch.setattr(webhook_service.Redis, "from_url", classmethod(_from_url))

    connection = webhook_service.get_webhook_redis_connection()

    assert connection is not None
    assert captured == {
        "url": "redis://redis.example.com:6379/0",
        "kwargs": {
            "decode_responses": False,
            "socket_keepalive": True,
            "health_check_interval": 30,
        },
    }
    webhook_service.get_webhook_redis_connection.cache_clear()


def test_worker_main_uses_configured_worker_ttl(monkeypatch) -> None:
    """Webhook worker bootstrap applies the configured RQ worker TTL."""
    captured: dict[str, object] = {}
    queue = SimpleNamespace(name="webhooks")
    connection = object()

    class _ConnectionContext:
        def __init__(self, redis_connection: object) -> None:
            captured["connection"] = redis_connection

        def __enter__(self) -> None:
            captured["entered"] = True
            return None

        def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            captured["exited"] = True
            return None

    class _WorkerStub:
        def __init__(self, queues: list[str], **kwargs: object) -> None:
            captured["queues"] = queues
            captured["worker_kwargs"] = kwargs

        def work(self) -> None:
            captured["worked"] = True

    monkeypatch.setattr(
        worker_module,
        "get_settings",
        lambda: SimpleNamespace(webhook=SimpleNamespace(worker_ttl_seconds=120)),
    )
    monkeypatch.setattr(worker_module, "get_webhook_queue", lambda: queue)
    monkeypatch.setattr(worker_module, "get_webhook_redis_connection", lambda: connection)
    monkeypatch.setattr(worker_module, "Connection", _ConnectionContext)
    monkeypatch.setattr(worker_module, "Worker", _WorkerStub)

    worker_module.main()

    assert captured["connection"] is connection
    assert captured["queues"] == ["webhooks"]
    assert captured["worker_kwargs"] == {"default_worker_ttl": 120}
    assert captured["worked"] is True
