"""RQ worker entrypoint for webhook delivery jobs."""

from __future__ import annotations

from rq import Connection, Worker

from app.config import get_settings
from app.services.webhook_service import get_webhook_queue, get_webhook_redis_connection


def main() -> None:
    """Start one RQ worker bound to the configured webhook queue."""
    settings = get_settings()
    queue = get_webhook_queue()
    with Connection(get_webhook_redis_connection()):
        # Keep each blocking dequeue window below common managed-Redis idle
        # timeouts so the worker does not exit during quiet periods.
        worker = Worker([queue.name], default_worker_ttl=settings.webhook.worker_ttl_seconds)
        worker.work()


if __name__ == "__main__":
    main()
