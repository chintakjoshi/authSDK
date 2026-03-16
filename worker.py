"""RQ worker entrypoint for webhook delivery jobs."""

from __future__ import annotations

from rq import Connection, Worker

from app.services.webhook_service import get_webhook_queue, get_webhook_redis_connection


def main() -> None:
    """Start one RQ worker bound to the configured webhook queue."""
    queue = get_webhook_queue()
    with Connection(get_webhook_redis_connection()):
        worker = Worker([queue.name])
        worker.work()


if __name__ == "__main__":
    main()
