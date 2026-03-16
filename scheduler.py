"""RQ scheduler entrypoint for delayed webhook retry jobs."""

from __future__ import annotations

from app.services.webhook_service import get_webhook_scheduler


def main() -> None:
    """Run the scheduler loop for delayed webhook retries."""
    scheduler = get_webhook_scheduler()
    scheduler.run()


if __name__ == "__main__":
    main()
