"""RQ scheduler entrypoint for delayed webhook retry jobs and maintenance tasks."""

from __future__ import annotations

from rq_scheduler import Scheduler

from app.config import get_settings
from app.services.webhook_service import get_webhook_scheduler

RETENTION_PURGE_JOB_ID = "maintenance:retention_purge"
RETENTION_PURGE_FUNC = "workers.maintenance_worker.run_retention_purge"


def configure_periodic_jobs(scheduler: Scheduler | None = None) -> None:
    """Register recurring maintenance jobs for the shared scheduler process."""
    settings = get_settings()
    if not settings.retention.enable_retention_purge:
        return

    target_scheduler = scheduler or get_webhook_scheduler()
    _ensure_cron_job(
        target_scheduler,
        job_id=RETENTION_PURGE_JOB_ID,
        cron_string=settings.retention.purge_cron,
        func=RETENTION_PURGE_FUNC,
        description="Run retention purge",
    )


def _ensure_cron_job(
    scheduler: Scheduler,
    *,
    job_id: str,
    cron_string: str,
    func: str,
    description: str,
) -> None:
    """Ensure one cron job exists with the expected definition."""
    for job in scheduler.get_jobs():
        if job.id != job_id:
            continue
        if (
            job.func_name == func
            and job.origin == scheduler.queue_name
            and str(job.meta.get("cron_string", "")).strip() == cron_string
        ):
            return
        scheduler.cancel(job)
        delete = getattr(job, "delete", None)
        if callable(delete):
            delete()
        break

    scheduler.cron(
        cron_string,
        func,
        id=job_id,
        description=description,
        queue_name=scheduler.queue_name,
    )


def main() -> None:
    """Run the scheduler loop for delayed webhook retries and maintenance jobs."""
    scheduler = get_webhook_scheduler()
    configure_periodic_jobs(scheduler)
    scheduler.run()


if __name__ == "__main__":
    main()
