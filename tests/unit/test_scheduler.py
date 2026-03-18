"""Unit tests for scheduled maintenance job registration."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import scheduler as scheduler_module


class _JobStub:
    """Minimal scheduled-job stub used by scheduler tests."""

    def __init__(
        self,
        *,
        job_id: str,
        func_name: str,
        origin: str,
        cron_string: str,
    ) -> None:
        self.id = job_id
        self.func_name = func_name
        self.origin = origin
        self.meta = {"cron_string": cron_string}
        self.deleted = False

    def delete(self) -> None:
        self.deleted = True


class _SchedulerStub:
    """Scheduler stub capturing cron registration and cancellation calls."""

    def __init__(self, jobs: list[_JobStub] | None = None) -> None:
        self.queue_name = "webhooks"
        self.jobs = jobs or []
        self.cancelled_job_ids: list[str] = []
        self.cron_calls: list[dict[str, object]] = []

    def get_jobs(self) -> list[_JobStub]:
        return list(self.jobs)

    def cancel(self, job: _JobStub) -> None:
        self.cancelled_job_ids.append(job.id)

    def cron(self, cron_string: str, func: str, **kwargs: object) -> object:
        self.cron_calls.append(
            {
                "cron_string": cron_string,
                "func": func,
                **kwargs,
            }
        )
        return object()


def _settings(*, enabled: bool, purge_cron: str = "0 3 * * *") -> SimpleNamespace:
    """Build a minimal settings object for scheduler tests."""
    return SimpleNamespace(
        retention=SimpleNamespace(
            enable_retention_purge=enabled,
            purge_cron=purge_cron,
        )
    )


def test_configure_periodic_jobs_noops_when_retention_is_disabled(monkeypatch) -> None:
    """Scheduler bootstrap does nothing when retention purge is disabled."""
    scheduler = _SchedulerStub()
    monkeypatch.setattr(scheduler_module, "get_settings", lambda: _settings(enabled=False))

    scheduler_module.configure_periodic_jobs(scheduler)

    assert scheduler.cron_calls == []


def test_configure_periodic_jobs_registers_retention_cron_job(monkeypatch) -> None:
    """Scheduler bootstrap registers the recurring retention purge job when enabled."""
    scheduler = _SchedulerStub()
    monkeypatch.setattr(
        scheduler_module,
        "get_settings",
        lambda: _settings(enabled=True, purge_cron="15 2 * * *"),
    )

    scheduler_module.configure_periodic_jobs(scheduler)

    assert scheduler.cron_calls == [
        {
            "cron_string": "15 2 * * *",
            "func": scheduler_module.RETENTION_PURGE_FUNC,
            "id": scheduler_module.RETENTION_PURGE_JOB_ID,
            "description": "Run retention purge",
            "queue_name": "webhooks",
        }
    ]


def test_configure_periodic_jobs_replaces_outdated_retention_job(monkeypatch) -> None:
    """Scheduler bootstrap replaces outdated retention cron definitions in place."""
    existing_job = _JobStub(
        job_id=scheduler_module.RETENTION_PURGE_JOB_ID,
        func_name=scheduler_module.RETENTION_PURGE_FUNC,
        origin="webhooks",
        cron_string="0 1 * * *",
    )
    scheduler = _SchedulerStub(jobs=[existing_job])
    monkeypatch.setattr(
        scheduler_module,
        "get_settings",
        lambda: _settings(enabled=True, purge_cron="0 3 * * *"),
    )

    scheduler_module.configure_periodic_jobs(scheduler)

    assert scheduler.cancelled_job_ids == [scheduler_module.RETENTION_PURGE_JOB_ID]
    assert existing_job.deleted is True
    assert scheduler.cron_calls[0]["cron_string"] == "0 3 * * *"


@pytest.mark.asyncio
async def test_retention_worker_runs_purge_and_logs(monkeypatch) -> None:
    """The retention worker executes one purge run and logs the result."""
    from workers import maintenance_worker

    class _SessionContext:
        async def __aenter__(self) -> object:
            return object()

        async def __aexit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
            return None

    class _SessionFactory:
        def __call__(self) -> _SessionContext:
            return _SessionContext()

    class _AdminServiceStub:
        async def run_retention_purge(self, db_session: object) -> object:
            del db_session
            return SimpleNamespace(
                enabled=True,
                audit_log_retention_days=90,
                session_log_retention_days=30,
                purged_audit_events=4,
                purged_sessions=2,
            )

    class _LoggerCapture:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, object]]] = []

        def info(self, event: str, **kwargs: object) -> None:
            self.calls.append((event, kwargs))

    capture = _LoggerCapture()
    monkeypatch.setattr(maintenance_worker, "get_session_factory", lambda: _SessionFactory())
    monkeypatch.setattr(maintenance_worker, "get_admin_service", lambda: _AdminServiceStub())
    monkeypatch.setattr(maintenance_worker, "logger", capture)

    await maintenance_worker.run_retention_purge_async()

    assert capture.calls == [
        (
            "retention_purge_completed",
            {
                "enabled": True,
                "audit_log_retention_days": 90,
                "session_log_retention_days": 30,
                "purged_audit_events": 4,
                "purged_sessions": 2,
            },
        )
    ]
