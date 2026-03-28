# Development Guide

This guide covers local setup, day-to-day commands, and the expected workflow
for engineers working in this repository.

Related docs:

- docs hub: `docs/README.md`
- contributor guide: `CONTRIBUTING.md`
- configuration reference: `docs/configuration.md`
- testing guide: `docs/testing.md`

## Prerequisites

- Python `3.11`
- Docker Desktop with the Compose plugin
- PostgreSQL and Redis ports available if you plan to use the local Docker stack
- optional: `uv` for faster local task execution

## Local Stack With Docker

1. Copy the environment template.

```powershell
Copy-Item .env-sample .env
```

2. Start the full stack.

```powershell
docker compose -f docker/docker-compose.yml up --build
```

The checked-in `.env-sample` already uses localhost-safe browser-session cookie
names for `http://localhost`. Keep those local names unless you are testing the
stack behind real HTTPS.

3. Verify readiness.

```powershell
curl http://localhost:8000/health/ready
```

Services started by Compose:

- `postgres`
- `redis`
- `mailhog`
- `adminer`
- `auth-service`
- `webhook-worker`
- `webhook-scheduler`

Local URLs:

- Swagger UI: `http://localhost:8000/docs`
- Mailhog: `http://localhost:8025`
- Adminer: `http://localhost:8080`

If you need a full reset:

```powershell
docker compose -f docker/docker-compose.yml down -v
```

## Python Environment

Install the service and development dependencies in your active environment:

```bash
python -m pip install --upgrade pip
python -m pip install .[dev]
python -m pip install build
```

If you prefer `uv`, the lockfile is already committed:

```bash
uv sync --extra dev
```

## Running The App Without Docker

The service expects working Postgres, Redis, and environment configuration.
For a complete key map, use `.env-sample` plus `docs/configuration.md`.

Start the API:

```bash
python -m alembic upgrade head
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Background processes:

```bash
python worker.py
python scheduler.py
```

## Common Commands

Lint:

```bash
python -m ruff check .
```

Format check:

```bash
python -m black --check .
```

Tests:

```bash
python -m pytest -q
```

Migrations:

```bash
python -m alembic upgrade head
python -m alembic upgrade head --sql
```

Build artifacts:

```bash
python -m build
python -m build sdk
```

Signing-key rotation:

```bash
python -m app.cli rotate-signing-key
```

## Local Verification Checklist

After changing auth flows, SDK behavior, persistence, or operational code, a
good local verification pass usually includes:

- `python -m ruff check .`
- `python -m black --check .`
- `python -m pytest -q`
- `python -m alembic upgrade head --sql`

For changes that affect packaging:

- `python -m build`
- `python -m build sdk`

For changes that affect runtime behavior:

- verify `/health/live`
- verify `/health/ready`
- inspect `/.well-known/jwks.json`
- test at least one end-to-end login or SDK-protected route

## Where To Go Next

- architecture and request flows: `docs/architecture.md`
- service endpoint map: `docs/service-api.md`
- SDK integration details: `docs/integrate-sdk.md`
- test strategy and load tests: `docs/testing.md`
- production runtime notes: `docs/operations.md`
