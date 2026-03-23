# Local Development (Docker)

This document is the step-by-step runbook to start the full auth service stack
locally with Docker.

Related docs:
- onboarding hub: `docs/README.md`
- SDK integration quickstart: `docs/integrate-sdk.md`
- troubleshooting: `docs/troubleshooting.md`

## 1. Prerequisites

- Docker Desktop running
- Docker Compose plugin (`docker compose version`)
- Port `8000` (service), `5432` (Postgres), and `6379` (Redis) available

## 2. Create `.env` from sample

From repository root:

```bash
cp .env-sample .env
```

PowerShell alternative:

```powershell
Copy-Item .env-sample .env
```

Notes:

- `.env` is ignored by git.
- For Docker startup, JWT keys are optional. If `JWT__PRIVATE_KEY_PEM` and
  `JWT__PUBLIC_KEY_PEM` are not set, the container generates temporary keys
  automatically on boot.

## 3. Start the full stack

From repository root:

```bash
docker compose -f docker/docker-compose.yml up --build
```

Detached mode:

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Services started:

- `postgres` (`postgres:16`)
- `redis` (`redis:7`)
- `mailhog` (local email inspection)
- `adminer` (local Postgres browser UI)
- `auth-service` (FastAPI + Alembic migration on startup)
- `webhook-worker` (RQ worker for immediate webhook delivery jobs)
- `webhook-scheduler` (RQ scheduler for delayed retries and retention jobs)

## 4. Verify service health

```bash
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
```

Expected:

- `/health/live` -> `200 {"status":"live"}`
- `/health/ready` -> `200 {"status":"ready"}`

Also useful:

```bash
curl http://localhost:8000/.well-known/jwks.json
```

Local UIs:

- Swagger UI: `http://localhost:8000/docs`
- Adminer: `http://localhost:8080`
  - server: `postgres`
  - username: `postgres`
  - password: `postgres`
  - database: `auth_service`

If you already initialized the stack before this change, Adminer will still
work with password `postgres`, but the existing Postgres volume remains on the
older `trust` auth mode until you recreate it:

```bash
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d --build
```

## 5. View logs

```bash
docker compose -f docker/docker-compose.yml logs -f auth-service
```

## 6. Stop or reset

Stop containers:

```bash
docker compose -f docker/docker-compose.yml down
```

Stop and remove Postgres volume (full reset):

```bash
docker compose -f docker/docker-compose.yml down -v
```

## 7. Optional: load-test setup

See `loadtests/README.md` for Locust runs and seeding a load-test user.
