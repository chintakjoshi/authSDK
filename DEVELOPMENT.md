# Local Development (Docker)

This document is the step-by-step runbook to start the full auth service stack
locally with Docker.

## 1. Prerequisites

- Docker Desktop running
- Docker Compose v2 (`docker compose version`)
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
- `auth-service` (FastAPI + Alembic migration on startup)

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
