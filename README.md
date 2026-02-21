# authSDK

Authentication service + SDK workspace for local development, testing, and load
validation.

## Local Docker Quick Start

1. Copy environment template:
```bash
cp .env-sample .env
```

2. Start stack:
```bash
docker compose -f docker/docker-compose.yml up --build
```

3. Verify health:
```bash
curl http://localhost:8000/health/ready
```

Full step-by-step guide: `DEVELOPMENT.md`.

The service is exposed at `http://localhost:8000`.

## GitHub CI/CD

### Workflows

- `CI` (`.github/workflows/ci.yml`)
  - Runs on pull requests and pushes to `main`.
  - Executes:
    - `ruff` lint
    - `black --check`
    - `pytest`
    - `alembic upgrade head --sql`
    - `alembic upgrade head` against CI Postgres service
    - `python -m build`
  - Boots Postgres and Redis service containers.
  - Generates ephemeral RSA keys at runtime for `JWT__PRIVATE_KEY_PEM` and `JWT__PUBLIC_KEY_PEM`.

- `Release Image` (`.github/workflows/release.yml`)
  - Runs on tags (`v*`) and manual dispatch.
  - Builds and pushes container image to GHCR:
    - `ghcr.io/<owner>/auth-service:<tag>`
    - `ghcr.io/<owner>/auth-service:sha-<commit-sha>`
  - If `docker/Dockerfile` is still empty, it exits with a warning and skips image publishing.

### Optional Release Input

- `image_tag` in `Release Image` workflow dispatch
  - Overrides default tag derivation when manually triggering release.
