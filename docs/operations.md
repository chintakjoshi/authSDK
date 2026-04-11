# Operations Guide

This guide covers deployment, runtime processes, health checks, and recurring
operator tasks for the auth service.

## Deployment Baseline

At minimum, a production deployment should:

- run `alembic upgrade head` before serving traffic
- expose `/health/live` and `/health/ready`
- provide Postgres and Redis connectivity
- provide JWT signing material
- run webhook worker and scheduler processes if webhook delivery is enabled
- set all production-only secrets and HTTPS URLs correctly

## Runtime Processes

Primary API process:

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Webhook worker:

```bash
python worker.py
```

Scheduler:

```bash
python scheduler.py
```

In Docker, these processes are already modeled in
`docker/docker-compose.yml`.

## Health And Monitoring

Health endpoints:

- `GET /health/live`
- `GET /health/ready`

Metrics:

- `GET /metrics`
- available without extra auth in development
- protected by admin access outside development

Operationally relevant endpoints:

- `GET /.well-known/jwks.json`
- `GET /openapi.json` when `APP__EXPOSE_DOCS=true`

## Required Production Configuration

At minimum:

- `APP__ENVIRONMENT=production`
- `APP__ALLOWED_HOSTS=[...]`
- `DATABASE__URL`
- `REDIS__URL`
- `JWT__PRIVATE_KEY_PEM`
- `JWT__PUBLIC_KEY_PEM`
- `SIGNING_KEYS__ENCRYPTION_KEY`
- `WEBHOOK__SECRET_ENCRYPTION_KEY`
- HTTPS OAuth settings
- HTTPS SAML settings
- HTTPS `EMAIL__PUBLIC_BASE_URL`

`docs/configuration.md` explains the full configuration model and validation
rules.

## Database Migrations

Before or during deploy:

```bash
python -m alembic upgrade head
```

To inspect the generated SQL:

```bash
python -m alembic upgrade head --sql
```

## Signing-Key Rotation

Rotate keys with the operational CLI:

```bash
python -m app.cli rotate-signing-key
```

Optional overlap override:

```bash
python -m app.cli rotate-signing-key --overlap-seconds 900
```

Recommended post-rotation checks:

1. `/.well-known/jwks.json` exposes the expected active and retiring keys.
2. Newly issued tokens use the new `kid`.
3. Previously issued still-valid tokens verify during the overlap window.

## Webhook Runtime Notes

Webhook delivery depends on:

- API process
- Redis
- RQ worker
- RQ scheduler

Tune these if the Redis path is behind an idle-sensitive proxy or load balancer:

- `WEBHOOK__WORKER_TTL_SECONDS`
- `WEBHOOK__REDIS_HEALTH_CHECK_INTERVAL_SECONDS`

The worker intentionally keeps its blocking dequeue window below common managed
Redis idle timeouts.

## Database Pool Tuning

The API uses explicit SQLAlchemy pool tuning rather than library defaults. The
main knobs are:

- `DATABASE__POOL_SIZE`
- `DATABASE__MAX_OVERFLOW`
- `DATABASE__POOL_TIMEOUT_SECONDS`
- `DATABASE__POOL_RECYCLE_SECONDS`

`DATABASE__POOL_RECYCLE_SECONDS` is especially important for managed Postgres
providers and proxies that silently drop older idle connections.

## Retention Purge

The scheduler registers the recurring retention-purge job only when:

- `RETENTION__ENABLE_RETENTION_PURGE=true`
- `RETENTION__PURGE_CRON` is set

Retention windows:

- `RETENTION__AUDIT_LOG_RETENTION_DAYS`
- `RETENTION__SESSION_LOG_RETENTION_DAYS`

## CI/CD Summary

CI validates:

- lint and formatting
- tests
- migrations
- service package build
- SDK package build and wheel import smoke test

Release workflow:

- builds and publishes the container image to GHCR
- supports branch, tag, semver, and sha tags
- can publish `latest` from the default branch or manual dispatch

Authoritative workflow definitions:

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`

## Related Docs

- architecture: `architecture.md`
- configuration: `configuration.md`
- troubleshooting: `troubleshooting.md`
- security review: `security-review.md`
