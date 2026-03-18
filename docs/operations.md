# Operations Guide

This guide covers baseline production operations for auth service maintainers.

## Deployment Baseline

- run database migrations on deploy:
  `alembic upgrade head`
- expose readiness and liveness probes:
  `/health/ready`, `/health/live`
- configure required production secrets via environment variables

## Required Production Configuration

At minimum:
- `APP__ENVIRONMENT=production`
- `DATABASE__URL`
- `REDIS__URL`
- `JWT__PRIVATE_KEY_PEM`
- `JWT__PUBLIC_KEY_PEM`
- `SIGNING_KEYS__ENCRYPTION_KEY`
- `WEBHOOK__SECRET_ENCRYPTION_KEY`
- OAuth and SAML settings with HTTPS URLs

Use `.env-sample` as a complete key map.

## Signing Key Rotation

Rotate with:

```bash
python -m app.cli rotate-signing-key
```

Optional overlap override:

```bash
python -m app.cli rotate-signing-key --overlap-seconds 900
```

Post-rotation checks:
1. `GET /.well-known/jwks.json` returns current active and overlap keys.
2. Newly issued tokens contain new `kid`.
3. Existing valid tokens continue to verify during overlap window.

## Webhook Worker Runtime

For webhook delivery, run:
- app API process
- webhook worker (`python worker.py`)
- webhook scheduler (`python scheduler.py`)

These are already modeled in `docker/docker-compose.yml`.

## Audit and Security Validation

- review `docs/security-review.md`
- run integration tests before release:
  `uv run pytest`
- run lint checks:
  `uv run ruff check app sdk tests loadtests docs`
