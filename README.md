# authSDK

[![Unit Tests](https://img.shields.io/github/check-runs/chintakjoshi/authSDK/main?nameFilter=Unit%20Tests&label=unit%20tests)](https://github.com/chintakjoshi/authSDK/actions/workflows/ci.yml)
[![Integration Tests](https://img.shields.io/github/check-runs/chintakjoshi/authSDK/main?nameFilter=Integration%20Tests&label=integration%20tests)](https://github.com/chintakjoshi/authSDK/actions/workflows/ci.yml)
[![Build Packages](https://img.shields.io/github/check-runs/chintakjoshi/authSDK/main?nameFilter=Build%20Packages&label=build%20packages)](https://github.com/chintakjoshi/authSDK/actions/workflows/ci.yml)
[![Container Publish](https://github.com/chintakjoshi/authSDK/actions/workflows/release.yml/badge.svg)](https://github.com/chintakjoshi/authSDK/actions/workflows/release.yml)
[![Lint](https://img.shields.io/github/check-runs/chintakjoshi/authSDK/main?nameFilter=Lint&label=lint)](https://github.com/chintakjoshi/authSDK/actions/workflows/ci.yml)

`authSDK` is a central authentication platform plus a reusable Python SDK for
downstream services.

For browser applications, the recommended integration path is now same-origin
cookie sessions backed by `HttpOnly` cookies. Non-browser consumers can keep
using the existing bearer-token contracts.

The repository contains two closely related deliverables:

- `app/`: a FastAPI auth service that owns identity, sessions, token issuance,
  API keys, OTP, lifecycle flows, admin APIs, key rotation, audit logging, and
  webhooks
- `sdk/`: the `auth-service-sdk` package used by other services to validate JWTs
  and API keys and enforce authorization locally

## Why This Repo Exists

This project is meant for a multi-service architecture where authentication
state lives in one place and application services consume that trust boundary
through the SDK.

Typical use cases:

- centralize sign-in, refresh, logout, and session revocation
- issue audience-scoped JWTs for multiple downstream services
- support OTP, password reset, email verification, OAuth, and SAML in one
  deployable service
- give consuming services a thin, reusable middleware layer instead of
  duplicating auth code

## System Overview

```text
                           +----------------------+
                           |   Downstream App     |
                           |  (FastAPI/Starlette) |
                           +----------+-----------+
                                      |
                        auth-service-sdk middleware/dependencies
                                      |
                                      v
+-----------+                +--------+--------+                +-----------+
| User/App  +--------------->+   auth-service   +-------------->+ Postgres  |
+-----------+                +--------+--------+                +-----------+
                                      |
                                      +--------------> Redis
                                      |
                                      +--------------> webhook worker
                                      |
                                      +--------------> scheduler / retention
```

The auth service exposes public auth endpoints, admin endpoints, JWKS, token
validation, API-key introspection, webhook management, and health probes.
Downstream services install `auth-service-sdk` and trust the auth service for
verification and session state.

## Feature Set

- email/password signup and login
- JWT access and refresh tokens
- browser-cookie sessions for first-party web apps
- audience-scoped access tokens for downstream APIs
- server-side session validation and logout
- API key issuance and introspection
- OTP login and step-up action tokens
- email verification and password reset flows
- Google OAuth and SAML entry points
- admin APIs for users, clients, API keys, audit log, signing keys, and
  webhooks
- signing-key rotation with overlap windows and JWKS publishing
- rate limiting, structured logging, correlation IDs, tracing, metrics, and
  security headers
- background webhook delivery and scheduled retention purge

## Repository Layout

```text
app/          FastAPI service, routers, schemas, services, middleware
sdk/          publishable Python SDK for consuming services
docs/         architecture, configuration, API, operations, troubleshooting
tests/        unit and integration coverage
loadtests/    Locust scenarios and result artifacts
docker/       Dockerfile and local compose stack
migrations/   Alembic environment and revisions
workers/      background job entrypoints
```

## Quick Start

1. Copy the local environment template.

```powershell
Copy-Item .env-sample .env
```

2. Start the local stack.

```powershell
docker compose -f docker/docker-compose.yml up --build
```

3. Verify the service is healthy.

```powershell
curl http://localhost:8000/health/ready
```

Local URLs:

- auth service: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs` when `APP__EXPOSE_DOCS=true`
- Mailhog: `http://localhost:8025`
- Adminer: `http://localhost:8080`

## Documentation Map

Start here based on what you need:

- repository docs hub: `docs/README.md`
- local development: `DEVELOPMENT.md`
- browser app quickstart: `docs/browser-consumer-quickstart.md`
- system architecture: `docs/architecture.md`
- configuration reference: `docs/configuration.md`
- service API guide: `docs/service-api.md`
- SDK integration: `docs/integrate-sdk.md`
- testing guide: `docs/testing.md`
- operations and deployment: `docs/operations.md`
- troubleshooting: `docs/troubleshooting.md`
- SDK package guide: `sdk/README.md`
- load tests: `loadtests/README.md`

## SDK At A Glance

The SDK package is published as `auth-service-sdk` and imported as `sdk`.

It provides:

- `JWTAuthMiddleware`
- `APIKeyAuthMiddleware`
- `require_role(...)`
- `require_action_token(...)`
- `require_fresh_auth(...)`
- `AuthClient`

Install options:

```bash
pip install auth-service-sdk
pip install /path/to/authSDK/sdk
pip install "git+https://github.com/<org>/<repo>.git#subdirectory=sdk"
```

## Development Workflow

The repo includes:

- linting with Ruff
- formatting checks with Black
- unit and integration tests with Pytest
- Alembic migration validation
- service and SDK package builds

Common commands:

```bash
python -m ruff check .
python -m black --check .
python -m pytest -q
python -m alembic upgrade head
python -m build
python -m build sdk
```

For a fuller contributor workflow, see `CONTRIBUTING.md`.

Browser-app integrators should start with `docs/browser-consumer-quickstart.md`
and then use `docs/service-api.md` plus `docs/integrate-sdk.md` for the exact
service and SDK contracts.

## Operational Entry Points

Rotate signing keys:

```bash
python -m app.cli rotate-signing-key
```

Run background processes outside Docker:

```bash
python worker.py
python scheduler.py
```

## CI/CD

GitHub Actions currently covers:

- lint and formatting checks
- unit and integration tests
- Alembic offline and online migration validation
- service package build
- SDK package build and wheel smoke test
- container image publication to GHCR

See `.github/workflows/ci.yml` and `.github/workflows/release.yml` for the
authoritative workflow definitions.
