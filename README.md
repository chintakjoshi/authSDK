# authSDK [![CI](https://github.com/chintakjoshi/authSDK/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/chintakjoshi/authSDK/actions/workflows/ci.yml)

Authentication platform repository containing:
- a central auth service you can deploy once for your organization
- a Python SDK (`auth-service-sdk`) that other apps can install to trust and consume that auth service

This repo is designed for a multi-service setup. The auth service owns identity,
token issuance, session state, OTP flows, API-key introspection, admin
operations, and signing keys. Downstream applications install the SDK and use
middleware/dependencies to validate tokens and enforce authorization locally
while delegating trust to the central auth service.

## What This Repo Contains

### 1. Central Auth Service

The service in `app/` is the backend authority for authentication and
authorization-related state. It provides:

- email/password signup and login
- JWT access and refresh token issuance
- audience-scoped tokens for downstream services
- logout and server-side session validation
- API key issuance and introspection
- OTP login challenges and action tokens
- email verification and password reset flows
- re-authentication for sensitive actions
- Google OAuth and SAML entry points
- admin APIs for users, audit logs, OAuth clients, API keys, signing keys, and webhooks
- signing-key rotation and JWKS publishing
- audit logging, rate limiting, health checks, and scheduled retention purge

### 2. Reusable SDK

The SDK lives in `sdk/` and is published as `auth-service-sdk`.

Installing the SDK does not install or run the auth backend itself. It gives
other Python/FastAPI/Starlette services a lightweight client-side integration
layer so they can trust the central auth service.

The SDK provides:

- `JWTAuthMiddleware`
  Verifies RS256 JWTs using the auth service JWKS, enforces token audience, and
  validates session state through the auth service.
- `APIKeyAuthMiddleware`
  Validates opaque API keys through auth-service introspection with local
  positive/negative caching.
- `require_role(...)`
  Route dependency for role-based authorization.
- `require_action_token(...)`
  Route dependency for step-up actions protected by action tokens.
- `require_fresh_auth(...)`
  Route dependency for enforcing recent authentication via `auth_time`.

## How The Pieces Fit Together

The intended architecture is:

```text
[ User / Client ]
        |
        v
[ Central Auth Service ]  -> issues JWTs, refresh tokens, API key decisions
        |
        +--> Postgres
        +--> Redis
        +--> webhook worker / scheduler
        |
        v
[ Downstream Apps ]
        |
        +--> install `auth-service-sdk`
        +--> validate JWTs/API keys
        +--> enforce roles / action tokens / fresh auth
```

Typical request flow:

1. A user authenticates against the auth service.
2. The auth service issues an access token for a specific audience such as
   `orders-api`.
3. The user calls a downstream app with that token.
4. The downstream app uses `auth-service-sdk` middleware to validate the token.
5. The SDK may call the auth service for JWKS, session validation, or API-key
   introspection.
6. The downstream app receives a trusted identity in `request.state.user`.

## When To Use This Repo

Use this repo when you want:

- one shared authentication authority for multiple internal or external apps
- consistent JWT validation across services
- centralized session revocation and token verification
- OTP, password reset, email verification, OAuth, and SAML in one place
- a reusable SDK so downstream services do not duplicate auth code

## Multi-App Example

Example setup:

- auth service deployed at `https://auth.example.com`
- `orders-api` expects audience `orders-api`
- `billing-api` expects audience `billing-api`

Login for `orders-api`:

```json
POST /auth/login
{
  "email": "user@example.com",
  "password": "Password123!",
  "audience": "orders-api"
}
```

SDK usage inside `orders-api`:

```python
from fastapi import FastAPI
from sdk import JWTAuthMiddleware

app = FastAPI()
app.add_middleware(
    JWTAuthMiddleware,
    auth_base_url="https://auth.example.com",
    expected_audience="orders-api",
)
```

This audience boundary prevents a token minted for one downstream service from
being replayed against another.

## Installing The SDK In Another Project

You can install the SDK from:

- a published package index:
  `pip install auth-service-sdk`
- a local path during development:
  `pip install /path/to/authSDK/sdk`
- a Git repository subdirectory:
  `pip install "git+https://github.com/<org>/<repo>.git#subdirectory=sdk"`

The package name is `auth-service-sdk`, while the import namespace is `sdk`.

## Start Here

- New engineer onboarding path: `docs/README.md`
- Local stack setup: `DEVELOPMENT.md`
- SDK middleware usage: `sdk/README.md`

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
Mailhog is exposed at `http://localhost:8025` for verification-email inspection.

## Common Next Steps

- Integrate SDK in a service: `docs/integrate-sdk.md`
- Review auth endpoint contracts: `docs/service-api.md`
- Review production operations: `docs/operations.md`
- Debug common integration issues: `docs/troubleshooting.md`

## Signing Key Rotation CLI

Rotate RS256 signing keys:

```bash
python -m app.cli rotate-signing-key
```

Optional overlap override:

```bash
python -m app.cli rotate-signing-key --overlap-seconds 900
```

## Minimum Endpoints The SDK Expects

Downstream apps using the SDK expect the auth service to expose:

- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

Those endpoints are implemented by this repo's auth service.

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
