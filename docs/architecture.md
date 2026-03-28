# Architecture

This document explains how the auth service, SDK, data stores, and background
processes fit together.

## High-Level Components

- `app/`
  FastAPI service exposing auth, lifecycle, OTP, OAuth, SAML, API-key, admin,
  webhook, health, JWKS, validation, and introspection endpoints
- `sdk/`
  Python package used by downstream services to validate JWTs and API keys and
  enforce role, action-token, and fresh-auth requirements
- `Postgres`
  durable state for users, sessions, API keys, audit events, OAuth clients,
  signing keys, and webhooks
- `Redis`
  short-lived and operational state such as OTP flow state, brute-force
  tracking, and webhook queues
- `worker.py`
  RQ worker that executes webhook delivery jobs
- `scheduler.py`
  RQ scheduler that runs delayed webhook retries and optional retention purge

## Request Path

The FastAPI app is assembled in `app/main.py` with:

- trusted-host enforcement when `APP__ALLOWED_HOSTS` is configured
- tracing middleware
- rate limiting
- structured request logging
- security headers
- Prometheus-style metrics collection
- correlation IDs

Routers registered in the application:

- `auth`
- `lifecycle`
- `otp`
- `oauth`
- `saml`
- `apikeys`
- `webhooks`
- `admin`
- `health`

## Core Flows

### User Login

1. A client calls `POST /auth/login`.
2. The service verifies credentials and brute-force state.
3. If email OTP is enabled, the service may return an OTP challenge instead of a
   token pair.
4. On success, the service issues an access token and refresh token and stores
   the session state.
5. Downstream services later validate the access token using the SDK.

### Token Validation In A Downstream Service

1. A downstream service uses `JWTAuthMiddleware`.
2. The SDK fetches and caches `/.well-known/jwks.json`.
3. JWT verification happens locally with the cached key set.
4. For user tokens, the SDK calls `GET /auth/validate` to confirm the session is
   still active.
5. The verified identity is placed in `request.state.user`.

### Browser Session Flow

1. A browser app calls same-origin `/_auth/csrf`.
2. The reverse proxy forwards that request to `GET /auth/csrf`.
3. The auth service sets a CSRF cookie and returns the token value.
4. The browser app calls same-origin `/_auth/login` with `credentials: include`
   and a matching CSRF header. An explicit
   `X-Auth-Session-Transport: cookie` header is still accepted but no longer
   required once browser-session context is established.
5. The auth service issues access and refresh cookies instead of returning raw
   token strings to JavaScript.
6. The browser app calls same-origin `/api/*` with `credentials: include`.
7. The downstream API uses `JWTAuthMiddleware` cookie extraction plus
   `CookieCSRFMiddleware` to authenticate and protect unsafe requests.
8. Refresh and logout continue through same-origin `/_auth/token` and
   `/_auth/logout`.

### API Key Validation

1. A downstream service uses `APIKeyAuthMiddleware`.
2. The SDK extracts the key from `X-API-Key` or `Authorization: ApiKey ...`.
3. Valid and invalid decisions are cached locally.
4. Cache misses call `POST /auth/introspect`.
5. The resolved identity is placed in `request.state.user`.

### Admin Sensitive Actions

Admin routes live under `/admin/*`. Access is granted by:

- an admin bearer token
- a development-only `X-Admin-API-Key` bootstrap key when configured

Destructive or sensitive admin actions can require a separate `X-Action-Token`
step-up token.

### Webhooks

1. Business events emit webhook delivery jobs.
2. Delivery jobs are enqueued in Redis-backed RQ queues.
3. `worker.py` sends deliveries.
4. `scheduler.py` handles delayed retries.
5. Delivery metadata is stored in Postgres for inspection and manual retry.

## Data And Runtime Responsibilities

Postgres is the source of truth for durable auth state:

- users
- sessions
- audit events
- API keys
- OAuth clients
- signing keys
- webhook endpoints and deliveries

Redis is used for fast operational state:

- OTP codes and challenges
- brute-force tracking
- RQ queues and delayed jobs

## Production Guardrails

At startup, production mode enforces several constraints, including:

- `ADMIN_API_KEY` must not be configured
- `APP__ALLOWED_HOSTS` must be explicit and cannot contain `*`
- signing-key and webhook encryption keys are required
- OAuth, SAML, and email public URLs must use HTTPS

See `configuration.md` for the full configuration model.

## Documentation Cross-References

- environment variables: `configuration.md`
- endpoint families: `service-api.md`
- SDK usage: `integrate-sdk.md`
- browser adoption quickstart: `browser-consumer-quickstart.md`
- deployment and runtime operations: `operations.md`
