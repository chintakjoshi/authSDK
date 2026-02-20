# Auth Service - Agent Rules

These rules are non-negotiable constraints for building this service. Read this file before writing any code, modifying any file, or making architectural decisions.

---

## Project Context

This is a production-level FastAPI authentication microservice that issues and validates tokens for multiple consuming services. It supports OAuth2/OIDC (Google), SAML 2.0, JWT (stateless, RS256), API Keys, and hybrid sessions (JWT + Redis). It is deployed on Kubernetes with Postgres and Redis as backing services. A companion SDK package is shipped separately for consuming services to integrate with.

This is v1. Do not add MFA, RBAC, admin API, webhooks, or consent management unless explicitly asked.

---

## Architecture Rules

- Never flatten logic into `main.py`. `main.py` is only for app factory, middleware registration, and router inclusion.
- All business logic lives in `app/services/`. Routers only handle request/response shaping and call services.
- All cryptographic and protocol logic (JWT, OAuth, SAML, API keys) lives in `app/core/`. Services call core modules.
- The SDK in `sdk/` is a separate package. It must not import anything from `app/`. It only uses the public HTTP API of the service.
- Never add a new router without a corresponding service module.
- Never access the database directly from a router. Always go through a service.
- `app/config.py` is the only place settings are defined. Never hardcode config values or use `os.getenv()` anywhere else.

---

## Database Rules

- Use async SQLAlchemy with `asyncpg`. Never use synchronous DB calls.
- Every table must have: `id` (UUID, default generated), `created_at`, `updated_at`, `deleted_at` (nullable, for soft deletes).
- Every table must have a `tenant_id` column (UUID, nullable for now) even if multi-tenancy is not active in v1.
- Never hard-delete user or session records. Always soft-delete via `deleted_at`.
- All schema changes go through Alembic migrations. Never use `create_all()` in production code paths.
- Never write raw SQL strings. Use SQLAlchemy ORM or Core expression language.
- Always filter soft-deleted records in queries (`WHERE deleted_at IS NULL`).

---

## Security Rules (Non-Negotiable)

- Never store plaintext passwords. Use `passlib` with `bcrypt`.
- Never store plaintext API keys. Store `sha256(key)`. Return the raw key only once at creation time.
- Never store plaintext refresh tokens. Hash them before persisting.
- Always use `hmac.compare_digest()` for token and key comparisons. Never use `==`.
- Use RS256 (asymmetric) for JWT signing. Never use HS256 in production code paths.
- Never log tokens, passwords, API keys, or any credential material. Redact them at the logging middleware level.
- Always validate `redirect_uri` against a stored allowlist before initiating or completing any OAuth flow.
- Never trust user-supplied input in SAML assertions without signature validation via `python3-saml`.
- All cookies must be set with `Secure=True`, `HttpOnly=True`, `SameSite=Strict`.
- Never put secrets in code, comments, or committed files. All secrets come from environment variables or mounted Kubernetes Secrets.

---

## JWT Rules

- Access tokens expire in 15 minutes. Refresh tokens expire in 7 days.
- Every JWT must include a `jti` (JWT ID) claim as a UUID. This is required for blocklist-based revocation.
- Every JWT must include `iat`, `exp`, `sub` (user ID), `type` (`access` or `refresh`).
- The JWKS endpoint (`GET /.well-known/jwks.json`) must always be public and unauthenticated.
- Never issue an access token without a corresponding session record existing in both Redis and the DB.
- On refresh, always rotate the refresh token (issue a new one, invalidate the old one).

---

## Session Rules

- Session state is stored in Redis under key `session:{session_id}` with TTL equal to `refresh_token_ttl_seconds`.
- Every Redis session must have a corresponding row in the `sessions` DB table for audit purposes.
- On logout, delete the Redis key AND mark the DB session as revoked. Both must happen in the same operation.
- If Redis is unavailable, fail closed on session-dependent operations. Do not fall back to DB-only session lookups silently.
- The JWT blocklist lives in Redis under key `blocklist:jti:{jti}` with TTL equal to the remaining lifetime of the token.

---

## API Key Rules

- API key format is always `sk_{secrets.token_urlsafe(32)}`.
- Store the first 8 characters of the raw key as `key_prefix` in the DB for display purposes.
- API keys must have an optional `expires_at` field. Expired keys must be rejected even if otherwise valid.
- API keys must be scoped to a service or purpose via a `scope` field. Never issue unscoped keys.

---

## OAuth / OIDC Rules

- Use `authlib` for all OAuth2 client operations. Never implement token exchange or PKCE manually.
- Always verify the `id_token` signature from Google using their public JWKS. Never skip this step.
- After a successful OAuth callback, always upsert into `user_identities` first, then resolve or create the canonical `users` record.
- Never trust the `email` from an OAuth provider without checking `email_verified: true` in the claims.

---

## SAML Rules

- Use `python3-saml` for all SAML operations. Never parse SAMLResponse XML manually.
- Always validate the assertion signature, conditions, and audience restriction.
- Expose SP metadata at `GET /auth/saml/metadata`. This must be kept up to date with the current certificate.
- After successful SAML assertion, apply the same upsert flow as OAuth via `user_identities`.

---

## Middleware Rules

The middleware stack must be applied in this exact order (outermost to innermost):

1. Correlation ID (generate or propagate `X-Correlation-ID`)
2. Structured logging (attach correlation ID, user ID, method, path, status, duration)
3. Rate limiting (Redis sliding window, stricter limits on `/auth/login` and `/auth/token`)
4. Security headers (CSP, X-Frame-Options, X-Content-Type-Options)
5. OpenTelemetry tracing
6. Prometheus metrics

Never add business logic inside middleware. Middleware is only for cross-cutting concerns.

---

## Error Handling Rules

- Never return stack traces or internal error details to the client in production (`environment != "development"`).
- All error responses follow this exact shape: `{"detail": "<human readable message>", "code": "<machine readable code>"}`.
- Use specific error codes: `invalid_token`, `token_expired`, `invalid_api_key`, `invalid_credentials`, `account_locked`, `rate_limited`, `saml_assertion_invalid`, `oauth_state_mismatch`.
- All auth failures (wrong password, invalid token, expired key) must be logged at `WARNING` level with the correlation ID and user identifier (if known).
- Never raise a 500 for an expected auth failure. Map all known failure cases to 4xx explicitly.

---

## Logging Rules

- Use `structlog` with JSON output. Never use `print()` or the stdlib `logging` module directly.
- Every log entry must include: `correlation_id`, `environment`, `service`, `level`, `timestamp` (ISO 8601, UTC).
- Auth event logs must additionally include: `event_type`, `user_id` (if known), `provider`, `ip_address`, `success` (bool).
- Never log PII beyond what is strictly necessary. Email addresses may be logged at INFO level. Names, phone numbers, and addresses must not be logged.
- Log every token issuance, token refresh, login attempt, logout, and API key usage as a structured auth event.

---

## Testing Rules

- Every service module must have a corresponding unit test file in `tests/unit/`.
- Every router must have integration tests in `tests/integration/` using `httpx.AsyncClient` against a real test app instance.
- Use `testcontainers` for Postgres and Redis in integration tests. Never mock the database in integration tests.
- Never use `unittest.mock` to mock cryptographic operations in integration tests. Use real test keys.
- All tests must be runnable with `pytest` from the repo root with no additional setup beyond `docker compose up`.
- Minimum coverage targets: `app/core/` at 95%, `app/services/` at 90%, `app/routers/` at 85%.
- Every security-sensitive code path (token validation, key comparison, SAML assertion parsing) must have explicit tests for the failure cases, not just the happy path.

---

## SDK Rules

- The SDK lives in `sdk/` and is published as a separate pip package named `auth-service-sdk`.
- It must have zero runtime dependencies beyond `httpx`, `python-jose`, and `starlette`.
- It must expose: `JWTAuthMiddleware`, `APIKeyAuthMiddleware`, `AuthClient` (async HTTP client).
- The middleware must inject a `request.state.user` dict on success with at minimum: `user_id`, `email`, `type`, `scopes`.
- The SDK must never make a network call during token verification for JWT. Verification must be local using the cached public key.
- The SDK must refresh its cached public key from the JWKS endpoint at most once every 5 minutes and on verification failure.

---

## Docker and Kubernetes Rules

- The Dockerfile must be multi-stage. Final image must be based on `python:3.11-slim`.
- The app must run as a non-root user inside the container.
- Never bake secrets, `.env` files, or credentials into the Docker image.
- Kubernetes manifests must include: `Deployment` (min 3 replicas), `HorizontalPodAutoscaler` (target 70% CPU), `PodDisruptionBudget` (minAvailable: 2), `NetworkPolicy`, `Service`, `Ingress`.
- Liveness probe: `GET /health/live`. Readiness probe: `GET /health/ready` (checks Postgres and Redis connectivity).
- Resource requests and limits must be set on every container. Never leave them unset.
- All Kubernetes Secrets must be managed via External Secrets Operator. Never commit raw secret values to the repo.

---

## Code Style Rules

- Python 3.11+. Use type hints everywhere. No untyped function signatures.
- Use `async`/`await` throughout. No synchronous blocking calls in async code paths.
- Pydantic v2 for all schemas. Never use plain dicts for request/response bodies.
- Keep functions under 40 lines. Extract helpers aggressively.
- No commented-out code in committed files.
- Every public function and class must have a docstring.
- Run `ruff` for linting and `black` for formatting before committing. Both must pass with zero errors.

---

## What Not to Build in v1

Do not implement any of the following unless explicitly instructed:

- MFA / TOTP / WebAuthn
- RBAC or scope enforcement beyond storing scopes in the JWT
- Admin API for user management
- Webhook system for auth events
- Consent management for OAuth
- Machine-to-machine Client Credentials flow
- Account lockout after failed attempts (rate limiting covers this in v1)
- Email verification or password reset flows
- Multi-tenancy activation (columns exist but logic is inactive)