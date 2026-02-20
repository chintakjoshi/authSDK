# Auth Service - Agent Rules

These rules are non-negotiable constraints for building this service. Read
this file before writing any code, modifying any file, or making any
architectural decision.

---

## Project Context

This is a production-level FastAPI authentication microservice that issues
and validates tokens for multiple consuming services. It supports
OAuth2/OIDC (Google), SAML 2.0, JWT (stateless, RS256), API Keys, and
hybrid sessions (JWT + Redis). It is deployed on Kubernetes with Postgres
and Redis as backing services. A companion SDK package is shipped
separately for consuming services to integrate with.

This is v1. Do not add MFA, RBAC, admin API, webhooks, or consent
management unless explicitly asked.

---

## Architecture Rules

- Never flatten logic into `main.py`. `main.py` is only for app factory,
  middleware registration, and router inclusion.
- All business logic lives in `app/services/`. Routers only handle
  request/response shaping and call services.
- All cryptographic and protocol logic (JWT, OAuth, SAML, API keys) lives
  in `app/core/`. Services call core modules.
- The SDK in `sdk/` is a separate package. It must not import anything
  from `app/`. It only uses the public HTTP API of the service.
- Never add a new router without a corresponding service module.
- Never access the database directly from a router. Always go through a
  service.
- `app/config.py` is the only place settings are defined. Never hardcode
  config values or use `os.getenv()` anywhere else.

---

## Database Rules

- Use async SQLAlchemy with `asyncpg`. Never use synchronous DB calls.
- Every table must have: `id` (UUID, default generated), `created_at`,
  `updated_at`, `deleted_at` (nullable, for soft deletes).
- Every table must have a `tenant_id` column (UUID, nullable for now) even
  if multi-tenancy is not active in v1.
- Never hard-delete user or session records. Always soft-delete via
  `deleted_at`.
- All schema changes go through Alembic migrations. Never use `create_all()`
  in production code paths.
- Never write raw SQL strings. Use SQLAlchemy ORM or Core expression
  language.
- Always filter soft-deleted records in queries (`WHERE deleted_at IS NULL`).

---

## Security Rules (Non-Negotiable)

- Never store plaintext passwords. Use `passlib` with `bcrypt`.
- Never store plaintext API keys. Store `sha256(key)`. Return the raw key
  only once at creation time.
- Never store plaintext refresh tokens. Store `sha256(token)` in DB only.
  The raw token never touches Redis.
- Always use `hmac.compare_digest()` for token and key comparisons. Never
  use `==`.
- Use RS256 (asymmetric) for JWT signing. Never use HS256 in any code path.
- Never log tokens, passwords, API keys, or any credential material. Redact
  them at the logging middleware level.
- Always validate `redirect_uri` against a stored allowlist before
  initiating or completing any OAuth flow.
- Never trust user-supplied input in SAML assertions without signature
  validation via `python3-saml`.
- All cookies must be set with `Secure=True`, `HttpOnly=True`,
  `SameSite=Strict`.
- Never put secrets in code, comments, or committed files. All secrets come
  from environment variables or mounted Kubernetes Secrets.

---

## JWT Rules

- Access tokens expire in 15 minutes. Refresh tokens expire in 7 days.
- Every JWT must include a `jti` (JWT ID) claim as a UUID. This is required
  for blocklist-based revocation.
- Every JWT must include `iat`, `exp`, `sub` (user ID), `type` (`access` or
  `refresh`).
- The JWKS endpoint (`GET /.well-known/jwks.json`) must always be public and
  unauthenticated.
- Never issue an access token without a corresponding session record existing
  in both Redis and the DB. This applies to user-login flows only (password,
  OAuth, SAML). API key identity flows are sessionless by design and must not
  create session records.
- On refresh, always rotate the refresh token (issue a new one, invalidate
  the old one).

---

## Session Rules

### Refresh Token Persistence (authoritative model)

Refresh tokens and session data are split across DB and Redis deliberately.
They serve different purposes and must not be conflated.

**DB `sessions` table** is the authoritative record. It stores:
- `session_id` (UUID, stable across all rotations, primary key)
- `user_id`
- `hashed_refresh_token` (sha256 of the raw token, updated on every
  rotation)
- `expires_at`
- `revoked_at` (null until logout or forced revocation)

**Redis** stores session payload data only, keyed by session ID, not by
token hash:
- Key: `session:{session_id}`
- Value: `{ user_id, email, scopes, issued_at }`
- TTL: equal to `refresh_token_ttl_seconds`

Redis is a performance cache. DB is the source of truth. Session rebuild from
DB is a controlled disaster-recovery operation (manual or recovery job), never
an inline auth path.

**Refresh flow (exact sequence):**
1. Hash the incoming raw token: `sha256(raw_token)`
2. Look up `hashed_refresh_token` in DB to find the session record
3. Validate `expires_at` and `revoked_at` on the DB record before touching
   Redis
4. Use `session_id` from the DB record to fetch session payload from Redis
5. If Redis key is missing, fail closed with `session_expired`. Do not fall
   back to DB-only and do not attempt inline rebuild from DB.
6. Rotate: generate new raw token, update `hashed_refresh_token` in DB,
   reset Redis TTL
7. Return new access token and new refresh token

**Why Redis is keyed by session_id and not token hash:** `session_id` is
stable across all rotations. Keying by token hash would require deleting and
recreating the Redis key on every refresh, which is wasteful and introduces
a consistency race window.

**The raw refresh token never touches Redis.** The Redis value is session
metadata only. The "never store plaintext refresh tokens" security rule
applies to the DB `hashed_refresh_token` column. There is nothing to hash
in Redis because the token is never stored there.

### Other Session Rules

- On logout: delete the Redis key AND set `revoked_at` on the DB session.
  Use a transactional wrapper that rolls back the DB write if the Redis
  delete fails.
- If Redis is unavailable, fail closed on all session-dependent operations.
  Never silently fall back to DB-only session validation.
- The JWT blocklist lives in Redis under key `blocklist:jti:{jti}` with TTL
  equal to the remaining lifetime of the token.
- `session_id` is generated once at login and never changes. It is never
  exposed to the client. The client only ever holds the raw refresh token.

---

## API Key Rules

- API key format is always `sk_{secrets.token_urlsafe(32)}`.
- Store the first 8 characters of the raw key as `key_prefix` in the DB for
  display purposes.
- API keys must have an optional `expires_at` field. Expired keys must be
  rejected even if otherwise valid.
- API keys must be scoped to a service or purpose via a `scope` field. Never
  issue unscoped keys.

---

## OAuth / OIDC Rules

- Use `authlib` for all OAuth2 client operations. Never implement token
  exchange or PKCE manually.
- Always verify the `id_token` signature from Google using their public JWKS.
  Never skip this step.
- After a successful OAuth callback, always upsert into `user_identities`
  first, then resolve or create the canonical `users` record.
- Never trust the `email` from an OAuth provider without checking
  `email_verified: true` in the claims.
- Never store OAuth `state` or `nonce` in cookies. `SameSite=Strict` cookies
  are not sent on cross-site redirect callbacks, so cookie-based state will
  not be present when the provider redirects back to your callback URL. Store
  state and nonce server-side in Redis instead.
- OAuth state storage model: on login, generate `state` and `nonce`, store
  in Redis under key `oauth_state:{state}` with TTL of 10 minutes, then
  include `state` and `nonce` in the authorization URL. On callback, look up
  `oauth_state:{state}` in Redis, reject with `oauth_state_mismatch` if
  missing or expired, delete the key immediately after reading (one-time use
  only), then proceed with token exchange.

---

## SAML Rules

- Use `python3-saml` for all SAML operations. Never parse SAMLResponse XML
  manually.
- Always validate the assertion signature, conditions, and audience
  restriction.
- Expose SP metadata at `GET /auth/saml/metadata`. This must be kept up to
  date with the current certificate.
- After successful SAML assertion, apply the same upsert flow as OAuth via
  `user_identities`.

---

## Middleware Rules

The middleware stack must be applied in this exact order (outermost to
innermost):

1. **Correlation ID** -- must be outermost. Every layer below it depends on
   the request-scoped correlation ID being present. Nothing works correctly
   without it.
2. **Prometheus metrics** -- must be outside rate limiting so it counts 100%
   of traffic including rejected requests. Metrics inside rate limiting
   undercount real traffic and make dashboards untrustworthy.
3. **Security headers** (CSP, X-Frame-Options, X-Content-Type-Options,
   Strict-Transport-Security) -- must be outside rate limiting so that 429
   responses, 401s, and 500s all carry the correct headers. A rate-limited
   response without security headers is a misconfiguration.
4. **Structured logging** -- must wrap rate limiting so that rate limit
   rejections are logged with their outcome. Needs correlation ID from step 1
   already attached.
5. **Rate limiting** (Redis sliding window, stricter limits on `/auth/login`
   and `/auth/token`) -- rejects bad traffic before expensive downstream work
   happens, but sits inside logging so rejections are captured.
6. **OpenTelemetry tracing** -- must be innermost so traces measure actual
   handler execution time only. Wrapping the full stack inflates span
   duration with middleware overhead that is not meaningful to service
   latency analysis.

Never add business logic inside middleware. Middleware is only for
cross-cutting concerns.

**Starlette registration note:** Starlette applies middleware in reverse
registration order. To achieve the execution order above, register in
reverse:

```python
app.add_middleware(TracingMiddleware)        # innermost, registered first
app.add_middleware(RateLimitMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(CorrelationIdMiddleware)  # outermost, registered last
```

---

## Error Handling Rules

- Never return stack traces or internal error details to the client in
  production (`environment != "development"`).
- All error responses follow this exact shape:
  `{"detail": "<human readable message>", "code": "<machine readable code>"}`.
- Valid error codes: `invalid_token`, `token_expired`, `invalid_api_key`,
  `expired_api_key`, `revoked_api_key`, `invalid_credentials`,
  `rate_limited`, `saml_assertion_invalid`, `oauth_state_mismatch`,
  `session_expired`.
- All auth failures (wrong password, invalid token, expired key) must be
  logged at `WARNING` level with the correlation ID and user identifier (if
  known).
- Never raise a 500 for an expected auth failure. Map all known failure cases
  to 4xx explicitly.

---

## Logging Rules

- Use `structlog` with JSON output. Never use `print()` or the stdlib
  `logging` module directly.
- Every log entry must include: `correlation_id`, `environment`, `service`,
  `level`, `timestamp` (ISO 8601, UTC).
- Auth event logs must additionally include: `event_type`, `user_id` (if
  known), `provider`, `ip_address`, `success` (bool).
- Never log PII beyond what is strictly necessary. Email addresses may be
  logged at INFO level. Names, phone numbers, and addresses must not be
  logged.
- Log every token issuance, token refresh, login attempt, logout, and API
  key usage as a structured auth event.

---

## Testing Rules

- Every service module must have a corresponding unit test file in
  `tests/unit/`.
- Every router must have integration tests in `tests/integration/` using
  `httpx.AsyncClient` against a real test app instance.
- Use `testcontainers` for Postgres and Redis in integration tests. Never
  mock the database in integration tests.
- Never use `unittest.mock` to mock cryptographic operations in integration
  tests. Use real test keys.
- All tests must be runnable with `pytest` from the repo root with no
  additional setup beyond `docker compose up`.
- Minimum coverage targets: `app/core/` at 95%, `app/services/` at 90%,
  `app/routers/` at 85%.
- Every security-sensitive code path (token validation, key comparison, SAML
  assertion parsing) must have explicit tests for failure cases, not just the
  happy path.

---

## SDK Rules

- The SDK lives in `sdk/` and is published as a separate pip package named
  `auth-service-sdk`.
- It must have zero runtime dependencies beyond `httpx`, `python-jose`,
  `cachetools`, and `starlette`.
- It must expose: `JWTAuthMiddleware`, `APIKeyAuthMiddleware`, `AuthClient`
  (async HTTP client).

### request.state.user shape

The injected user object is type-discriminated by the `type` field:

- `type: "user"` (password / OAuth / SAML login):
  `{ type, user_id, email (required), scopes }`
- `type: "api_key"` (API key identity):
  `{ type, key_id, service, scopes, email: None }`

`email` is required when `type == "user"` and must be absent or None when
`type == "api_key"`. Consuming services must check `type == "user"` before
accessing `email`.

### JWT Verification (local)

- The SDK must never make a network call during JWT verification.
  Verification is local using the cached public key.
- The SDK refreshes its cached public key from the JWKS endpoint at most
  once every 5 minutes and on verification failure.
- Verification is purely cryptographic. No network call per request is
  acceptable.

### API Key Verification (network introspection with local cache)

API keys are opaque random strings with no cryptographic self-verification
property. Local-only verification is not possible without replicating the
full key database into every consuming service, which is a security
anti-pattern. The correct model is network introspection with a mandatory
short-lived in-process cache.

**Verification flow:**
1. Hash the raw key on arrival: `sha256(raw_key)`. Never hold the raw key
   longer than this step.
2. Check the in-process cache keyed by `sha256(raw_key)`.
3. On cache hit: use the cached result directly. No network call.
4. On cache miss: call `POST /auth/introspect` on the auth service with the raw
   key.
5. Auth service hashes it, validates against DB (expiry, revocation, scope),
   returns `{ valid, user_id, scopes, key_id, expires_at }`.
6. Cache valid results keyed by `sha256(raw_key)` with TTL of 60 seconds.
7. Cache invalid results for 10 seconds to prevent hammering the auth service
   with bad keys.
8. On valid result: inject `request.state.user` and continue.
9. On invalid result: return 401 immediately.

**Cache rules:**
- Cache is in-process only using `cachetools.TTLCache`. Never use Redis or
  any shared external cache. The entire point is to avoid a network call per
  request.
- Default TTL is 60 seconds. A revoked key remains valid on a given service
  instance for up to 60 seconds. This is an accepted and documented
  tradeoff.
- For immediate revocation of a compromised key, the operational response is
  key deletion at the source, not cache invalidation. Document this in the
  SDK README.
- Cache is keyed by `sha256(raw_key)`. Never cache by raw key. Raw keys are
  credential material and must not persist in memory.

**Failure behavior:**
- If the auth service is unreachable during introspection, return 503 (not
  401). 503 signals the failure is transient and retryable. 401 signals bad
  credentials. These are not the same.
- Never fall back to a stale cache entry when the auth service is
  unreachable.
- Never serve a request with an unverified API key regardless of cache state.

**Introspection endpoint contract (`POST /auth/introspect`):**

On success:
`{ "valid": true, "user_id": "...", "scopes": [...], "key_id": "...", "expires_at": "..." }`

On failure:
`{ "valid": false, "code": "invalid_api_key" | "expired_api_key" | "revoked_api_key" }`

---

## Docker and Kubernetes Rules

- The Dockerfile must be multi-stage. Final image must be based on
  `python:3.11-slim`.
- The app must run as a non-root user inside the container.
- Never bake secrets, `.env` files, or credentials into the Docker image.
- Kubernetes manifests must include: `Deployment` (min 3 replicas),
  `HorizontalPodAutoscaler` (target 70% CPU), `PodDisruptionBudget`
  (minAvailable: 2), `NetworkPolicy`, `Service`, `Ingress`.
- Liveness probe: `GET /health/live`. Readiness probe: `GET /health/ready`
  (checks Postgres and Redis connectivity).
- Resource requests and limits must be set on every container. Never leave
  them unset.
- All Kubernetes Secrets must be managed via External Secrets Operator.
  Never commit raw secret values to the repo.

---

## Code Style Rules

- Python 3.11+. Use type hints everywhere. No untyped function signatures.
- Use `async`/`await` throughout. No synchronous blocking calls in async
  code paths.
- Pydantic v2 for all schemas. Never use plain dicts for request/response
  bodies.
- Keep functions under 40 lines. Extract helpers aggressively.
- No commented-out code in committed files.
- Every public function and class must have a docstring.
- Run `ruff` for linting and `black` for formatting before committing. Both
  must pass with zero errors.

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
