# Troubleshooting

Use this guide when local onboarding, deployment, or integration behavior does
not match expectations.

## Local Stack Will Not Start

Checks:

1. Confirm `.env` exists or rely on `.env-sample`.
2. Start the stack from the repo root:

```powershell
docker compose -f docker/docker-compose.yml up --build
```

3. Inspect auth-service logs:

```powershell
docker compose -f docker/docker-compose.yml logs -f auth-service
```

4. Verify readiness:

```powershell
curl http://localhost:8000/health/ready
```

Useful local UIs:

- Swagger UI: `http://localhost:8000/docs`
- Mailhog: `http://localhost:8025`
- Adminer: `http://localhost:8080`

If a stale Postgres volume is causing confusion, recreate it:

```powershell
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d --build
```

## `401` Invalid Token

Common causes:

- missing bearer token
- expired token
- invalid audience
- stale JWKS in a downstream service
- revoked or expired session

Checks:

1. Inspect the JWT header and confirm `alg=RS256` and a `kid` are present.
2. Confirm that `kid` exists in `GET /.well-known/jwks.json`.
3. Call `GET /auth/validate` with the same bearer token.
4. Confirm the downstream service is using the expected audience.

## `401` Invalid API Key

Common causes:

- wrong header shape
- key revoked or expired
- key created in a different environment

Checks:

1. Retry with `X-API-Key: sk_...` or `Authorization: ApiKey sk_...`.
2. Call `POST /auth/introspect` directly.
3. Inspect the returned error code:
   `invalid_api_key`, `expired_api_key`, or `revoked_api_key`.

## `403` Insufficient Role Or Step-Up Required

Common causes:

- valid token, wrong role
- missing `X-Action-Token`
- stale `auth_time`

Checks:

1. Inspect `request.state.user`.
2. Confirm the route is using the expected SDK dependency.
3. For action-protected routes, send `X-Action-Token`.
4. For fresh-auth checks, reauthenticate and retry promptly.

## `503` From SDK-Protected Routes

Common causes:

- downstream service cannot reach auth service
- auth service is returning `5xx`
- required online validation endpoint is unavailable

Checks:

1. From the downstream runtime, call `/.well-known/jwks.json`.
2. Call `/auth/validate`.
3. Call `/auth/introspect`.
4. Verify the configured `auth_base_url`.

## Email Verification Or Password Reset Links Are Wrong

Common cause:

- `EMAIL__PUBLIC_BASE_URL` points at an internal hostname, container address, or
  local bind address that the user cannot reach

Fix:

- set `EMAIL__PUBLIC_BASE_URL` to the externally reachable origin of the auth
  service

## OTP Flow Is Not Completing

Common causes:

- wrong challenge/code pairing
- expired code
- max-attempt threshold exceeded
- email delivery issue

Checks:

1. In local development, inspect Mailhog at `http://localhost:8025`.
2. Verify the code belongs to the current challenge.
3. Request a fresh OTP and retry.

## `403` Invalid CSRF Token Or Browser Login Never Sticks

Common causes:

- the browser rejected one or more auth cookies, so CSRF and session state were
  never established
- a cookie name starts with `__Host-` while `BROWSER_SESSIONS__SECURE_ONLY=false`
- a cookie name starts with `__Host-` but the matching cookie path is not `/`
- a cookie name starts with `__Secure-` on plain `http://localhost`

Checks:

1. Inspect the browser devtools Application or Storage tab and confirm the
   access, refresh, and CSRF cookies are actually being stored.
2. Confirm local HTTP development uses non-prefixed names such as
   `auth_access`, `auth_refresh`, and `auth_csrf`.
3. If you are using `__Host-*`, verify all of these are true:
   - `BROWSER_SESSIONS__SECURE_ONLY=true`
   - `BROWSER_SESSIONS__COOKIE_DOMAIN` is unset
   - the matching cookie path is `/`
4. If you want `BROWSER_SESSIONS__REFRESH_COOKIE_PATH=/_auth`, use
   `__Secure-auth_refresh` or a non-prefixed refresh cookie name instead of
   `__Host-auth_refresh`.
5. Call `GET /auth/csrf` and verify the response includes a `Set-Cookie` header
   for the configured CSRF cookie name.

Fix:

- for local HTTP development, use the `.env-sample` browser-session values as-is
- for HTTPS production, keep `BROWSER_SESSIONS__SECURE_ONLY=true` and use
  `__Host-auth_access`, `__Secure-auth_refresh`, and `__Host-auth_csrf`

## Webhook Worker Stops After Idle Time

Common cause:

- the Redis network path drops long-idle connections

Checks:

1. Inspect worker logs for Redis timeout behavior.
2. Confirm the worker and scheduler are both running.
3. Lower `WEBHOOK__WORKER_TTL_SECONDS` if needed.
4. Keep `WEBHOOK__REDIS_HEALTH_CHECK_INTERVAL_SECONDS` enabled.

## Admin Access Is Failing

Checks:

1. In development, confirm `ADMIN_API_KEY` is configured if you are using
   `X-Admin-API-Key`.
2. Remember the bootstrap key only works in development.
3. In non-development environments, use an admin bearer token.

## Still Blocked?

Use these docs together:

- environment issues: `configuration.md`
- endpoint behavior: `service-api.md`
- deployment/runtime issues: `operations.md`
