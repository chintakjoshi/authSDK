# Configuration Reference

The application uses nested environment variables loaded by Pydantic Settings
with `__` as the delimiter.

Example:

```text
APP__ENVIRONMENT=development
DATABASE__URL=postgresql+asyncpg://postgres:postgres@localhost:5432/auth_service
```

`.env-sample` is the authoritative local template. This document explains how
those values map to the runtime model and which settings matter in production.

## How Configuration Is Loaded

- settings are defined in `app/config.py`
- environment variables are loaded from process env and `.env`
- nested models use the `SECTION__KEY=value` convention
- list settings such as allowlists should be provided as JSON arrays

Examples:

```text
APP__ALLOWED_HOSTS=["auth.example.com","api.auth.example.com"]
OAUTH__REDIRECT_URI_ALLOWLIST=["https://app.example.com/callback"]
```

## Required Baseline Settings

These are required for any meaningful runtime:

- `APP__ENVIRONMENT`
- `DATABASE__URL`
- `REDIS__URL`
- `JWT__PRIVATE_KEY_PEM`
- `JWT__PUBLIC_KEY_PEM`
- `OAUTH__GOOGLE_CLIENT_ID`
- `OAUTH__GOOGLE_CLIENT_SECRET`
- `OAUTH__GOOGLE_REDIRECT_URI`
- `OAUTH__REDIRECT_URI_ALLOWLIST`
- `SAML__SP_ENTITY_ID`
- `SAML__SP_ACS_URL`
- `SAML__SP_X509_CERT`
- `SAML__SP_PRIVATE_KEY`
- `SAML__IDP_ENTITY_ID`
- `SAML__IDP_SSO_URL`
- `SAML__IDP_X509_CERT`

For Docker-based local development, the compose stack provides working defaults
for most values and can generate ephemeral JWT keys on container boot.

## Production-Only Requirements

When `APP__ENVIRONMENT=production`, startup rejects unsafe configurations.

Required in production:

- `APP__ALLOWED_HOSTS`
- `SIGNING_KEYS__ENCRYPTION_KEY`
- `WEBHOOK__SECRET_ENCRYPTION_KEY`
- `BROWSER_SESSIONS__SECURE_ONLY=true` when browser sessions are enabled
- HTTPS OAuth redirect URI
- HTTPS redirect URI allowlist entries
- HTTPS SAML ACS URL
- HTTPS SAML IdP SSO URL
- HTTPS `EMAIL__PUBLIC_BASE_URL`

Forbidden in production:

- `ADMIN_API_KEY`
- wildcard `APP__ALLOWED_HOSTS`

## Settings By Area

### App

- `APP__ENVIRONMENT`
  one of `development`, `staging`, `production`
- `APP__SERVICE`
  service name used in logs and default auth-service audience
- `APP__HOST`
  bind host for local or process-based startup
- `APP__PORT`
  bind port
- `APP__LOG_LEVEL`
  one of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- `APP__TRUSTED_PROXY_CIDRS`
  optional JSON array of proxy CIDRs
- `APP__ALLOWED_HOSTS`
  optional in non-production, required in production
- `APP__EXPOSE_DOCS`
  defaults to `false`; set to `true` only when you want `/docs` and
  `/openapi.json` exposed

### Database

- `DATABASE__URL`
  must use the `postgresql+asyncpg://` SQLAlchemy URL form

### Redis

- `REDIS__URL`
  must use `redis://` or `rediss://`

### JWT

- `JWT__ALGORITHM`
  currently `RS256`
- `JWT__PRIVATE_KEY_PEM`
  private signing key
- `JWT__PUBLIC_KEY_PEM`
  public verification key
- `JWT__ACCESS_TOKEN_TTL_SECONDS`
- `JWT__REFRESH_TOKEN_TTL_SECONDS`

### OAuth

- `OAUTH__GOOGLE_CLIENT_ID`
- `OAUTH__GOOGLE_CLIENT_SECRET`
- `OAUTH__GOOGLE_REDIRECT_URI`
- `OAUTH__REDIRECT_URI_ALLOWLIST`

### SAML

- `SAML__SP_ENTITY_ID`
- `SAML__SP_ACS_URL`
- `SAML__SP_X509_CERT`
- `SAML__SP_PRIVATE_KEY`
- `SAML__IDP_ENTITY_ID`
- `SAML__IDP_SSO_URL`
- `SAML__IDP_X509_CERT`

### Rate Limiting

- `RATE_LIMIT__DEFAULT_REQUESTS_PER_MINUTE`
- `RATE_LIMIT__LOGIN_REQUESTS_PER_MINUTE`
- `RATE_LIMIT__TOKEN_REQUESTS_PER_MINUTE`

### Auth Policy

- `AUTH__REQUIRE_VERIFIED_EMAIL_FOR_PASSWORD_LOGIN`
  blocks password login until email verification is complete

### Browser Sessions

- `BROWSER_SESSIONS__ENABLED`
  enables cookie-mode auth endpoints and cookie helpers
- `BROWSER_SESSIONS__INFER_COOKIE_TRANSPORT`
  defaults to `true`; when enabled, authSDK treats browser-session signals such
  as CSRF/session cookies as cookie transport even without an explicit
  transport header
- `BROWSER_SESSIONS__TRANSPORT_HEADER_NAME`
  explicit browser transport selector, defaults to `X-Auth-Session-Transport`;
  `token` still overrides browser-session inference when needed
- `BROWSER_SESSIONS__ACCESS_COOKIE_NAME`
  access JWT cookie name, defaults to `__Host-auth_access`
- `BROWSER_SESSIONS__REFRESH_COOKIE_NAME`
  refresh cookie name, defaults to `__Host-auth_refresh`
- `BROWSER_SESSIONS__CSRF_COOKIE_NAME`
  CSRF cookie name, defaults to `__Host-auth_csrf`
- `BROWSER_SESSIONS__SAME_SITE`
  one of `lax`, `strict`, `none`
- `BROWSER_SESSIONS__SECURE_ONLY`
  must be `true` in production when browser sessions are enabled
- `BROWSER_SESSIONS__COOKIE_DOMAIN`
  leave unset for host-only cookies; only set this intentionally for broader
  cookie scope
- `BROWSER_SESSIONS__ACCESS_COOKIE_PATH`
  access cookie path, usually `/`
- `BROWSER_SESSIONS__REFRESH_COOKIE_PATH`
  refresh cookie path; use your same-origin auth prefix such as `/_auth`
- `BROWSER_SESSIONS__CSRF_COOKIE_PATH`
  CSRF cookie path, usually `/`
- `BROWSER_SESSIONS__CSRF_HEADER_NAME`
  CSRF request header name, defaults to `X-CSRF-Token`

Prefix-validation rules:

- `__Secure-*` cookie names require `BROWSER_SESSIONS__SECURE_ONLY=true`
- `__Host-*` cookie names require `BROWSER_SESSIONS__SECURE_ONLY=true`
- `__Host-*` cookie names require `BROWSER_SESSIONS__COOKIE_DOMAIN` to stay unset
- `__Host-*` cookie names require the matching cookie path to be `/`
- if you want `BROWSER_SESSIONS__REFRESH_COOKIE_PATH=/_auth`, do not use
  `__Host-*` for the refresh cookie name

### Signing Keys

- `SIGNING_KEYS__ROTATION_OVERLAP_SECONDS`
- `SIGNING_KEYS__ENCRYPTION_KEY`

### Email And OTP

- `EMAIL__MAILHOG_HOST`
- `EMAIL__MAILHOG_PORT`
- `EMAIL__EMAIL_FROM`
- `EMAIL__PUBLIC_BASE_URL`
- `EMAIL__EMAIL_VERIFY_TTL_SECONDS`
- `EMAIL__PASSWORD_RESET_TTL_SECONDS`
- `EMAIL__OTP_CODE_LENGTH`
- `EMAIL__OTP_TTL_SECONDS`
- `EMAIL__OTP_MAX_ATTEMPTS`
- `EMAIL__ACTION_TOKEN_TTL_SECONDS`

### Webhooks

- `WEBHOOK__QUEUE_NAME`
- `WEBHOOK__REQUEST_TIMEOUT_SECONDS`
- `WEBHOOK__RESPONSE_BODY_MAX_CHARS`
- `WEBHOOK__WORKER_TTL_SECONDS`
- `WEBHOOK__REDIS_HEALTH_CHECK_INTERVAL_SECONDS`
- `WEBHOOK__SECRET_ENCRYPTION_KEY`

### Retention

- `RETENTION__ENABLE_RETENTION_PURGE`
- `RETENTION__AUDIT_LOG_RETENTION_DAYS`
- `RETENTION__SESSION_LOG_RETENTION_DAYS`
- `RETENTION__PURGE_CRON`

### Development Bootstrap

- `ADMIN_API_KEY`
  only valid in development; enables `X-Admin-API-Key` access to `/admin/*`

## Local Development Notes

- `.env-sample` is designed for the Docker stack
- `.env` is gitignored and should hold local overrides
- the compose stack wires container-internal URLs for Postgres and Redis
- if JWT PEM values are omitted in Docker, the container generates ephemeral
  keys on startup

Browser-session notes:

- for browser consumers, prefer same-origin `/_auth` and `/api` proxy routes
- leave `BROWSER_SESSIONS__COOKIE_DOMAIN` unset unless you intentionally need
  broader cookie scope
- in local HTTP development, use non-prefixed cookie names such as
  `auth_access`, `auth_refresh`, and `auth_csrf`
- in local HTTP development, `BROWSER_SESSIONS__SECURE_ONLY=false` is acceptable
  until the app is served over HTTPS
- in HTTPS production, prefer host-only names such as `__Host-auth_access`,
  `__Secure-auth_refresh`, and `__Host-auth_csrf`
- once a browser app moves to cookie sessions, it should stop persisting raw
  auth tokens in JavaScript-readable storage

## Related Docs

- local workflow: `../DEVELOPMENT.md`
- architecture: `architecture.md`
- browser app quickstart: `browser-consumer-quickstart.md`
- operations: `operations.md`
- troubleshooting: `troubleshooting.md`
