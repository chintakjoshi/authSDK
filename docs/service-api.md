# Service API Guide

This document is the human-readable map of the auth service API. Use the
OpenAPI document for exact request and response schemas.

Base URL examples assume `http://localhost:8000`.

Browser-consumer note:

- browser apps should usually expose these endpoints through a same-origin auth
  proxy such as `/_auth`
- start with `browser-consumer-quickstart.md` for the deployment and request
  model, then use this document for endpoint semantics

## Error Shape

Application errors follow the same basic structure:

```json
{
  "detail": "human readable message",
  "code": "machine_readable_code"
}
```

## Endpoint Families

### Health

- `GET /health/live`
- `GET /health/ready`

### Auth And Token

- `GET /auth/csrf`
- `POST /auth/signup`
- `POST /auth/login`
- `POST /auth/token`
- `POST /auth/logout`
- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

### Self-Service (Bearer-Authenticated)

- `GET /auth/sessions`
- `DELETE /auth/sessions`
- `DELETE /auth/sessions/{session_id}`
- `GET /auth/history`

### Lifecycle And Recovery

- `GET /auth/verify-email`
- `POST /auth/verify-email/resend`
- `POST /auth/verify-email/resend/request`
- `POST /auth/password/forgot`
- `GET /auth/password/reset`
- `POST /auth/password/reset`
- `POST /auth/reauth`
- `POST /auth/users/me/erase`

### OTP

- `POST /auth/otp/verify/login`
- `POST /auth/otp/resend/login`
- `POST /auth/otp/request/action`
- `POST /auth/otp/verify/action`
- `POST /auth/otp/enable`
- `POST /auth/otp/disable`

### OAuth And SAML

- `GET /auth/oauth/google/login`
- `GET /auth/oauth/google/callback`
- `GET /auth/saml/login`
- `GET /auth/saml/metadata`

Federated browser-flow notes:

- `GET /auth/oauth/google/login` accepts optional `redirect_uri` and `audience`
  query params
- `GET /auth/saml/login` accepts optional `relay_state` and `audience` query
  params
- when browser sessions are enabled and caller redirect context is supplied,
  the callback completes by setting auth cookies and returning `303 See Other`
  to the caller instead of a raw JSON token pair
- OAuth validates `redirect_uri` against the configured allowlist
- SAML preserves opaque `relay_state`; when `relay_state` is an allowlisted
  absolute URL, it is treated as the browser return target

### User API Keys

- `POST /auth/apikeys`
- `GET /auth/apikeys`
- `POST /auth/apikeys/{key_id}/revoke`

### Webhooks

- `POST /webhooks`
- `GET /webhooks`
- `GET /webhooks/{endpoint_id}/deliveries`
- `POST /webhooks/deliveries/{delivery_id}/retry`

### Admin

The admin surface lives under `/admin/*`.

Major areas include:

- users (list, detail, role, delete, erase, OTP toggle)
- sessions (per-user list, detail, single revoke, filtered revoke, bulk revoke)
- user history (per-user audit feed)
- API keys
- OAuth clients
- webhooks and deliveries
- audit log
- signing-key rotation

For engineers building admin dashboards or internal tools on top of these
endpoints, see `admin-dashboard-integration.md` for per-endpoint guidance,
step-up flow details, session/history payload shapes, and recommended view
compositions.

## Auth Model By Endpoint Type

Public endpoints:

- signup, login, OAuth entry, JWKS, health, and public lifecycle recovery flows
- CSRF bootstrap through `GET /auth/csrf`

Bearer-token endpoints:

- logout
- validate
- current-user OTP flows
- most authenticated user workflows

Browser-session endpoints:

- `GET /auth/csrf` mints a CSRF cookie and returns the token value
- `POST /auth/login`, `POST /auth/token`, and `POST /auth/logout` accept
  `X-Auth-Session-Transport: cookie`
- when browser sessions are enabled, those endpoints also default to cookie
  mode when browser-session cookies or CSRF request context are already present
- cookie-mode auth responses omit raw access and refresh tokens from the JSON
  body and set cookies instead
- cookie-mode mutation requests require a matching CSRF cookie and
  `X-CSRF-Token` header

Admin endpoints:

- admin bearer token
- or development-only `X-Admin-API-Key` bootstrap access when configured

Step-up protected endpoints:

- some admin mutations and sensitive user operations also require an
  `X-Action-Token`

## Common Integration Flows

### Signup

`POST /auth/signup` returns the same success response for both new and already
registered emails:

```json
{
  "accepted": true
}
```

This avoids revealing account existence through the public signup API. When the
email is available, the service still creates the user and schedules the
verification email after the response is sent.

### Password Login

Request:

```json
{
  "email": "user@example.com",
  "password": "Password123!",
  "audience": "orders-api"
}
```

Notes:

- `audience` is optional but recommended for downstream APIs
- login may return a token pair or an OTP challenge
- login may also return `{ "authenticated": true, "session_transport": "cookie" }`
  when cookie transport is requested or inferred from browser-session context
- if verified email is required and the user is unverified, login returns
  `email_not_verified`

Cookie-mode request requirements:

- fetch a CSRF token first from `GET /auth/csrf`
- send `X-CSRF-Token` matching the CSRF cookie
- expect access and refresh cookies instead of raw token strings
- `X-Auth-Session-Transport: cookie` is optional for browser clients after
  CSRF bootstrap, but still accepted
- `X-Auth-Session-Transport: token` explicitly preserves legacy token-pair
  behavior

### Refresh Token

```json
{
  "refresh_token": "..."
}
```

Cookie-mode refresh does not send a JSON refresh token. It reads the refresh
token from the configured cookie and requires a valid CSRF header.
`X-Auth-Session-Transport: cookie` remains optional-but-supported for explicit
browser clients.

### Client Credentials

`POST /auth/token` also supports form-encoded client credentials:

```text
grant_type=client_credentials
client_id=...
client_secret=...
audience=orders-api
```

### API Key Introspection

```json
{
  "api_key": "sk_..."
}
```

## Important Behavior Contracts

### Email Verification Policy

When `AUTH__REQUIRE_VERIFIED_EMAIL_FOR_PASSWORD_LOGIN=true`:

- `POST /auth/login` returns `400`
- response code is `email_not_verified`
- no token pair is issued
- clients should direct the user toward verification or resend flows

### Verification Resend Privacy

`POST /auth/verify-email/resend/request` always responds with a generic success
payload for unknown, verified, and unverified emails. Callers must not infer
account existence from the response.

### Password Reset Session Revocation

`POST /auth/password/reset` revokes active sessions for the user. Callers should
clear local auth state if later refresh or validation calls return
`session_expired`.

### SDK Expectations

Services using `auth-service-sdk` require these endpoints to exist:

- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

Browser-session consumers should also expose:

- `GET /auth/csrf`

## OpenAPI

Use these for authoritative schemas when `APP__EXPOSE_DOCS=true`:

- `GET /docs`
- `GET /openapi.json`

## Related Docs

- architecture: `architecture.md`
- browser app quickstart: `browser-consumer-quickstart.md`
- SDK integration: `integrate-sdk.md`
- troubleshooting: `troubleshooting.md`
