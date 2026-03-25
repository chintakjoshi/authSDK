# Service API Guide

This document is the human-readable map of the auth service API. Use the
OpenAPI document for exact request and response schemas.

Base URL examples assume `http://localhost:8000`.

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

- `POST /auth/signup`
- `POST /auth/login`
- `POST /auth/token`
- `POST /auth/logout`
- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

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

- users
- API keys
- OAuth clients
- webhooks and deliveries
- audit log
- signing-key rotation

## Auth Model By Endpoint Type

Public endpoints:

- signup, login, OAuth entry, JWKS, health, and public lifecycle recovery flows

Bearer-token endpoints:

- logout
- validate
- current-user OTP flows
- most authenticated user workflows

Admin endpoints:

- admin bearer token
- or development-only `X-Admin-API-Key` bootstrap access when configured

Step-up protected endpoints:

- some admin mutations and sensitive user operations also require an
  `X-Action-Token`

## Common Integration Flows

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
- if verified email is required and the user is unverified, login returns
  `email_not_verified`

### Refresh Token

```json
{
  "refresh_token": "..."
}
```

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

## OpenAPI

Use these for authoritative schemas:

- `GET /docs`
- `GET /openapi.json`

## Related Docs

- architecture: `architecture.md`
- SDK integration: `integrate-sdk.md`
- troubleshooting: `troubleshooting.md`
