# Service API Reference (Practical)

This is a practical reference for common integration flows.

Base URL examples assume `http://localhost:8000`.

## Response Error Shape

All errors follow:

```json
{
  "detail": "human readable message",
  "code": "machine_readable_code"
}
```

## Core Endpoints

### Health

- `GET /health/live`
- `GET /health/ready`

### Auth

- `POST /auth/signup`
  - request: `{"email":"user@example.com","password":"Password123!"}`
- `POST /auth/login`
  - request: `{"email":"user@example.com","password":"Password123!"}`
  - response: token pair or OTP challenge
- `POST /auth/token`
  - refresh flow request: `{"refresh_token":"..."}`
  - client credentials flow:
    `grant_type=client_credentials&client_id=...&client_secret=...`
- `POST /auth/logout`
  - request: `{"refresh_token":"..."}`
  - requires bearer access token
- `GET /.well-known/jwks.json`
- `GET /auth/validate`
  - requires bearer access token
- `POST /auth/introspect`
  - request: `{"api_key":"sk_..."}`

### Email / OTP / Lifecycle

- `GET /auth/verify-email`
- `POST /auth/verify-email/resend`
- `POST /auth/password/forgot`
- `GET /auth/password/reset`
- `POST /auth/password/reset`
- `POST /auth/reauth`
- `POST /auth/otp/verify/login`
- `POST /auth/otp/resend/login`
- `POST /auth/otp/request/action`
- `POST /auth/otp/verify/action`
- `POST /auth/otp/enable`
- `POST /auth/otp/disable`
- `POST /auth/users/me/erase`

### OAuth / SAML

- `GET /auth/oauth/google/login`
- `GET /auth/oauth/google/callback`
- `GET /auth/saml/login`
- `GET /auth/saml/metadata`

### API Keys

- `POST /auth/apikeys`
- `GET /auth/apikeys`
- `POST /auth/apikeys/{key_id}/revoke`

### Admin

Admin endpoints are under `/admin/*`.

Auth options:
- bearer access token with admin role
- development-only bootstrap header:
  `X-Admin-API-Key: <configured ADMIN_API_KEY>`

### Webhooks

- `POST /webhooks`
- `GET /webhooks`
- `GET /webhooks/{endpoint_id}/deliveries`
- `POST /webhooks/deliveries/{delivery_id}/retry`

## Recommended Integration Flow

1. Use `/auth/login` to issue tokens for end users.
2. Use SDK `JWTAuthMiddleware` for protected user routes.
3. Use SDK `APIKeyAuthMiddleware` for machine clients using opaque API keys.
4. Enforce role/action/fresh-auth with SDK dependencies where needed.

## OpenAPI

For full request/response schemas, use:

- `GET /docs` (Swagger UI)
- `GET /openapi.json`
