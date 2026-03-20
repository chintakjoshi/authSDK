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

## Browser / BFF Integration

Recommended production shape:

1. Browser calls your BFF only.
2. BFF calls this auth service.
3. BFF stores session state in `HttpOnly` cookies or another server-managed session layer.

Password-login contract when verified-email policy is enabled:

- `POST /auth/login` returns `400` with
  `{"detail":"Email is not verified.","code":"email_not_verified"}`
  for correct credentials on an unverified account.
- This is a terminal auth-policy response, not a retryable transport error.
- No access token or refresh token is issued in this branch.
- A BFF should not create cookies, session rows, or partial login state when it receives
  `email_not_verified`.
- The next user action should usually be "Check email" or "Resend verification email".

Verification resend contract:

- `POST /auth/verify-email/resend/request` is the public endpoint a BFF should call when the
  user is blocked by `email_not_verified`.
- On success it always returns `200 {"sent": true}` for unknown, verified, and unverified
  emails. Clients must not infer account existence or verification status from that `200`
  response.
- Only `429 rate_limited` and backend failures should be treated as operational errors.

Lifecycle email link contract:

- Verification and password-reset emails are built from `EMAIL__PUBLIC_BASE_URL`.
- Set that value to the externally reachable origin for this auth service, for example
  `https://auth.example.com`.
- Do not leave it pointed at an internal container hostname or `0.0.0.0`, or emailed links
  will not work outside the local network.

Verification completion contract:

- `GET /auth/verify-email` only marks the email as verified.
- It does not auto-login the user and does not issue tokens.
- After successful verification, the BFF should direct the user back through the normal
  login flow.

Password-reset session contract:

- `POST /auth/password/reset` revokes all active sessions for the user.
- A BFF should clear its own auth cookies if a later refresh, validate, or reauth request
  returns `session_expired` after a password reset.

## Core Endpoints

### Health

- `GET /health/live`
- `GET /health/ready`

### Auth

- `POST /auth/signup`
  - request: `{"email":"user@example.com","password":"Password123!"}`
- `POST /auth/login`
  - request: `{"email":"user@example.com","password":"Password123!","audience":"orders-api"}`
  - `audience` is optional and scopes the issued access token to a downstream service
  - response: token pair or OTP challenge
  - when verified-email login policy is enabled, unverified users receive
    `{"detail":"Email is not verified.","code":"email_not_verified"}`
- `POST /auth/token`
  - refresh flow request: `{"refresh_token":"..."}`
  - client credentials flow:
    `grant_type=client_credentials&client_id=...&client_secret=...&audience=orders-api`
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
- `POST /auth/verify-email/resend/request`
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

1. Use `/auth/signup`, then complete `/auth/verify-email` before `/auth/login`.
2. Use `/auth/verify-email/resend/request` when an unverified user needs a fresh verification email.
3. Use SDK `JWTAuthMiddleware` for protected user routes.
4. Use SDK `APIKeyAuthMiddleware` for machine clients using opaque API keys.
5. Enforce role/action/fresh-auth with SDK dependencies where needed.

## Lifecycle Error Contracts

- `email_not_verified`
  Returned by `POST /auth/login` when credentials are correct but password login requires a
  verified email first.
- `invalid_verify_token`
  Returned when a verification link is blank, expired, replaced by a newer resend, or already
  consumed.
- `invalid_reset_token`
  Returned when a password-reset token is blank, expired, or already consumed.
- `session_expired`
  Returned when a refresh/access-token-backed session is no longer active, including after
  logout or password reset.
- `rate_limited`
  Returned when resend or other protected operations exceed their configured request budget.

## OpenAPI

For full request/response schemas, use:

- `GET /docs` (Swagger UI)
- `GET /openapi.json`
