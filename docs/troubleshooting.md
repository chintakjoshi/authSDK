# Troubleshooting Guide

Use this when onboarding or integration tests fail.

## 401 Invalid Token

Common causes:
- missing or malformed `Authorization: Bearer <token>`
- expired access token
- wrong signing key cache (stale JWKS in downstream service)
- user session revoked or logged out

Checks:
1. Decode token header and confirm `alg=RS256` and `kid` exists.
2. Verify `GET /.well-known/jwks.json` includes that `kid`.
3. Call `GET /auth/validate` with the access token.

## 403 Insufficient Role / Action Required / Reauth Required

Common causes:
- token is valid but role check fails
- missing `X-Action-Token` for protected action routes
- `auth_time` older than your `require_fresh_auth()` threshold

Checks:
1. Inspect `request.state.user["role"]` in your service.
2. For action-protected routes, confirm `X-Action-Token` header is present.
3. If using `require_fresh_auth(300)`, re-run reauth and retry quickly.

## 503 Auth Service Unavailable (SDK)

Common causes:
- downstream service cannot reach auth service
- auth service returned upstream `5xx`

Checks:
1. Curl `/.well-known/jwks.json` from the downstream service host/container.
2. Curl `/auth/introspect` and `/auth/validate` directly.
3. Check Docker networking and `auth_base_url`.

## API Key Requests Failing

Common causes:
- key revoked/expired
- key not prefixed as `sk_...`
- wrong environment key used in another environment

Checks:
1. Call `/auth/introspect` directly with the same key.
2. Confirm returned `code` (`invalid_api_key`, `expired_api_key`, `revoked_api_key`).

## OTP Flows Not Completing

Common causes:
- OTP not delivered or delayed
- wrong challenge token/user/code pairing
- code expired or max attempts exceeded

Checks:
1. If local, inspect Mailhog UI at `http://localhost:8025`.
2. Confirm code is used with the matching challenge/action.
3. Retry with a new challenge/code.

## Local Stack Not Starting

Checks:
1. Confirm `.env` exists and was copied from `.env-sample`.
2. Run:
   `docker compose -f docker/docker-compose.yml up --build`
3. Check:
   `docker compose -f docker/docker-compose.yml logs -f auth-service`
4. Verify health:
   `curl http://localhost:8000/health/ready`
