# SDK Integration Guide

This guide is for teams integrating `auth-service-sdk` into another Python
service.

If your consumer includes a browser frontend, start with
`browser-consumer-quickstart.md` first. This document focuses on the downstream
Python service side of that integration.

## Install

Published package:

```bash
pip install auth-service-sdk
```

Local path:

```bash
pip install /path/to/authSDK/sdk
```

Git subdirectory install:

```bash
pip install "git+https://github.com/<org>/<repo>.git#subdirectory=sdk"
```

The package name is `auth-service-sdk`. The import namespace is `sdk`.

## Service Requirements

The auth service must expose:

- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

## JWT-Protected Routes

Use `JWTAuthMiddleware` when your service accepts bearer tokens issued by the
auth service.

```python
from fastapi import FastAPI
from sdk import JWTAuthMiddleware

app = FastAPI()

app.add_middleware(
    JWTAuthMiddleware,
    auth_base_url="https://auth.example.com",
    expected_audience="orders-api",
)
```

What it does:

- verifies RS256 JWTs locally with cached JWKS
- refreshes JWKS once on verification failure
- validates user-token session state through `/auth/validate`
- writes the verified identity to `request.state.user`

Machine-to-machine tokens with type `m2m` are accepted by the middleware when
they satisfy the expected audience and claim checks.

For browser-cookie sessions, enable cookie extraction explicitly:

```python
from fastapi import FastAPI
from sdk import CookieCSRFMiddleware, JWTAuthMiddleware

app = FastAPI()
app.add_middleware(
    CookieCSRFMiddleware,
    csrf_cookie_name="auth_csrf",
    csrf_header_name="X-CSRF-Token",
    access_cookie_name="auth_access",
)
app.add_middleware(
    JWTAuthMiddleware,
    auth_base_url="https://auth.example.com",
    expected_audience="orders-api",
    token_sources=["authorization", "cookie"],
    access_cookie_name="auth_access",
)
```

Cookie-mode notes:

- register `CookieCSRFMiddleware` before `JWTAuthMiddleware`; FastAPI/Starlette
  executes the most recently added middleware first
- the cookie names above match the local HTTP browser-session baseline; in
  HTTPS production, match your authSDK config, often `__Host-auth_access` and
  `__Host-auth_csrf`
- `Authorization` still takes precedence when both a bearer token and cookie
  are present
- authenticated source is recorded on `request.state.auth_transport`
- `CookieCSRFMiddleware` only enforces unsafe requests authenticated through
  cookies

## API-Key-Protected Routes

Use `APIKeyAuthMiddleware` when your service accepts opaque API keys.

```python
from fastapi import FastAPI
from sdk import APIKeyAuthMiddleware

app = FastAPI()
app.add_middleware(
    APIKeyAuthMiddleware,
    auth_base_url="https://auth.example.com",
)
```

What it does:

- extracts keys from `X-API-Key` or `Authorization: ApiKey ...`
- caches valid introspection results
- caches invalid introspection results briefly
- fails closed with `503` when the auth service is unavailable

## Route-Level Authorization Dependencies

```python
from fastapi import Depends, FastAPI
from sdk import require_action_token, require_fresh_auth, require_role

app = FastAPI()

@app.get("/admin")
async def admin_route(user=Depends(require_role("admin"))):
    return {"user": user}

@app.post("/dangerous")
async def dangerous_route(
    user=Depends(
        require_action_token(
            "erase_account",
            auth_base_url="https://auth.example.com",
            expected_audience="orders-api",
        )
    )
):
    return {"user": user}

@app.post("/sensitive")
async def sensitive_route(user=Depends(require_fresh_auth(300))):
    return {"user": user}
```

Use them for:

- role gates
- OTP-backed step-up actions
- recent-authentication requirements

## Identity Shape

After successful auth, `request.state.user` contains one of these identity
shapes.

User token:

```json
{
  "type": "user",
  "user_id": "uuid",
  "email": "user@example.com",
  "email_verified": true,
  "mfa_enabled": false,
  "role": "user",
  "scopes": [],
  "auth_time": 1710000000
}
```

Service token:

```json
{
  "type": "service",
  "client_id": "client-id",
  "role": "service",
  "scopes": ["metrics:read"],
  "email": null
}
```

API key:

```json
{
  "type": "api_key",
  "key_id": "uuid",
  "service": "orders",
  "scopes": ["orders:read"],
  "email": null
}
```

The middleware also sets:

- `request.state.auth_transport = "authorization"` for bearer-token requests
- `request.state.auth_transport = "cookie"` for cookie-authenticated requests

## Failure Semantics

- `401`
  invalid token or API key
- `403`
  authenticated, but blocked by role, action token, or stale-auth policy
- `503`
  auth service unavailable for a required online validation step

## Audience Guidance

Set `expected_audience` to your service identifier and request that same
audience when your clients obtain tokens. This prevents a token minted for one
service from being replayed against another.

## Related Docs

- SDK package README: `../sdk/README.md`
- browser app quickstart: `browser-consumer-quickstart.md`
- service API guide: `service-api.md`
- troubleshooting: `troubleshooting.md`
