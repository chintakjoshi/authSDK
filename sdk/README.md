# auth-service-sdk

`auth-service-sdk` provides middleware and dependencies for protecting routes
with JWTs, API keys, role checks, action-token checks, and fresh-auth checks.

## Quick Navigation

- Full onboarding path: `../docs/README.md`
- Service integration quickstart: `../docs/integrate-sdk.md`
- Auth API contract summary: `../docs/service-api.md`
- Troubleshooting: `../docs/troubleshooting.md`

## Installation

```bash
pip install auth-service-sdk
```

## Minimum Service Endpoints Required

The SDK expects an auth service that exposes:

- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

## JWTAuthMiddleware

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from sdk import JWTAuthMiddleware


async def protected(request):
    return JSONResponse({"user": request.state.user})


app = Starlette(routes=[Route("/protected", protected)])
app.add_middleware(
    JWTAuthMiddleware,
    auth_base_url="https://auth.example.com",
    expected_audience="orders-api",
)
```

Behavior:
- JWT verification is local using cached JWKS.
- User access tokens are then validated against auth-service session state via
  `/auth/validate`.
- JWKS cache TTL is 5 minutes.
- On verification failure, middleware forces one JWKS refresh and retries once.

## APIKeyAuthMiddleware

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from sdk import APIKeyAuthMiddleware


async def protected(request):
    return JSONResponse({"identity": request.state.user})


app = Starlette(routes=[Route("/protected", protected)])
app.add_middleware(
    APIKeyAuthMiddleware,
    auth_base_url="https://auth.example.com",
)
```

Behavior:
- API key cache key is `sha256(raw_key)`.
- Valid introspection responses are cached for 60 seconds.
- Invalid introspection responses are cached for 10 seconds.
- If auth-service is unreachable, middleware returns `503` and does not fall
  back to stale data.

## `request.state.user` shape

- JWT/user identity:
  `{ "type": "user", "user_id": str, "email": str, "email_verified": bool, "email_otp_enabled": bool, "role": "admin"|"user"|"service", "scopes": list[str], "auth_time": int }`
- API key identity:
  `{ "type": "api_key", "key_id": str, "service": str, "scopes": list[str], "email": None }`

## Dependencies

```python
from fastapi import Depends, FastAPI
from sdk import require_action_token, require_fresh_auth, require_role

app = FastAPI()

@app.get("/admin-only")
async def admin_only(user=Depends(require_role("admin"))):
    return {"user_id": user["user_id"]}

@app.post("/dangerous")
async def dangerous_op(
    user=Depends(
        require_action_token(
            "erase_account",
            auth_base_url="https://auth.example.com",
            expected_audience="orders-api",
        )
    )
):
    return {"user_id": user["user_id"]}

@app.post("/sensitive")
async def sensitive_op(user=Depends(require_fresh_auth(300))):
    return {"user_id": user["user_id"]}
```

## Failure Semantics (Important)

- `401`: invalid JWT/API key or invalid claims.
- `403`: authenticated but blocked by role, action token, or stale auth.
- `503`: auth-service unavailable for required network validation.

## Audience Requirement

- Set `expected_audience` to your service identifier when using JWT middleware or action-token dependencies.
- Request that same audience from the auth service during login or client-credentials issuance so tokens are scoped to your service.
