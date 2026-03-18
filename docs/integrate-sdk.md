# SDK Integration Quickstart

This guide is for engineers integrating `auth-service-sdk` into an existing
service.

## 1. Install

```bash
pip install auth-service-sdk
```

## 2. Confirm Auth Service Reachability

Set your auth base URL:

```bash
export AUTH_BASE_URL="https://auth.example.com"
```

Verify required endpoints:

```bash
curl "$AUTH_BASE_URL/.well-known/jwks.json"
curl -X POST "$AUTH_BASE_URL/auth/introspect" -H "content-type: application/json" -d '{"api_key":"sk_test"}'
```

## 3. Protect Routes with JWTs

```python
from fastapi import FastAPI
from sdk import JWTAuthMiddleware

app = FastAPI()

app.add_middleware(
    JWTAuthMiddleware,
    auth_base_url="https://auth.example.com",
)
```

`JWTAuthMiddleware` does:
- local RS256 verification using JWKS cache
- one forced JWKS refresh on verification failure
- online session-state check via `GET /auth/validate`

## 4. Add Authorization Checks

```python
from fastapi import Depends, FastAPI
from sdk import require_role, require_action_token, require_fresh_auth

app = FastAPI()

@app.get("/admin")
async def admin_route(user=Depends(require_role("admin"))):
    return {"ok": True}

@app.post("/dangerous")
async def dangerous_route(
    user=Depends(
        require_action_token("erase_account", auth_base_url="https://auth.example.com")
    )
):
    return {"ok": True}

@app.post("/sensitive")
async def sensitive_route(user=Depends(require_fresh_auth(300))):
    return {"ok": True}
```

## 5. Protect Service-to-Service Routes with API Keys

```python
from fastapi import FastAPI
from sdk import APIKeyAuthMiddleware

app = FastAPI()
app.add_middleware(APIKeyAuthMiddleware, auth_base_url="https://auth.example.com")
```

`APIKeyAuthMiddleware` does:
- introspection on cache miss (`POST /auth/introspect`)
- valid cache TTL 60 seconds
- invalid cache TTL 10 seconds
- fail-closed `503` when auth service is unavailable

## 6. Read Identity in Handlers

After middleware succeeds, `request.state.user` contains:
- user JWT identity:
  `{"type":"user","user_id","email","email_verified","email_otp_enabled","role","scopes","auth_time"}`
- API key identity:
  `{"type":"api_key","key_id","service","scopes","email":None}`

## 7. Validate End-to-End

1. Obtain access token from `/auth/login`.
2. Call one protected route with `Authorization: Bearer <token>`.
3. Confirm expected `401` for invalid token and `403` for role/action/fresh-auth failures.

If blocked, continue with `troubleshooting.md`.
