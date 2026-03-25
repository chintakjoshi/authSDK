# auth-service-sdk

`auth-service-sdk` is the client-side integration package for services that
trust the central auth service.

It gives downstream FastAPI and Starlette applications a thin auth layer
instead of reimplementing JWT verification, API-key introspection, or common
authorization checks.

## Package Surface

- `JWTAuthMiddleware`
- `APIKeyAuthMiddleware`
- `AuthClient`
- `get_current_user`
- `require_role(...)`
- `require_action_token(...)`
- `require_fresh_auth(...)`

## Installation

```bash
pip install auth-service-sdk
```

Local development installs are also supported:

```bash
pip install /path/to/authSDK/sdk
```

## Minimum Service Endpoints Required

The SDK expects the auth service to expose:

- `GET /.well-known/jwks.json`
- `GET /auth/validate`
- `POST /auth/introspect`

## JWT Example

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

Behavior summary:

- local RS256 verification using cached JWKS
- one forced JWKS refresh on verification failure
- online session validation for user tokens
- verified identity stored in `request.state.user`

## API Key Example

```python
from fastapi import FastAPI
from sdk import APIKeyAuthMiddleware

app = FastAPI()
app.add_middleware(
    APIKeyAuthMiddleware,
    auth_base_url="https://auth.example.com",
)
```

Behavior summary:

- extracts keys from `X-API-Key` or `Authorization: ApiKey ...`
- caches valid and invalid introspection decisions locally
- fails closed when the auth service is unavailable

## Dependency Example

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

## Failure Semantics

- `401`: invalid token or API key
- `403`: authenticated but blocked by policy
- `503`: auth service unavailable for a required validation call

## Documentation

- repo overview: `../README.md`
- SDK integration guide: `../docs/integrate-sdk.md`
- service API guide: `../docs/service-api.md`
- troubleshooting: `../docs/troubleshooting.md`
