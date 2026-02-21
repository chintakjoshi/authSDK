# auth-service-sdk

`auth-service-sdk` provides middleware for verifying JWTs locally and API keys via auth-service introspection.

## Installation

```bash
pip install auth-service-sdk
```

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
)
```

Behavior:
- JWT verification is local using cached JWKS.
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
- If auth-service is unreachable, middleware returns `503` and does not fall back to stale data.

## `request.state.user` shape

- JWT/user identity: `{ "type": "user", "user_id": str, "email": str, "scopes": list[str] }`
- API key identity: `{ "type": "api_key", "key_id": str, "service": str, "scopes": list[str], "email": None }`
