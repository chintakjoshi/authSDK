"""Integration tests for SDK require_role dependency with JWT middleware."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt

from sdk import JWTAuthMiddleware, require_role
from sdk.client import AuthClient


def _base64url_uint(value: int) -> str:
    """Encode integer in URL-safe base64 without padding."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate_signing_material(kid: str) -> tuple[str, dict[str, str]]:
    """Generate RSA private PEM and matching JWKS key entry."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": kid,
        "n": _base64url_uint(public_numbers.n),
        "e": _base64url_uint(public_numbers.e),
    }
    return private_pem, jwk


def _build_token(private_pem: str, kid: str, role: str) -> str:
    """Build RS256 JWT with role claim."""
    now = datetime.now(UTC)
    payload = {
        "jti": str(uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": "user-1",
        "type": "access",
        "email": "user@example.com",
        "email_verified": True,
        "role": role,
        "scopes": ["svc:read"],
    }
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.mark.asyncio
async def test_require_role_returns_403_for_insufficient_role() -> None:
    """Routes guarded by require_role reject user role for admin-only access."""
    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, "kid-1", role="user")

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        JWTAuthMiddleware,
        auth_base_url="https://auth.local",
        auth_client=auth_client,
    )
    admin_dependency = Depends(require_role("admin"))

    @app.get("/admin")
    async def admin_only(user=admin_dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/admin", headers={"authorization": f"Bearer {token}"})

    await auth_http_client.aclose()
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient role"


@pytest.mark.asyncio
async def test_require_role_allows_admin_role() -> None:
    """Routes guarded by require_role allow admin access."""
    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, "kid-1", role="admin")

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        JWTAuthMiddleware,
        auth_base_url="https://auth.local",
        auth_client=auth_client,
    )
    admin_dependency = Depends(require_role("admin"))

    @app.get("/admin")
    async def admin_only(user=admin_dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/admin", headers={"authorization": f"Bearer {token}"})

    await auth_http_client.aclose()
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"
