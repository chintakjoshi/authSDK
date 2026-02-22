"""Unit tests for SDK middleware claim validation and refresh behavior."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from jose import jwt

from sdk.client import AuthClient
from sdk.middleware import JWTAuthMiddleware


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


def _build_token(
    private_pem: str,
    kid: str,
    email: str = "user@example.com",
    include_jti: bool = True,
    role: str = "user",
) -> str:
    """Build RS256 JWT for middleware tests."""
    now = datetime.now(UTC)
    payload = {
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": "user-1",
        "type": "access",
        "email": email,
        "role": role,
        "scopes": ["svc:read"],
    }
    if include_jti:
        payload["jti"] = str(uuid4())
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})


@pytest.mark.asyncio
async def test_jwt_middleware_verifies_and_caches_jwks() -> None:
    """JWT middleware fetches JWKS once and verifies tokens locally."""
    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, kid="kid-1")
    jwks_calls = 0

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        nonlocal jwks_calls
        if request.url.path == "/.well-known/jwks.json":
            jwks_calls += 1
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    app = FastAPI()
    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)
    app.add_middleware(
        JWTAuthMiddleware, auth_base_url="https://auth.local", auth_client=auth_client
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"user": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.get("/protected", headers={"authorization": f"Bearer {token}"})
        second = await client.get("/protected", headers={"authorization": f"Bearer {token}"})

    await auth_http_client.aclose()
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["user"]["type"] == "user"
    assert first.json()["user"]["role"] == "user"
    assert jwks_calls == 1


@pytest.mark.asyncio
async def test_jwt_middleware_refreshes_once_on_verification_failure() -> None:
    """JWT middleware forces one JWKS refresh when first verification fails."""
    stale_private, stale_jwk = _generate_signing_material("kid-1")
    del stale_private
    active_private, active_jwk = _generate_signing_material("kid-1")
    token = _build_token(active_private, kid="kid-1")
    jwks_calls = 0

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        nonlocal jwks_calls
        if request.url.path == "/.well-known/jwks.json":
            jwks_calls += 1
            if jwks_calls == 1:
                return httpx.Response(status_code=200, json={"keys": [stale_jwk]})
            return httpx.Response(status_code=200, json={"keys": [active_jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    app = FastAPI()
    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)
    app.add_middleware(
        JWTAuthMiddleware, auth_base_url="https://auth.local", auth_client=auth_client
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"user": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/protected", headers={"authorization": f"Bearer {token}"})

    await auth_http_client.aclose()
    assert response.status_code == 200
    assert jwks_calls == 2


@pytest.mark.asyncio
async def test_jwt_middleware_rejects_missing_required_claim() -> None:
    """JWT middleware rejects tokens missing required claims."""
    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, kid="kid-1", include_jti=False)

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    app = FastAPI()
    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)
    app.add_middleware(
        JWTAuthMiddleware, auth_base_url="https://auth.local", auth_client=auth_client
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"user": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/protected", headers={"authorization": f"Bearer {token}"})

    await auth_http_client.aclose()
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"


@pytest.mark.asyncio
async def test_jwt_middleware_rejects_missing_role_claim() -> None:
    """JWT middleware rejects tokens without role claim."""
    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, kid="kid-1")
    payload = jwt.get_unverified_claims(token)
    payload.pop("role", None)
    token_without_role = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": "kid-1"},
    )

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    app = FastAPI()
    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)
    app.add_middleware(
        JWTAuthMiddleware, auth_base_url="https://auth.local", auth_client=auth_client
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {"user": request.state.user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            "/protected", headers={"authorization": f"Bearer {token_without_role}"}
        )

    await auth_http_client.aclose()
    assert response.status_code == 401
    assert response.json()["code"] == "invalid_token"
