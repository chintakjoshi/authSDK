"""Unit tests for SDK FastAPI role dependencies."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Request
from httpx import ASGITransport, AsyncClient
from jose import jwt

from sdk.client import AuthClient
from sdk.dependencies import (
    get_current_user,
    require_action_token,
    require_fresh_auth,
    require_role,
)


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate_signing_material(kid: str) -> tuple[str, dict[str, str]]:
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


def _build_action_token(private_pem: str, kid: str, sub: str, action: str) -> str:
    now = datetime.now(UTC)
    payload = {
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": sub,
        "type": "action_token",
        "action": action,
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})


def _build_app(user_payload: dict[str, object]) -> FastAPI:
    """Create app with get_current_user overridden by fixed payload."""
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: user_payload
    admin_dependency = Depends(require_role("admin"))

    @app.get("/admin")
    async def admin_only(user=admin_dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    return app


async def test_require_role_allows_matching_role() -> None:
    """Role dependency allows requests when role matches allowed set."""
    app = _build_app(
        {
            "type": "user",
            "user_id": "u-1",
            "email": "a@example.com",
            "email_verified": True,
            "email_otp_enabled": False,
            "role": "admin",
            "scopes": [],
            "auth_time": int(datetime.now(UTC).timestamp()),
        }
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/admin")

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"


async def test_require_role_rejects_non_matching_role() -> None:
    """Role dependency rejects requests when role is outside allowed set."""
    app = _build_app(
        {
            "type": "user",
            "user_id": "u-1",
            "email": "a@example.com",
            "email_verified": True,
            "email_otp_enabled": False,
            "role": "user",
            "scopes": [],
            "auth_time": int(datetime.now(UTC).timestamp()),
        }
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/admin")

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient role"


async def test_require_role_allows_service_identity() -> None:
    """Role dependency accepts M2M service identities for service-only routes."""
    app = _build_app(
        {
            "type": "service",
            "client_id": "client-1",
            "email": None,
            "role": "service",
            "scopes": ["billing:read"],
        }
    )
    service_dependency = Depends(require_role("service"))

    @app.get("/service")
    async def service_only(user=service_dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/service")

    assert response.status_code == 200
    assert response.json()["user"]["client_id"] == "client-1"


async def test_require_action_token_allows_matching_action_and_user() -> None:
    """Action-token dependency allows requests for the bound action and user."""
    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_action_token(private_pem, kid="kid-1", sub="u-1", action="erase_account")

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        return httpx.Response(status_code=404, json={"detail": "not found"})

    auth_http_client = httpx.AsyncClient(
        base_url="https://auth.local",
        transport=httpx.MockTransport(auth_handler),
    )
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: {
        "type": "user",
        "user_id": "u-1",
        "email": "a@example.com",
        "email_verified": True,
        "email_otp_enabled": False,
        "role": "user",
        "scopes": [],
        "auth_time": int(datetime.now(UTC).timestamp()),
    }
    dependency = Depends(
        require_action_token(
            "erase_account",
            auth_base_url="https://auth.local",
            auth_client=auth_client,
        )
    )

    @app.post("/dangerous")
    async def dangerous(_: Request, user=dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/dangerous", headers={"x-action-token": token})

    await auth_http_client.aclose()
    assert response.status_code == 200
    assert response.json()["user"]["user_id"] == "u-1"


async def test_require_action_token_sets_headers_when_missing() -> None:
    """Missing action tokens return the OTP-required guidance headers."""
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: {
        "type": "user",
        "user_id": "u-1",
        "email": "a@example.com",
        "email_verified": True,
        "email_otp_enabled": False,
        "role": "user",
        "scopes": [],
        "auth_time": int(datetime.now(UTC).timestamp()),
    }
    dependency = Depends(require_action_token("erase_account", auth_base_url="https://auth.local"))

    @app.post("/dangerous")
    async def dangerous(user=dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/dangerous")

    assert response.status_code == 403
    assert response.json()["detail"] == "Action token required"
    assert response.headers["x-otp-required"] == "true"
    assert response.headers["x-otp-action"] == "erase_account"


async def test_require_fresh_auth_rejects_stale_auth_time() -> None:
    """Fresh-auth dependency rejects stale sessions with a reauth header."""
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: {
        "type": "user",
        "user_id": "u-1",
        "email": "a@example.com",
        "email_verified": True,
        "email_otp_enabled": False,
        "role": "user",
        "scopes": [],
        "auth_time": int((datetime.now(UTC) - timedelta(minutes=10)).timestamp()),
    }
    dependency = Depends(require_fresh_auth(300))

    @app.post("/dangerous")
    async def dangerous(user=dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/dangerous")

    assert response.status_code == 403
    assert response.json()["detail"] == "Re-authentication required"
    assert response.headers["x-reauth-required"] == "true"
