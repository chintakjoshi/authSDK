"""SDK tests for browser-session middleware support."""

from __future__ import annotations

import base64
import inspect
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

from sdk import middleware as sdk_middleware
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
    *,
    subject: str = "user-1",
    audience: str | list[str] = ("auth-service", "orders-api"),
) -> str:
    """Build a valid user access token for middleware tests."""
    now = datetime.now(UTC)
    payload = {
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "sub": subject,
        "type": "access",
        "role": "user",
        "aud": list(audience) if not isinstance(audience, str) else audience,
        "email": f"{subject}@example.com",
        "email_verified": True,
        "mfa_enabled": False,
        "scopes": ["svc:read"],
        "auth_time": int(now.timestamp()),
        "jti": str(uuid4()),
    }
    return jwt.encode({"alg": "RS256", "kid": kid}, payload, private_pem).decode("utf-8")


def _request(
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
) -> StarletteRequest:
    """Build a lightweight request for direct middleware invocation."""
    header_list = [
        (key.lower().encode("utf-8"), value.encode("utf-8"))
        for key, value in (headers or {}).items()
    ]
    sent = False

    async def _receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": b"", "more_body": False}

    return StarletteRequest(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": header_list,
            "client": ("127.0.0.1", 12345),
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
        },
        receive=_receive,
    )


async def _allow_request(_: Any) -> Response:
    """Return a success response from middleware call_next."""
    return Response(status_code=204)


@pytest.mark.asyncio
async def test_jwt_middleware_accepts_cookie_tokens_when_enabled() -> None:
    """JWT middleware should authenticate from a configured access cookie."""
    signature = inspect.signature(JWTAuthMiddleware.__init__)
    assert "token_sources" in signature.parameters
    assert "access_cookie_name" in signature.parameters

    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, kid="kid-1")

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        if request.url.path == "/auth/validate":
            return httpx.Response(status_code=204)
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        JWTAuthMiddleware,
        auth_base_url="https://auth.local",
        expected_audience="orders-api",
        auth_client=auth_client,
        token_sources=["cookie", "authorization"],
        access_cookie_name="__Host-auth_access",
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {
            "user": request.state.user,
            "auth_transport": getattr(request.state, "auth_transport", None),
        }

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        client.cookies.set("__Host-auth_access", token)
        response = await client.get("/protected")

    await auth_http_client.aclose()
    assert response.status_code == 200
    assert response.json()["auth_transport"] == "cookie"
    assert response.json()["user"]["user_id"] == "user-1"


@pytest.mark.asyncio
async def test_jwt_middleware_prefers_authorization_header_over_cookie() -> None:
    """When both transports are present, bearer auth should win deterministically."""
    signature = inspect.signature(JWTAuthMiddleware.__init__)
    assert "token_sources" in signature.parameters
    assert "access_cookie_name" in signature.parameters

    private_pem, jwk = _generate_signing_material("kid-1")
    header_token = _build_token(private_pem, kid="kid-1", subject="header-user")
    cookie_token = _build_token(private_pem, kid="kid-1", subject="cookie-user")

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        if request.url.path == "/auth/validate":
            return httpx.Response(status_code=204)
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        JWTAuthMiddleware,
        auth_base_url="https://auth.local",
        expected_audience="orders-api",
        auth_client=auth_client,
        token_sources=["authorization", "cookie"],
        access_cookie_name="__Host-auth_access",
    )

    @app.get("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {
            "user": request.state.user,
            "auth_transport": getattr(request.state, "auth_transport", None),
        }

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        client.cookies.set("__Host-auth_access", cookie_token)
        response = await client.get(
            "/protected",
            headers={"authorization": f"Bearer {header_token}"},
        )

    await auth_http_client.aclose()
    assert response.status_code == 200
    assert response.json()["auth_transport"] == "authorization"
    assert response.json()["user"]["user_id"] == "header-user"


@pytest.mark.asyncio
async def test_cookie_csrf_middleware_rejects_unsafe_cookie_authenticated_requests_without_header() -> (
    None
):
    """Unsafe cookie-authenticated requests should fail closed without CSRF header."""
    cookie_csrf_middleware = getattr(sdk_middleware, "CookieCSRFMiddleware", None)
    assert cookie_csrf_middleware is not None
    signature = inspect.signature(cookie_csrf_middleware.__init__)
    assert "csrf_cookie_name" in signature.parameters
    assert "csrf_header_name" in signature.parameters
    assert "access_cookie_name" in signature.parameters

    middleware = cookie_csrf_middleware(
        app=FastAPI(),
        csrf_cookie_name="csrf_token",
        csrf_header_name="x-csrf-token",
        access_cookie_name="access_token",
    )
    request = _request(
        method="POST",
        path="/dangerous",
        headers={"cookie": "access_token=access-token; csrf_token=cookie-token"},
    )
    request.state.auth_transport = "cookie"

    response = await middleware.dispatch(request, _allow_request)

    assert response.status_code == 403
    assert response.body == b'{"detail":"Invalid CSRF token.","code":"invalid_csrf_token"}'


@pytest.mark.asyncio
async def test_cookie_csrf_middleware_allows_matching_header_for_cookie_authenticated_requests() -> (
    None
):
    """Matching CSRF cookie and header should allow unsafe cookie-authenticated requests."""
    cookie_csrf_middleware = getattr(sdk_middleware, "CookieCSRFMiddleware", None)
    assert cookie_csrf_middleware is not None

    middleware = cookie_csrf_middleware(
        app=FastAPI(),
        csrf_cookie_name="csrf_token",
        csrf_header_name="x-csrf-token",
        access_cookie_name="access_token",
    )
    request = _request(
        method="POST",
        path="/dangerous",
        headers={
            "cookie": "access_token=access-token; csrf_token=cookie-token",
            "x-csrf-token": "cookie-token",
        },
    )
    request.state.auth_transport = "cookie"

    response = await middleware.dispatch(request, _allow_request)

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_cookie_csrf_middleware_rejects_when_access_cookie_implies_cookie_auth_without_state() -> (
    None
):
    """CSRF should still fail closed when middleware order leaves auth_transport unset."""
    cookie_csrf_middleware = getattr(sdk_middleware, "CookieCSRFMiddleware", None)
    assert cookie_csrf_middleware is not None

    middleware = cookie_csrf_middleware(
        app=FastAPI(),
        csrf_cookie_name="csrf_token",
        csrf_header_name="x-csrf-token",
        access_cookie_name="access_token",
    )
    request = _request(
        method="POST",
        path="/dangerous",
        headers={"cookie": "access_token=access-token; csrf_token=cookie-token"},
    )

    response = await middleware.dispatch(request, _allow_request)

    assert response.status_code == 403
    assert response.body == b'{"detail":"Invalid CSRF token.","code":"invalid_csrf_token"}'


@pytest.mark.asyncio
async def test_cookie_csrf_middleware_skips_enforcement_when_bearer_auth_wins_over_cookie() -> None:
    """Bearer auth should still bypass cookie CSRF checks when both transports are present."""
    cookie_csrf_middleware = getattr(sdk_middleware, "CookieCSRFMiddleware", None)
    assert cookie_csrf_middleware is not None

    middleware = cookie_csrf_middleware(
        app=FastAPI(),
        csrf_cookie_name="csrf_token",
        csrf_header_name="x-csrf-token",
        access_cookie_name="access_token",
    )
    request = _request(
        method="POST",
        path="/dangerous",
        headers={
            "authorization": "Bearer header-token",
            "cookie": "access_token=access-token; csrf_token=cookie-token",
        },
    )

    response = await middleware.dispatch(request, _allow_request)

    assert response.status_code == 204


@pytest.mark.asyncio
async def test_cookie_csrf_and_jwt_middlewares_fail_closed_even_with_wrong_registration_order() -> (
    None
):
    """Missing CSRF must still be rejected when consumers register middleware in the wrong order."""
    cookie_csrf_middleware = getattr(sdk_middleware, "CookieCSRFMiddleware", None)
    assert cookie_csrf_middleware is not None

    private_pem, jwk = _generate_signing_material("kid-1")
    token = _build_token(private_pem, kid="kid-1")

    async def auth_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/jwks.json":
            return httpx.Response(status_code=200, json={"keys": [jwk]})
        if request.url.path == "/auth/validate":
            return httpx.Response(status_code=204)
        return httpx.Response(status_code=404, json={"detail": "not found"})

    transport = httpx.MockTransport(auth_handler)
    auth_http_client = httpx.AsyncClient(base_url="https://auth.local", transport=transport)
    auth_client = AuthClient(base_url="https://auth.local", http_client=auth_http_client)

    app = FastAPI()
    app.add_middleware(
        JWTAuthMiddleware,
        auth_base_url="https://auth.local",
        expected_audience="orders-api",
        auth_client=auth_client,
        token_sources=["authorization", "cookie"],
        access_cookie_name="__Host-auth_access",
    )
    app.add_middleware(
        cookie_csrf_middleware,
        csrf_cookie_name="__Host-auth_csrf",
        csrf_header_name="X-CSRF-Token",
        access_cookie_name="__Host-auth_access",
    )

    @app.post("/protected")
    async def protected(request: Request) -> dict[str, object]:
        return {
            "user": request.state.user,
            "auth_transport": getattr(request.state, "auth_transport", None),
        }

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        client.cookies.set("__Host-auth_access", token)
        client.cookies.set("__Host-auth_csrf", "csrf-cookie-token")
        response = await client.post("/protected")

    await auth_http_client.aclose()
    assert response.status_code == 403
    assert response.json()["code"] == "invalid_csrf_token"
