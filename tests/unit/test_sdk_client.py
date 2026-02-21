"""Unit tests for SDK AuthClient."""

from __future__ import annotations

import httpx
import pytest

from sdk.client import AuthClient
from sdk.exceptions import AuthServiceResponseError, AuthServiceUnavailableError


@pytest.mark.asyncio
async def test_fetch_jwks_returns_normalized_payload() -> None:
    """AuthClient fetches and validates JWKS payload shape."""

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/jwks.json"
        return httpx.Response(
            status_code=200,
            json={"keys": [{"kid": "kid-1", "kty": "RSA", "n": "abc", "e": "AQAB"}]},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(base_url="https://auth.local", transport=transport) as http_client:
        client = AuthClient(base_url="https://auth.local", http_client=http_client)
        jwks = await client.fetch_jwks()

    assert jwks["keys"][0]["kid"] == "kid-1"


@pytest.mark.asyncio
async def test_introspect_api_key_returns_valid_payload() -> None:
    """AuthClient returns normalized valid introspection payload."""

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/auth/introspect"
        return httpx.Response(
            status_code=200,
            json={
                "valid": True,
                "user_id": "user-1",
                "scopes": ["svc:read"],
                "key_id": "key-1",
                "expires_at": None,
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(base_url="https://auth.local", transport=transport) as http_client:
        client = AuthClient(base_url="https://auth.local", http_client=http_client)
        payload = await client.introspect_api_key("sk_test_1")

    assert payload["valid"] is True
    assert payload["key_id"] == "key-1"
    assert payload["scopes"] == ["svc:read"]


@pytest.mark.asyncio
async def test_introspect_api_key_raises_unavailable_on_network_error() -> None:
    """Network failures map to AuthServiceUnavailableError."""

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down", request=request)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(base_url="https://auth.local", transport=transport) as http_client:
        client = AuthClient(base_url="https://auth.local", http_client=http_client)
        with pytest.raises(AuthServiceUnavailableError):
            await client.introspect_api_key("sk_test_1")


@pytest.mark.asyncio
async def test_fetch_jwks_raises_response_error_on_invalid_payload() -> None:
    """Malformed JWKS payload is rejected."""

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, json={"not_keys": []})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(base_url="https://auth.local", transport=transport) as http_client:
        client = AuthClient(base_url="https://auth.local", http_client=http_client)
        with pytest.raises(AuthServiceResponseError):
            await client.fetch_jwks()
