"""Unit tests for Google OAuth core helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.core.oauth import (
    GOOGLE_DISCOVERY_URL,
    GoogleOAuthClient,
    OAuthProtocolError,
    get_google_oauth_client,
)


class _ResponseStub:
    """Minimal async HTTP response stub."""

    def __init__(self, payload: dict[str, Any], *, raise_error: bool = False) -> None:
        self._payload = payload
        self._raise_error = raise_error

    def raise_for_status(self) -> None:
        if self._raise_error:
            raise RuntimeError("upstream failure")

    def json(self) -> dict[str, Any]:
        return self._payload


class _ClientStub:
    """OAuth client stub that records calls and supports close tracking."""

    def __init__(
        self,
        *,
        authorization_url: str = "https://accounts.example/auth",
        fetch_result: dict[str, Any] | None = None,
        metadata_response: _ResponseStub | None = None,
        jwks_response: _ResponseStub | None = None,
        fail_fetch_token: bool = False,
    ) -> None:
        self.authorization_url = authorization_url
        self.fetch_result = fetch_result or {"id_token": "id-token"}
        self.metadata_response = metadata_response or _ResponseStub(
            {
                "authorization_endpoint": "https://accounts.example/auth",
                "token_endpoint": "https://accounts.example/token",
                "jwks_uri": "https://accounts.example/jwks",
                "issuer": "https://accounts.example",
            }
        )
        self.jwks_response = jwks_response or _ResponseStub({"keys": []})
        self.fail_fetch_token = fail_fetch_token
        self.closed = False
        self.get_calls: list[str] = []
        self.fetch_calls: list[dict[str, object]] = []

    def create_authorization_url(self, endpoint: str, **kwargs: object) -> tuple[str, None]:
        self.fetch_calls.append({"authorization_endpoint": endpoint, **kwargs})
        return self.authorization_url, None

    async def fetch_token(self, endpoint: str, **kwargs: object) -> dict[str, Any]:
        self.fetch_calls.append({"token_endpoint": endpoint, **kwargs})
        if self.fail_fetch_token:
            raise RuntimeError("token exchange failed")
        return self.fetch_result

    async def get(self, url: str) -> _ResponseStub:
        self.get_calls.append(url)
        if url == GOOGLE_DISCOVERY_URL:
            return self.metadata_response
        return self.jwks_response

    async def aclose(self) -> None:
        self.closed = True


class _ClaimsStub(dict[str, object]):
    """Decoded claims object exposing authlib-style validate()."""

    def __init__(self, *args: object, should_fail: bool = False, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.should_fail = should_fail

    def validate(self) -> None:
        if self.should_fail:
            from authlib.jose import JoseError

            raise JoseError("bad token")


def _client() -> GoogleOAuthClient:
    return GoogleOAuthClient(
        client_id="google-client-id",
        client_secret="google-secret",
        default_redirect_uri="https://service.local/oauth/callback",
        redirect_uri_allowlist=[
            "https://service.local/oauth/callback",
            "https://service.local/allowed",
        ],
    )


def test_resolve_redirect_uri_allows_default_and_allowlisted_values() -> None:
    """Redirect URI resolution accepts the default and explicit allowlisted values."""
    client = _client()

    assert client.resolve_redirect_uri(None) == "https://service.local/oauth/callback"
    assert client.resolve_redirect_uri("https://service.local/allowed") == (
        "https://service.local/allowed"
    )


def test_resolve_redirect_uri_rejects_unknown_value() -> None:
    """Redirect URI validation fails closed for unknown callbacks."""
    with pytest.raises(OAuthProtocolError) as exc_info:
        _client().resolve_redirect_uri("https://evil.example/callback")

    assert exc_info.value.code == "invalid_credentials"
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_create_google_authorization_url_uses_metadata_and_closes_client() -> None:
    """Authorization URL construction reads provider metadata and closes the HTTP client."""
    client = _client()
    http_client = _ClientStub()

    async def _metadata() -> dict[str, str]:
        return {"authorization_endpoint": "https://accounts.example/auth"}

    client._get_provider_metadata = _metadata  # type: ignore[assignment]
    client._build_client = lambda redirect_uri: http_client  # type: ignore[method-assign]

    url = await client.create_google_authorization_url(
        state="state-1",
        nonce="nonce-1",
        code_verifier="verifier-1",
        redirect_uri="https://service.local/oauth/callback",
    )

    assert url == "https://accounts.example/auth"
    assert http_client.closed is True


@pytest.mark.asyncio
async def test_exchange_code_for_tokens_maps_upstream_failure() -> None:
    """Token exchange failures surface the stable invalid_credentials contract."""
    client = _client()
    http_client = _ClientStub(fail_fetch_token=True)

    async def _metadata() -> dict[str, str]:
        return {"token_endpoint": "https://accounts.example/token"}

    client._get_provider_metadata = _metadata  # type: ignore[assignment]
    client._build_client = lambda redirect_uri: http_client  # type: ignore[method-assign]

    with pytest.raises(OAuthProtocolError) as exc_info:
        await client.exchange_code_for_tokens(
            code="auth-code",
            code_verifier="verifier-1",
            redirect_uri="https://service.local/oauth/callback",
        )

    assert exc_info.value.code == "invalid_credentials"
    assert exc_info.value.status_code == 401
    assert http_client.closed is True


@pytest.mark.asyncio
async def test_verify_id_token_returns_claims_and_maps_jose_errors(monkeypatch) -> None:
    """ID-token verification returns decoded claims and rejects jose failures."""
    client = _client()

    async def _metadata() -> dict[str, str]:
        return {
            "jwks_uri": "https://accounts.example/jwks",
            "issuer": "https://accounts.example",
        }

    async def _jwks(jwks_uri: str) -> dict[str, object]:
        del jwks_uri
        return {"keys": ["ignored"]}

    client._get_provider_metadata = _metadata  # type: ignore[assignment]
    client._fetch_jwks = _jwks  # type: ignore[assignment]
    monkeypatch.setattr("app.core.oauth.JsonWebKey.import_key_set", lambda jwks: "key-set")
    monkeypatch.setattr(
        "app.core.oauth.jwt.decode",
        lambda token, key_set, claims_options: _ClaimsStub(
            sub="google-user",
            email="oauth@example.com",
            nonce=claims_options["nonce"]["value"],
        ),
    )

    claims = await client.verify_id_token("id-token", "nonce-1")
    assert claims["email"] == "oauth@example.com"

    monkeypatch.setattr(
        "app.core.oauth.jwt.decode",
        lambda token, key_set, claims_options: _ClaimsStub(should_fail=True),
    )
    with pytest.raises(OAuthProtocolError) as exc_info:
        await client.verify_id_token("id-token", "nonce-1")
    assert exc_info.value.code == "invalid_credentials"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_provider_metadata_caches_and_fetch_jwks_maps_errors() -> None:
    """Discovery metadata is cached and upstream JWKS failures fail closed."""
    client = _client()
    discovery_client = _ClientStub()
    client._build_client = lambda redirect_uri: discovery_client  # type: ignore[method-assign]

    first = await client._get_provider_metadata()
    second = await client._get_provider_metadata()

    assert first == second
    assert discovery_client.get_calls == [GOOGLE_DISCOVERY_URL]

    failing_client = _ClientStub(jwks_response=_ResponseStub({}, raise_error=True))
    client._build_client = lambda redirect_uri: failing_client  # type: ignore[method-assign]
    with pytest.raises(OAuthProtocolError) as exc_info:
        await client._fetch_jwks("https://accounts.example/jwks")
    assert exc_info.value.status_code == 503


def test_get_google_oauth_client_builds_from_settings(monkeypatch) -> None:
    """Cached Google OAuth dependency is assembled from app settings."""
    fake_settings = SimpleNamespace(
        oauth=SimpleNamespace(
            google_client_id="configured-client",
            google_client_secret=SimpleNamespace(get_secret_value=lambda: "configured-secret"),
            google_redirect_uri="https://service.local/callback",
            redirect_uri_allowlist=[
                "https://service.local/callback",
                "https://service.local/second",
            ],
        )
    )
    get_google_oauth_client.cache_clear()
    monkeypatch.setattr("app.core.oauth.get_settings", lambda: fake_settings)

    client = get_google_oauth_client()

    assert client.resolve_redirect_uri(None) == "https://service.local/callback"
    assert client.resolve_redirect_uri("https://service.local/second") == (
        "https://service.local/second"
    )
    get_google_oauth_client.cache_clear()
