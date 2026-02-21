"""Google OAuth/OIDC protocol operations via authlib."""

from __future__ import annotations

import hmac
import secrets
from functools import lru_cache
from typing import Any

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JoseError, JsonWebKey, jwt

from app.config import get_settings

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"


class OAuthProtocolError(Exception):
    """Raised when OAuth protocol operations fail."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class GoogleOAuthClient:
    """Authlib-backed Google OAuth/OIDC client."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        default_redirect_uri: str,
        redirect_uri_allowlist: list[str],
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._default_redirect_uri = default_redirect_uri
        self._redirect_uri_allowlist = redirect_uri_allowlist
        self._metadata: dict[str, Any] | None = None

    def resolve_redirect_uri(self, redirect_uri: str | None) -> str:
        """Validate and resolve redirect URI against allowlist."""
        candidate = redirect_uri or self._default_redirect_uri
        for allowed in self._redirect_uri_allowlist:
            if hmac.compare_digest(candidate, allowed):
                return candidate
        raise OAuthProtocolError("Invalid redirect URI.", "invalid_credentials", 400)

    def generate_state(self) -> str:
        """Generate OAuth state token."""
        return secrets.token_urlsafe(32)

    def generate_nonce(self) -> str:
        """Generate OIDC nonce."""
        return secrets.token_urlsafe(32)

    def generate_code_verifier(self) -> str:
        """Generate PKCE code verifier."""
        return secrets.token_urlsafe(64)

    async def create_google_authorization_url(
        self,
        state: str,
        nonce: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> str:
        """Build Google authorization URL with PKCE parameters."""
        metadata = await self._get_provider_metadata()
        client = self._build_client(redirect_uri=redirect_uri)
        try:
            authorization_url, _ = client.create_authorization_url(
                metadata["authorization_endpoint"],
                state=state,
                nonce=nonce,
                code_verifier=code_verifier,
                prompt="select_account",
            )
        finally:
            await client.aclose()
        return authorization_url

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for token payload."""
        metadata = await self._get_provider_metadata()
        client = self._build_client(redirect_uri=redirect_uri)
        try:
            return await client.fetch_token(
                metadata["token_endpoint"],
                grant_type="authorization_code",
                code=code,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri,
            )
        except Exception as exc:
            raise OAuthProtocolError(
                "OAuth token exchange failed.", "invalid_credentials", 401
            ) from exc
        finally:
            await client.aclose()

    async def verify_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        """Verify Google ID token signature and critical claims."""
        metadata = await self._get_provider_metadata()
        jwks = await self._fetch_jwks(metadata["jwks_uri"])
        key_set = JsonWebKey.import_key_set(jwks)
        claims_options = {
            "iss": {
                "essential": True,
                "values": [metadata["issuer"], "https://accounts.google.com"],
            },
            "aud": {"essential": True, "value": self._client_id},
            "nonce": {"essential": True, "value": nonce},
            "exp": {"essential": True},
            "sub": {"essential": True},
            "email": {"essential": True},
        }
        try:
            claims = jwt.decode(id_token, key_set, claims_options=claims_options)
            claims.validate()
        except JoseError as exc:
            raise OAuthProtocolError("Invalid ID token.", "invalid_credentials", 401) from exc
        return dict(claims)

    async def _get_provider_metadata(self) -> dict[str, Any]:
        """Load and cache provider OpenID metadata."""
        if self._metadata is not None:
            return self._metadata
        client = self._build_client(redirect_uri=self._default_redirect_uri)
        try:
            response = await client.get(GOOGLE_DISCOVERY_URL)
            response.raise_for_status()
            self._metadata = dict(response.json())
            return self._metadata
        except Exception as exc:
            raise OAuthProtocolError(
                "OAuth provider unavailable.", "invalid_credentials", 503
            ) from exc
        finally:
            await client.aclose()

    async def _fetch_jwks(self, jwks_uri: str) -> dict[str, Any]:
        """Fetch JWKS used for ID token verification."""
        client = self._build_client(redirect_uri=self._default_redirect_uri)
        try:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            return dict(response.json())
        except Exception as exc:
            raise OAuthProtocolError(
                "OAuth provider unavailable.", "invalid_credentials", 503
            ) from exc
        finally:
            await client.aclose()

    def _build_client(self, redirect_uri: str) -> AsyncOAuth2Client:
        """Build authlib OAuth2 client for Google endpoints."""
        return AsyncOAuth2Client(
            client_id=self._client_id,
            client_secret=self._client_secret,
            scope="openid email profile",
            redirect_uri=redirect_uri,
            token_endpoint_auth_method="client_secret_post",
            timeout=10.0,
        )


@lru_cache
def get_google_oauth_client() -> GoogleOAuthClient:
    """Build and cache Google OAuth client from settings."""
    settings = get_settings()
    return GoogleOAuthClient(
        client_id=settings.oauth.google_client_id,
        client_secret=settings.oauth.google_client_secret.get_secret_value(),
        default_redirect_uri=str(settings.oauth.google_redirect_uri),
        redirect_uri_allowlist=[str(uri) for uri in settings.oauth.redirect_uri_allowlist],
    )
