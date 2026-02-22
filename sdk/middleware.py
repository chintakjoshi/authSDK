"""Authentication middleware classes for consuming services."""

from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Any

from cachetools import TTLCache
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from sdk.cache import JWKSCacheManager
from sdk.client import AuthClient
from sdk.exceptions import (
    AuthServiceResponseError,
    AuthServiceUnavailableError,
    JWTVerificationError,
)
from sdk.types import APIKeyIdentity, APIKeyIntrospectionResponse, UserIdentity


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build SDK auth error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


def _extract_bearer_token(request: Request) -> str | None:
    """Extract bearer token from Authorization header."""
    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if not hmac.compare_digest(scheme.lower(), "bearer"):
        return None
    stripped = token.strip()
    return stripped or None


def _extract_api_key(request: Request) -> str | None:
    """Extract API key from X-API-Key or Authorization headers."""
    direct_key = request.headers.get("x-api-key", "").strip()
    if direct_key:
        return direct_key

    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if hmac.compare_digest(scheme.lower(), "apikey"):
        stripped = value.strip()
        return stripped or None
    return None


def _normalize_scopes(value: Any) -> list[str]:
    """Normalize a generic value into string scopes list."""
    if not isinstance(value, list):
        return []
    return [str(scope) for scope in value]


def _extract_service(introspection: APIKeyIntrospectionResponse, scopes: list[str]) -> str:
    """Extract API key service identity from introspection payload or scopes."""
    if introspection.get("valid") is True:
        service = introspection.get("service")
        if isinstance(service, str) and service.strip():
            return service.strip()
    if scopes and ":" in scopes[0]:
        return scopes[0].split(":", 1)[0]
    return "unknown"


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Verify RS256 JWT locally using cached JWKS and inject request user state."""

    def __init__(
        self,
        app,
        auth_base_url: str,
        auth_client: AuthClient | None = None,
        jwks_cache: JWKSCacheManager | None = None,
        required_token_type: str = "access",
    ) -> None:
        """Initialize middleware with auth client and JWKS cache."""
        super().__init__(app)
        self._auth_client = auth_client or AuthClient(base_url=auth_base_url)
        self._jwks_cache = jwks_cache or JWKSCacheManager(
            auth_client=self._auth_client, ttl_seconds=300
        )
        self._required_token_type = required_token_type

    async def dispatch(self, request: Request, call_next) -> Response:
        """Verify JWT and inject user identity into request state."""
        token = _extract_bearer_token(request)
        if token is None:
            return _error_response(401, "Invalid token.", "invalid_token")

        try:
            claims = await self._verify_with_refresh(token)
        except JWTVerificationError as exc:
            return _error_response(401, exc.detail, exc.code)
        except AuthServiceUnavailableError:
            return _error_response(503, "Auth service unavailable.", "session_expired")
        except AuthServiceResponseError:
            return _error_response(503, "Auth service unavailable.", "session_expired")

        email = claims.get("email")
        if not isinstance(email, str) or not email.strip():
            return _error_response(401, "Invalid token.", "invalid_token")
        role = claims.get("role")
        if role not in {"admin", "user", "service"}:
            return _error_response(401, "Invalid token.", "invalid_token")
        email_verified = claims.get("email_verified")
        if not isinstance(email_verified, bool):
            return _error_response(401, "Invalid token.", "invalid_token")

        user_identity: UserIdentity = {
            "type": "user",
            "user_id": str(claims.get("sub", "")),
            "email": email,
            "email_verified": email_verified,
            "role": str(role),
            "scopes": _normalize_scopes(claims.get("scopes", [])),
        }
        request.state.user = user_identity
        return await call_next(request)

    async def _verify_with_refresh(self, token: str) -> dict[str, Any]:
        """Verify token using cached JWKS and force-refresh once on failure."""
        jwks = await self._jwks_cache.get_jwks()
        try:
            return self._decode_token(token, jwks)
        except JWTVerificationError:
            refreshed_jwks = await self._jwks_cache.get_jwks(force_refresh=True)
            return self._decode_token(token, refreshed_jwks)

    def _decode_token(self, token: str, jwks: dict[str, Any]) -> dict[str, Any]:
        """Decode token and enforce claim/algorithm constraints."""
        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise JWTVerificationError("Invalid token.", "invalid_token") from exc

        algorithm = str(header.get("alg", ""))
        if not hmac.compare_digest(algorithm, "RS256"):
            raise JWTVerificationError("Invalid token.", "invalid_token")

        kid = header.get("kid")
        key = self._select_key(jwks=jwks, kid=str(kid) if kid is not None else None)
        options = {
            "verify_aud": False,
            "require_jti": True,
            "require_iat": True,
            "require_exp": True,
            "require_sub": True,
        }
        try:
            claims = jwt.decode(token, key, algorithms=["RS256"], options=options)
        except ExpiredSignatureError as exc:
            raise JWTVerificationError("Token has expired.", "token_expired") from exc
        except JWTError as exc:
            raise JWTVerificationError("Invalid token.", "invalid_token") from exc

        token_type = str(claims.get("type", ""))
        if token_type not in {"access", "refresh"}:
            raise JWTVerificationError("Invalid token.", "invalid_token")
        if self._required_token_type and not hmac.compare_digest(
            token_type, self._required_token_type
        ):
            raise JWTVerificationError("Invalid token.", "invalid_token")
        return claims

    @staticmethod
    def _select_key(jwks: dict[str, Any], kid: str | None) -> dict[str, str]:
        """Select JWK by required kid value."""
        keys = jwks.get("keys", [])
        if not isinstance(keys, list) or not keys:
            raise JWTVerificationError("Invalid token.", "invalid_token")
        if not kid:
            raise JWTVerificationError("Invalid token.", "invalid_token")
        for key in keys:
            if isinstance(key, dict) and key.get("kid") == kid:
                return {str(name): str(value) for name, value in key.items()}
        raise JWTVerificationError("Invalid token.", "invalid_token")


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """Introspect API keys with in-process caching and fail-closed behavior."""

    def __init__(
        self,
        app,
        auth_base_url: str,
        auth_client: AuthClient | None = None,
        cache_maxsize: int = 10000,
        valid_ttl_seconds: int = 60,
        invalid_ttl_seconds: int = 10,
    ) -> None:
        """Initialize middleware with introspection client and TTL caches."""
        super().__init__(app)
        self._auth_client = auth_client or AuthClient(base_url=auth_base_url)
        self._valid_cache: TTLCache[str, APIKeyIdentity] = TTLCache(
            maxsize=cache_maxsize, ttl=valid_ttl_seconds
        )
        self._invalid_cache: TTLCache[str, str] = TTLCache(
            maxsize=cache_maxsize, ttl=invalid_ttl_seconds
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Authenticate request using API key introspection + local cache."""
        raw_key = _extract_api_key(request)
        if raw_key is None:
            return _error_response(401, "Invalid API key.", "invalid_api_key")

        key_hash = sha256(raw_key.encode("utf-8")).hexdigest()
        cached_identity = self._valid_cache.get(key_hash)
        if cached_identity is not None:
            request.state.user = cached_identity
            return await call_next(request)

        cached_error_code = self._invalid_cache.get(key_hash)
        if cached_error_code is not None:
            return _error_response(
                401, self._api_key_error_detail(cached_error_code), cached_error_code
            )

        try:
            introspection = await self._auth_client.introspect_api_key(raw_key)
        except (AuthServiceUnavailableError, AuthServiceResponseError):
            return _error_response(503, "Auth service unavailable.", "session_expired")
        finally:
            raw_key = ""
            del raw_key

        if introspection.get("valid") is not True:
            code = str(introspection.get("code", "invalid_api_key"))
            if code not in {"invalid_api_key", "expired_api_key", "revoked_api_key"}:
                code = "invalid_api_key"
            self._invalid_cache[key_hash] = code
            return _error_response(401, self._api_key_error_detail(code), code)

        key_id = str(introspection.get("key_id", "")).strip()
        if not key_id:
            self._invalid_cache[key_hash] = "invalid_api_key"
            return _error_response(401, "Invalid API key.", "invalid_api_key")

        scopes = _normalize_scopes(introspection.get("scopes", []))
        identity: APIKeyIdentity = {
            "type": "api_key",
            "key_id": key_id,
            "service": _extract_service(introspection, scopes),
            "scopes": scopes,
            "email": None,
        }
        self._valid_cache[key_hash] = identity
        request.state.user = identity
        return await call_next(request)

    @staticmethod
    def _api_key_error_detail(code: str) -> str:
        """Map API key error code to stable human-readable detail."""
        if code == "expired_api_key":
            return "API key expired."
        if code == "revoked_api_key":
            return "API key revoked."
        return "Invalid API key."
