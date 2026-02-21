"""Async HTTP client for auth-service public endpoints."""

from __future__ import annotations

from typing import Any

import httpx

from sdk.exceptions import AuthServiceResponseError, AuthServiceUnavailableError
from sdk.types import JWKS, APIKeyIntrospectionResponse

DEFAULT_TIMEOUT = httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=5.0)


class AuthClient:
    """Async client for fetching JWKS and introspecting API keys."""

    def __init__(
        self,
        base_url: str,
        timeout: httpx.Timeout | float | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Create client with sane defaults and optional injected transport."""
        self._owns_client = http_client is None
        self._client = http_client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout or DEFAULT_TIMEOUT,
        )

    async def fetch_jwks(self) -> JWKS:
        """Fetch public JWKS from auth service."""
        response = await self._request("GET", "/.well-known/jwks.json")
        payload = self._json_object(response)
        keys = payload.get("keys")
        if not isinstance(keys, list):
            raise AuthServiceResponseError("Invalid JWKS response payload.", response.status_code)

        normalized_keys: list[dict[str, str]] = []
        for item in keys:
            if not isinstance(item, dict):
                raise AuthServiceResponseError("Invalid JWKS key entry.", response.status_code)
            normalized_keys.append({str(key): str(value) for key, value in item.items()})
        return {"keys": normalized_keys}

    async def introspect_api_key(self, raw_api_key: str) -> APIKeyIntrospectionResponse:
        """Call auth-service API key introspection endpoint."""
        response = await self._request("POST", "/auth/introspect", json={"api_key": raw_api_key})
        payload = self._json_object(response)
        is_valid = payload.get("valid")
        if not isinstance(is_valid, bool):
            raise AuthServiceResponseError(
                "Invalid introspection response payload.", response.status_code
            )

        if not is_valid:
            code = str(payload.get("code", "invalid_api_key"))
            if code not in {"invalid_api_key", "expired_api_key", "revoked_api_key"}:
                code = "invalid_api_key"
            return {"valid": False, "code": code}

        scopes_raw = payload.get("scopes", [])
        scopes = [str(scope) for scope in scopes_raw] if isinstance(scopes_raw, list) else []
        response_payload: APIKeyIntrospectionResponse = {
            "valid": True,
            "user_id": str(payload["user_id"]) if payload.get("user_id") is not None else None,
            "scopes": scopes,
            "key_id": str(payload.get("key_id", "")),
            "expires_at": (
                str(payload["expires_at"]) if payload.get("expires_at") is not None else None
            ),
        }
        if "service" in payload and payload["service"] is not None:
            response_payload["service"] = str(payload["service"])
        return response_payload

    async def aclose(self) -> None:
        """Close underlying HTTP client if owned by this instance."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AuthClient:
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit async context manager and close managed resources."""
        del exc_type, exc, tb
        await self.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Execute request and normalize upstream failures."""
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise AuthServiceUnavailableError("Auth service unavailable.") from exc

        if response.status_code >= 500:
            raise AuthServiceUnavailableError("Auth service unavailable.")
        if response.status_code >= 400:
            raise AuthServiceResponseError(
                f"Auth service request failed with status {response.status_code}.",
                response.status_code,
            )
        return response

    @staticmethod
    def _json_object(response: httpx.Response) -> dict[str, Any]:
        """Return response JSON as object."""
        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthServiceResponseError(
                "Auth service returned invalid JSON.", response.status_code
            ) from exc
        if not isinstance(payload, dict):
            raise AuthServiceResponseError(
                "Auth service returned invalid JSON object.", response.status_code
            )
        return payload
