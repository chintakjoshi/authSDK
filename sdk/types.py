"""SDK data contract types."""

from __future__ import annotations

from typing import Literal, TypedDict

ErrorCode = Literal[
    "invalid_token",
    "token_expired",
    "invalid_api_key",
    "expired_api_key",
    "revoked_api_key",
    "invalid_credentials",
    "rate_limited",
    "saml_assertion_invalid",
    "oauth_state_mismatch",
    "session_expired",
    "already_verified",
    "invalid_verify_token",
]


class UserIdentity(TypedDict):
    """Authenticated user identity injected for JWT-based auth."""

    type: Literal["user"]
    user_id: str
    email: str
    email_verified: bool
    role: Literal["admin", "user", "service"]
    scopes: list[str]


class APIKeyIdentity(TypedDict):
    """Authenticated identity injected for API key auth."""

    type: Literal["api_key"]
    key_id: str
    service: str
    scopes: list[str]
    email: None


AuthenticatedIdentity = UserIdentity | APIKeyIdentity


class JWKS(TypedDict):
    """JWKS payload returned by the auth service."""

    keys: list[dict[str, str]]


class APIKeyIntrospectionValid(TypedDict, total=False):
    """Successful API key introspection payload."""

    valid: Literal[True]
    user_id: str | None
    scopes: list[str]
    key_id: str
    expires_at: str | None
    service: str


class APIKeyIntrospectionInvalid(TypedDict):
    """Failed API key introspection payload."""

    valid: Literal[False]
    code: Literal["invalid_api_key", "expired_api_key", "revoked_api_key"]


APIKeyIntrospectionResponse = APIKeyIntrospectionValid | APIKeyIntrospectionInvalid
