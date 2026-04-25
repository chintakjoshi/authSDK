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
    "account_locked",
    "otp_expired",
    "invalid_otp",
    "otp_max_attempts_exceeded",
    "otp_action_mismatch",
    "action_token_invalid",
    "otp_required",
    "email_not_verified",
    "otp_issuance_blocked",
    "reauth_required",
    "invalid_scope",
    "invalid_webhook_url",
    "not_found",
    "method_not_allowed",
    "service_unavailable",
    "internal_server_error",
]


class UserIdentity(TypedDict):
    """Authenticated user identity injected for JWT-based auth."""

    type: Literal["user"]
    user_id: str
    email: str
    email_verified: bool
    mfa_enabled: bool
    role: Literal["admin", "user", "service"]
    scopes: list[str]
    auth_time: int


class ServiceIdentity(TypedDict):
    """Authenticated machine identity injected for M2M JWT auth."""

    type: Literal["service"]
    client_id: str
    role: Literal["service"]
    scopes: list[str]
    email: None


class APIKeyIdentity(TypedDict):
    """Authenticated identity injected for API key auth."""

    type: Literal["api_key"]
    key_id: str
    service: str
    scopes: list[str]
    email: None


AuthenticatedJWTIdentity = UserIdentity | ServiceIdentity
AuthenticatedIdentity = UserIdentity | ServiceIdentity | APIKeyIdentity


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
