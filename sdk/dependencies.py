"""FastAPI dependencies for role-aware authorization checks."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from sdk.cache import JWKSCacheManager
from sdk.client import AuthClient
from sdk.exceptions import (
    AuthServiceResponseError,
    AuthServiceUnavailableError,
    JWTVerificationError,
)
from sdk.types import UserIdentity


def get_current_user(request: Request) -> UserIdentity:
    """Return authenticated user identity set by SDK middleware."""
    user = getattr(request.state, "user", None)
    if not isinstance(user, dict):
        raise HTTPException(status_code=401, detail="Invalid token.")
    if user.get("type") != "user":
        raise HTTPException(status_code=401, detail="Invalid token.")
    return user  # type: ignore[return-value]


def require_role(*roles: str) -> Callable[[UserIdentity], UserIdentity]:
    """Require that the authenticated user has one of the allowed roles."""

    def checker(user: Annotated[UserIdentity, Depends(get_current_user)]) -> UserIdentity:
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return checker


def require_action_token(
    action: str,
    *,
    auth_base_url: str,
    auth_client: AuthClient | None = None,
) -> Callable[[Request, UserIdentity], UserIdentity]:
    """Require a valid action token in X-Action-Token for the current user."""
    cache = JWKSCacheManager(auth_client=auth_client or AuthClient(base_url=auth_base_url))

    async def checker(
        request: Request,
        user: Annotated[UserIdentity, Depends(get_current_user)],
    ) -> UserIdentity:
        token = request.headers.get("x-action-token", "").strip()
        if not token:
            raise HTTPException(
                status_code=403,
                detail="Action token required",
                headers={"X-OTP-Required": "true", "X-OTP-Action": action},
            )
        try:
            claims = await _verify_action_token(token, cache)
        except JWTVerificationError as exc:
            raise HTTPException(status_code=403, detail=exc.detail) from exc
        except (AuthServiceUnavailableError, AuthServiceResponseError) as exc:
            raise HTTPException(status_code=503, detail="Auth service unavailable") from exc

        if claims.get("action") != action:
            raise HTTPException(status_code=403, detail="Action mismatch")
        if claims.get("sub") != user.get("user_id"):
            raise HTTPException(status_code=403, detail="Token user mismatch")
        return user

    return checker


def require_fresh_auth(max_age_seconds: int = 300) -> Callable[[UserIdentity], UserIdentity]:
    """Require a recent auth_time claim for password re-authenticated actions."""

    def checker(user: Annotated[UserIdentity, Depends(get_current_user)]) -> UserIdentity:
        auth_time = user.get("auth_time", 0)
        if not isinstance(auth_time, int) or (time.time() - auth_time) > max_age_seconds:
            raise HTTPException(
                status_code=403,
                detail="Re-authentication required",
                headers={"X-Reauth-Required": "true"},
            )
        return user

    return checker


async def _verify_action_token(token: str, cache: JWKSCacheManager) -> dict[str, object]:
    """Verify action token using cached JWKS with one forced refresh on failure."""
    jwks = await cache.get_jwks()
    try:
        return _decode_action_token(token, jwks)
    except JWTVerificationError:
        refreshed_jwks = await cache.get_jwks(force_refresh=True)
        return _decode_action_token(token, refreshed_jwks)


def _decode_action_token(token: str, jwks: dict[str, object]) -> dict[str, object]:
    """Decode and validate a short-lived action token."""
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise JWTVerificationError("Invalid action token", "action_token_invalid") from exc

    if str(header.get("alg", "")) != "RS256":
        raise JWTVerificationError("Invalid action token", "action_token_invalid")

    key = _select_key(jwks, header.get("kid"))
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            options={
                "verify_aud": False,
                "require_jti": True,
                "require_iat": True,
                "require_exp": True,
                "require_sub": True,
            },
        )
    except ExpiredSignatureError as exc:
        raise JWTVerificationError("Invalid action token", "action_token_invalid") from exc
    except JWTError as exc:
        raise JWTVerificationError("Invalid action token", "action_token_invalid") from exc

    if claims.get("type") != "action_token":
        raise JWTVerificationError("Invalid action token", "action_token_invalid")
    return claims


def _select_key(jwks: dict[str, object], kid: object) -> dict[str, str]:
    """Select JWK by kid from JWKS document."""
    keys = jwks.get("keys", [])
    if not isinstance(keys, list) or not isinstance(kid, str) or not kid:
        raise JWTVerificationError("Invalid action token", "action_token_invalid")
    for key in keys:
        if isinstance(key, dict) and key.get("kid") == kid:
            return {str(name): str(value) for name, value in key.items()}
    raise JWTVerificationError("Invalid action token", "action_token_invalid")
