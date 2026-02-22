"""FastAPI dependencies for role-aware authorization checks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request

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
