"""Shared admin-access helpers for route modules."""

from __future__ import annotations

import hmac
import json
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.browser_sessions import (
    extract_access_token,
    require_csrf_for_cookie_authenticated_request,
)
from app.dependencies import get_database_session
from app.services.admin_service import AdminService, AdminServiceError, get_admin_service


def extract_bearer_token(request: Request) -> str | None:
    """Extract bearer token from Authorization header."""
    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if not hmac.compare_digest(scheme.lower(), "bearer"):
        return None
    stripped = token.strip()
    return stripped or None


def extract_admin_api_key(request: Request) -> str | None:
    """Extract local-dev admin bootstrap key from X-Admin-API-Key."""
    token = request.headers.get("x-admin-api-key", "").strip()
    return token or None


async def require_admin_claims(
    request: Request,
    *,
    db_session: AsyncSession,
    admin_service: AdminService,
) -> dict[str, object]:
    """Validate caller as an admin via bootstrap key or bearer token."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        try:
            payload = json.loads(csrf_error.body.decode("utf-8"))
        except Exception:
            payload = {}
        raise AdminServiceError(
            detail=str(payload.get("detail", "Invalid CSRF token.")),
            code=str(payload.get("code", "invalid_csrf_token")),
            status_code=csrf_error.status_code,
            headers=dict(csrf_error.headers),
        )

    settings = get_settings()
    configured_admin_api_key = settings.admin_api_key
    supplied_admin_api_key = extract_admin_api_key(request)
    if (
        settings.app.environment == "development"
        and configured_admin_api_key is not None
        and supplied_admin_api_key is not None
        and hmac.compare_digest(
            supplied_admin_api_key,
            configured_admin_api_key.get_secret_value(),
        )
    ):
        claims = {"sub": "local_admin_bootstrap", "role": "admin", "type": "bootstrap_admin"}
        request.state.user = {
            "user_id": None,
            "email": None,
            "role": "admin",
        }
        return claims

    claims = await admin_service.validate_admin_access_token(
        db_session=db_session,
        token=extract_access_token(request)[0],
    )
    request.state.user = {
        "user_id": str(claims.get("sub", "")) or None,
        "email": str(claims.get("email", "")) or None,
        "role": str(claims.get("role", "")) or None,
    }
    return claims


async def require_admin_access(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
) -> None:
    """FastAPI dependency that rejects non-admin requests."""
    await require_admin_claims(
        request,
        db_session=db_session,
        admin_service=admin_service,
    )
