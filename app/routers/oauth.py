"""OAuth/OIDC routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_database_session
from app.schemas.token import TokenPairResponse
from app.services.audit_service import AuditService, get_audit_service
from app.services.oauth_service import OAuthService, OAuthServiceError, get_oauth_service

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


def _extract_client_ip(request: Request) -> str:
    """Extract client IP using forwarding headers when present."""
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


@router.get("/google/login")
async def google_login(
    request: Request,
    oauth_service: Annotated[OAuthService, Depends(get_oauth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    redirect_uri: Annotated[str | None, Query()] = None,
) -> Response:
    """Initiate Google OAuth flow with server-side state storage."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    try:
        authorization_url = await oauth_service.build_google_login_url(redirect_uri=redirect_uri)
    except OAuthServiceError as exc:
        audit_service.log_login_attempt(
            provider="google",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.log_login_attempt(
        provider="google",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
    )
    return RedirectResponse(url=authorization_url, status_code=302)


@router.get("/google/callback", response_model=TokenPairResponse)
async def google_callback(
    state: Annotated[str, Query(min_length=8)],
    code: Annotated[str, Query(min_length=8)],
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    oauth_service: Annotated[OAuthService, Depends(get_oauth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> TokenPairResponse | JSONResponse:
    """Complete Google OAuth callback and issue auth tokens."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    try:
        token_pair = await oauth_service.complete_google_callback(
            db_session=db_session,
            state=state,
            code=code,
        )
    except OAuthServiceError as exc:
        audit_service.log_login_attempt(
            provider="google",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.log_login_attempt(
        provider="google",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
    )
    audit_service.log_token_issuance(
        provider="google",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
    )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )
