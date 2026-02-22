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


@router.get("/google/login")
async def google_login(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    oauth_service: Annotated[OAuthService, Depends(get_oauth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    redirect_uri: Annotated[str | None, Query()] = None,
) -> Response:
    """Initiate Google OAuth flow with server-side state storage."""
    try:
        authorization_url = await oauth_service.build_google_login_url(redirect_uri=redirect_uri)
    except OAuthServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "google", "phase": "start"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.login.success",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "google", "phase": "start"},
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
    try:
        token_pair = await oauth_service.complete_google_callback(
            db_session=db_session,
            state=state,
            code=code,
        )
    except OAuthServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "google", "phase": "callback"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.login.success",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "google", "phase": "callback"},
    )
    await audit_service.record(
        db=db_session,
        event_type="session.created",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "google"},
    )
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "google", "token_kind": "access_refresh_pair"},
    )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )
