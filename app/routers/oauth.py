"""OAuth/OIDC routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.browser_sessions import (
    build_cookie_session_redirect_response,
    get_browser_session_settings,
)
from app.dependencies import get_database_session
from app.schemas.token import TokenPairResponse
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import extract_client_ip, normalize_user_agent
from app.services.oauth_service import OAuthService, OAuthServiceError, get_oauth_service
from app.services.webhook_service import WebhookService, get_webhook_service

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


def _normalized_optional_attr(value: object) -> str | None:
    """Normalize optional redirect-like attributes without stringifying None."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


@router.get("/google/login")
async def google_login(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    oauth_service: Annotated[OAuthService, Depends(get_oauth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    redirect_uri: Annotated[str | None, Query()] = None,
    audience: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
) -> Response:
    """Initiate Google OAuth flow with server-side state storage."""
    try:
        authorization_url = await oauth_service.build_google_login_url(
            redirect_uri=redirect_uri,
            audience=audience,
        )
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
    return RedirectResponse(url=authorization_url, status_code=302)


@router.get("/google/callback", response_model=TokenPairResponse)
async def google_callback(
    state: Annotated[str, Query(min_length=8)],
    code: Annotated[str, Query(min_length=8)],
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    oauth_service: Annotated[OAuthService, Depends(get_oauth_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> TokenPairResponse | JSONResponse:
    """Complete Google OAuth callback and issue auth tokens."""
    client_ip = extract_client_ip(request)
    user_agent = normalize_user_agent(request.headers.get("user-agent"))
    try:
        completion = await oauth_service.complete_google_callback(
            db_session=db_session,
            state=state,
            code=code,
            client_ip=client_ip,
            user_agent=user_agent,
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
        actor_id=completion.user_id,
        metadata={"provider": "google", "phase": "callback"},
    )
    await audit_service.record(
        db=db_session,
        event_type="session.created",
        actor_type="user",
        success=True,
        request=request,
        actor_id=completion.user_id,
        target_id=str(completion.session_id),
        target_type="session",
        metadata={"provider": "google"},
    )
    await webhook_service.emit_event(
        event_type="session.created",
        data={
            "session_id": str(completion.session_id),
            "user_id": completion.user_id,
            "provider": "google",
        },
    )
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        actor_id=completion.user_id,
        metadata={"provider": "google", "token_kind": "access_refresh_pair"},
    )
    redirect_uri = _normalized_optional_attr(getattr(completion, "redirect_uri", None))
    if redirect_uri is not None and get_browser_session_settings().enabled:
        return build_cookie_session_redirect_response(
            redirect_url=redirect_uri,
            access_token=completion.access_token,
            refresh_token=completion.refresh_token,
        )
    return TokenPairResponse(
        access_token=completion.access_token,
        refresh_token=completion.refresh_token,
    )
