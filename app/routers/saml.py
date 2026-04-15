"""SAML routes."""

from __future__ import annotations

from typing import Annotated
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.browser_sessions import (
    build_cookie_session_redirect_response,
    get_browser_session_settings,
)
from app.core.saml import build_saml_request_data
from app.dependencies import get_database_session
from app.schemas.token import TokenPairResponse
from app.services.audit_service import AuditService, get_audit_service
from app.services.saml_service import SamlService, SamlServiceError, get_saml_service
from app.services.webhook_service import WebhookService, get_webhook_service

router = APIRouter(prefix="/auth/saml", tags=["saml"])


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


def _query_to_dict(request: Request) -> dict[str, str]:
    """Convert query params to plain string dict."""
    return {key: value for key, value in request.query_params.items()}


async def _post_form_to_dict(request: Request) -> dict[str, str]:
    """Parse POST form body as key/value dict."""
    body = await request.body()
    if not body:
        return {}
    decoded = body.decode("utf-8")
    parsed = parse_qs(decoded, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items() if values}


def _append_query_params(url: str, **params: str) -> str:
    """Append query parameters to a URL while preserving existing values."""
    parsed = urlsplit(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        existing[key] = [value]
    merged_query = urlencode(existing, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, merged_query, parsed.fragment))


def _normalized_optional_attr(value: object) -> str | None:
    """Normalize optional redirect-like attributes without stringifying None."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


@router.get("/login", response_model=None)
async def saml_login(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    relay_state: Annotated[str | None, Query()] = None,
    audience: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
) -> Response:
    """Initiate SAML authentication request."""
    request_data = build_saml_request_data(request=request, get_data=_query_to_dict(request))
    try:
        redirect_url = await saml_service.create_login_url(
            request_data=request_data,
            relay_state=relay_state,
            audience=audience,
        )
    except SamlServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "saml", "phase": "start"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.api_route("/callback", methods=["GET", "POST"], response_model=TokenPairResponse)
async def saml_callback(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> TokenPairResponse | JSONResponse:
    """Handle SAML response callback and issue tokens."""
    get_data = _query_to_dict(request)
    post_data = await _post_form_to_dict(request) if request.method.upper() == "POST" else {}
    request_data = build_saml_request_data(request=request, get_data=get_data, post_data=post_data)
    try:
        completion = await saml_service.complete_callback(
            db_session=db_session,
            request_data=request_data,
        )
    except SamlServiceError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "saml", "phase": "callback"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.login.success",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "saml", "phase": "callback"},
    )
    await audit_service.record(
        db=db_session,
        event_type="session.created",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "saml"},
    )
    await webhook_service.emit_event(
        event_type="session.created",
        data={"provider": "saml"},
    )
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "saml", "token_kind": "access_refresh_pair"},
    )
    redirect_uri = _normalized_optional_attr(getattr(completion, "redirect_uri", None))
    relay_state = _normalized_optional_attr(getattr(completion, "relay_state", None))
    if redirect_uri is not None and get_browser_session_settings().enabled:
        redirect_url = (
            _append_query_params(redirect_uri, relay_state=relay_state)
            if relay_state is not None
            else redirect_uri
        )
        return build_cookie_session_redirect_response(
            redirect_url=redirect_url,
            access_token=completion.access_token,
            refresh_token=completion.refresh_token,
        )
    return TokenPairResponse(
        access_token=completion.access_token,
        refresh_token=completion.refresh_token,
    )


@router.get("/metadata", response_model=None)
async def saml_metadata(
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
) -> Response:
    """Expose SP metadata for IdP configuration."""
    try:
        metadata = saml_service.metadata_xml()
    except SamlServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    return Response(content=metadata, media_type="application/samlmetadata+xml")
