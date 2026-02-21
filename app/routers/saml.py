"""SAML routes."""

from __future__ import annotations

from typing import Annotated
from urllib.parse import parse_qs

import structlog
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.saml import build_saml_request_data
from app.dependencies import get_database_session
from app.schemas.token import TokenPairResponse
from app.services.saml_service import SamlService, SamlServiceError, get_saml_service

router = APIRouter(prefix="/auth/saml", tags=["saml"])
logger = structlog.get_logger(__name__)


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


@router.get("/login", response_model=None)
async def saml_login(
    request: Request,
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
    relay_state: Annotated[str | None, Query()] = None,
) -> Response:
    """Initiate SAML authentication request."""
    correlation_id = request.headers.get("x-correlation-id", "unknown")
    client_ip = _extract_client_ip(request)
    request_data = build_saml_request_data(request=request, get_data=_query_to_dict(request))
    try:
        redirect_url = saml_service.create_login_url(
            request_data=request_data, relay_state=relay_state
        )
    except SamlServiceError as exc:
        logger.warning(
            "saml_login_start",
            correlation_id=correlation_id,
            event_type="login_attempt",
            user_id=None,
            provider="saml",
            ip_address=client_ip,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.api_route("/callback", methods=["GET", "POST"], response_model=TokenPairResponse)
async def saml_callback(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    saml_service: Annotated[SamlService, Depends(get_saml_service)],
) -> TokenPairResponse | JSONResponse:
    """Handle SAML response callback and issue tokens."""
    correlation_id = request.headers.get("x-correlation-id", "unknown")
    client_ip = _extract_client_ip(request)
    get_data = _query_to_dict(request)
    post_data = await _post_form_to_dict(request) if request.method.upper() == "POST" else {}
    request_data = build_saml_request_data(request=request, get_data=get_data, post_data=post_data)
    try:
        token_pair = await saml_service.complete_callback(
            db_session=db_session,
            request_data=request_data,
        )
    except SamlServiceError as exc:
        logger.warning(
            "saml_callback",
            correlation_id=correlation_id,
            event_type="login_attempt",
            user_id=None,
            provider="saml",
            ip_address=client_ip,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    logger.info(
        "saml_callback",
        correlation_id=correlation_id,
        event_type="login_attempt",
        user_id=None,
        provider="saml",
        ip_address=client_ip,
        success=True,
    )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
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
