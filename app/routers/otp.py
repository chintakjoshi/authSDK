"""Email OTP routes for login MFA and sensitive action verification."""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.browser_sessions import (
    build_cookie_session_response,
    extract_access_token,
    is_cookie_transport_request,
    require_csrf_for_cookie_authenticated_request,
    require_csrf_for_cookie_transport,
)
from app.core.browser_sessions import (
    extract_bearer_token as _shared_extract_bearer_token,
)
from app.dependencies import get_database_session
from app.schemas.otp import (
    OTPEnrollmentResponse,
    OTPMessageSentResponse,
    RequestActionOTPRequest,
    RequestActionOTPResponse,
    ResendLoginOTPRequest,
    VerifyActionOTPRequest,
    VerifyActionOTPResponse,
    VerifyLoginOTPRequest,
)
from app.schemas.token import CookieSessionResponse, TokenPairResponse
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import extract_client_ip, normalize_user_agent
from app.services.otp_service import OTPService, OTPServiceError, get_otp_service
from app.services.webhook_service import WebhookService, get_webhook_service

router = APIRouter(tags=["otp"])


def _error_response(
    status_code: int,
    detail: str,
    code: str,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "code": code},
        headers=headers,
    )


def _extract_action_token(request: Request) -> str | None:
    """Extract action token from X-Action-Token header."""
    token = request.headers.get("x-action-token", "").strip()
    return token or None


def _extract_bearer_token(request: Request) -> str | None:
    """Compatibility wrapper for bearer extraction used by existing tests."""
    return _shared_extract_bearer_token(request)


def _auth_time_is_fresh(claims: dict[str, object], *, max_age_seconds: int = 300) -> bool:
    """Return True when auth_time is recent enough for password step-up."""
    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, int):
        return False
    return (time.time() - auth_time) <= max_age_seconds


async def _record_failure_events(
    *,
    audit_service: AuditService,
    db_session: AsyncSession,
    request: Request,
    actor_id: str | None,
    events: tuple[str, ...],
    metadata: dict[str, object] | None = None,
    failure_reason: str | None = None,
) -> None:
    """Persist OTP-related audit failures derived from service exceptions."""
    for event_type in events:
        await audit_service.record(
            db=db_session,
            event_type=event_type,
            actor_type="user",
            success=False,
            request=request,
            actor_id=actor_id,
            failure_reason=failure_reason,
            metadata=metadata,
        )


@router.post("/auth/otp/verify/login", response_model=TokenPairResponse | CookieSessionResponse)
async def verify_login_otp(
    payload: VerifyLoginOTPRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> TokenPairResponse | JSONResponse:
    """Complete password login after email OTP verification."""
    csrf_error = require_csrf_for_cookie_transport(request)
    if csrf_error is not None:
        return csrf_error

    try:
        result = await otp_service.verify_login_code(
            db_session=db_session,
            challenge_token=payload.challenge_token,
            code=payload.code,
            client_ip=extract_client_ip(request),
            user_agent=normalize_user_agent(request.headers.get("user-agent")),
        )
    except OTPServiceError as exc:
        await _record_failure_events(
            audit_service=audit_service,
            db_session=db_session,
            request=request,
            actor_id=exc.user_id,
            events=exc.audit_events,
            metadata={"context": "login"},
            failure_reason=exc.code,
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="otp.verified",
        actor_type="user",
        success=True,
        request=request,
        actor_id=result.user_id,
        metadata={"context": "login"},
    )
    await webhook_service.emit_event(
        event_type="otp.verified",
        data={"user_id": result.user_id, "context": "login"},
    )
    await audit_service.record(
        db=db_session,
        event_type="user.login.success",
        actor_type="user",
        success=True,
        request=request,
        actor_id=result.user_id,
        metadata={"provider": "password"},
    )
    if result.suspicious_login is not None:
        await audit_service.record(
            db=db_session,
            event_type="user.login.suspicious",
            actor_type="user",
            success=True,
            request=request,
            actor_id=result.user_id,
            metadata={"provider": "password", **result.suspicious_login},
        )
    await audit_service.record(
        db=db_session,
        event_type="session.created",
        actor_type="user",
        success=True,
        request=request,
        actor_id=result.user_id,
        target_id=str(result.session_id),
        target_type="session",
        metadata={"provider": "password"},
    )
    await webhook_service.emit_event(
        event_type="session.created",
        data={
            "session_id": str(result.session_id),
            "user_id": result.user_id,
            "provider": "password",
        },
    )
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        actor_id=result.user_id,
        metadata={"provider": "password", "token_kind": "access_refresh_pair"},
    )
    if is_cookie_transport_request(request):
        return build_cookie_session_response(
            access_token=result.token_pair.access_token,
            refresh_token=result.token_pair.refresh_token,
        )
    return TokenPairResponse(
        access_token=result.token_pair.access_token,
        refresh_token=result.token_pair.refresh_token,
    )


@router.post("/auth/otp/resend/login", response_model=OTPMessageSentResponse)
async def resend_login_otp(
    payload: ResendLoginOTPRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> OTPMessageSentResponse | JSONResponse:
    """Resend a login OTP for an active challenge token."""
    try:
        user_id = await otp_service.resend_login_code(
            db_session=db_session,
            challenge_token=payload.challenge_token,
        )
    except OTPServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="otp.sent",
        actor_type="user",
        success=True,
        request=request,
        actor_id=user_id,
        metadata={"context": "login"},
    )
    return OTPMessageSentResponse(sent=True)


@router.post("/auth/otp/request/action", response_model=RequestActionOTPResponse)
async def request_action_otp(
    payload: RequestActionOTPRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> RequestActionOTPResponse | JSONResponse:
    """Send an OTP for a sensitive authenticated action."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, _ = extract_access_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = await otp_service.validate_access_token(db_session=db_session, token=access_token)
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
        result = await otp_service.request_action_code(
            db_session=db_session,
            user_id=user_id,
            action=payload.action,
        )
    except OTPServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="otp.sent",
        actor_type="user",
        success=True,
        request=request,
        actor_id=result.user_id,
        metadata={"context": "action", "action": result.action},
    )
    return RequestActionOTPResponse(sent=True, action=result.action, expires_in=result.expires_in)


@router.post("/auth/otp/verify/action", response_model=VerifyActionOTPResponse)
async def verify_action_otp(
    payload: VerifyActionOTPRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> VerifyActionOTPResponse | JSONResponse:
    """Verify an action OTP and mint an action token."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, _ = extract_access_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = await otp_service.validate_access_token(db_session=db_session, token=access_token)
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
        result = await otp_service.verify_action_code(
            db_session=db_session,
            user_id=user_id,
            code=payload.code,
            action=payload.action,
            audience=claims.get("aud"),
        )
    except OTPServiceError as exc:
        await _record_failure_events(
            audit_service=audit_service,
            db_session=db_session,
            request=request,
            actor_id=exc.user_id,
            events=exc.audit_events,
            metadata={"context": "action", "action": payload.action},
            failure_reason=exc.code,
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="otp.verified",
        actor_type="user",
        success=True,
        request=request,
        actor_id=result.user_id,
        metadata={"context": "action", "action": result.action},
    )
    await webhook_service.emit_event(
        event_type="otp.verified",
        data={"user_id": result.user_id, "context": "action", "action": result.action},
    )
    return VerifyActionOTPResponse(action_token=result.action_token)


@router.post("/auth/otp/enable", response_model=OTPEnrollmentResponse)
async def enable_email_otp(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> OTPEnrollmentResponse | JSONResponse:
    """Enable login OTP for the authenticated user."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, _ = extract_access_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = await otp_service.validate_access_token(db_session=db_session, token=access_token)
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
        action = "enable_otp"
        action_token_valid = await otp_service.validate_action_token_for_user(
            db_session=db_session,
            token=_extract_action_token(request),
            expected_action=action,
            user_id=user_id,
        )
        if not action_token_valid:
            if bool(claims.get("email_otp_enabled", False)):
                return _error_response(
                    status_code=403,
                    detail="OTP required.",
                    code="otp_required",
                    headers={"X-OTP-Required": "true", "X-OTP-Action": action},
                )
            if not _auth_time_is_fresh(claims):
                return _error_response(
                    status_code=403,
                    detail="Re-authentication required.",
                    code="reauth_required",
                    headers={"X-Reauth-Required": "true"},
                )
        user = await otp_service.enable_email_otp(
            db_session=db_session,
            user_id=user_id,
            action_token=None,
            require_action_token=False,
        )
    except OTPServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="otp.enabled",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
    )
    return OTPEnrollmentResponse(email_otp_enabled=user.email_otp_enabled)


@router.post("/auth/otp/disable", response_model=OTPEnrollmentResponse)
async def disable_email_otp(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> OTPEnrollmentResponse | JSONResponse:
    """Disable login OTP for the authenticated user."""
    csrf_error = require_csrf_for_cookie_authenticated_request(request)
    if csrf_error is not None:
        return csrf_error

    access_token, _ = extract_access_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = await otp_service.validate_access_token(db_session=db_session, token=access_token)
        user_id = str(claims.get("sub", "")).strip()
        if not user_id:
            return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
        action = "disable_otp"
        action_token_valid = await otp_service.validate_action_token_for_user(
            db_session=db_session,
            token=_extract_action_token(request),
            expected_action=action,
            user_id=user_id,
        )
        if not action_token_valid:
            if bool(claims.get("email_otp_enabled", False)):
                return _error_response(
                    status_code=403,
                    detail="OTP required.",
                    code="otp_required",
                    headers={"X-OTP-Required": "true", "X-OTP-Action": action},
                )
            if not _auth_time_is_fresh(claims):
                return _error_response(
                    status_code=403,
                    detail="Re-authentication required.",
                    code="reauth_required",
                    headers={"X-Reauth-Required": "true"},
                )
        user = await otp_service.disable_email_otp(
            db_session=db_session,
            user_id=user_id,
            action_token=None,
            require_action_token=False,
        )
    except OTPServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    await audit_service.record(
        db=db_session,
        event_type="otp.disabled",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
    )
    return OTPEnrollmentResponse(email_otp_enabled=user.email_otp_enabled)
