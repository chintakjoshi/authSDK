"""Authentication routes."""

from __future__ import annotations

import inspect
import json
from typing import Annotated
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.core.browser_sessions import (
    build_cookie_session_response,
    clear_auth_cookies,
    extract_refresh_token_from_cookie,
    get_browser_session_settings,
    is_cookie_transport_request,
    mint_csrf_token,
    require_csrf_for_cookie_transport,
    set_csrf_cookie,
)
from app.core.browser_sessions import (
    extract_bearer_token as _shared_extract_bearer_token,
)
from app.core.callable_compat import add_supported_kwarg, get_callable_parameter_names
from app.core.jwt import JWTService, TokenValidationError, get_jwt_service
from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.dependencies import get_database_session
from app.schemas.api_key import APIKeyIntrospectRequest
from app.schemas.otp import LoginOTPChallengeResponse
from app.schemas.token import (
    CookieSessionResponse,
    CSRFTokenResponse,
    LogoutRequest,
    OAuthAccessTokenResponse,
    RefreshTokenRequest,
    TokenPairResponse,
)
from app.schemas.user import LoginRequest
from app.services.api_key_service import APIKeyService, get_api_key_service
from app.services.audit_service import AuditService, get_audit_service
from app.services.brute_force_service import (
    BruteForceProtectionError,
    BruteForceProtectionService,
    extract_client_ip,
    get_brute_force_service,
    normalize_user_agent,
)
from app.services.m2m_service import M2MService, M2MServiceError, get_m2m_service
from app.services.otp_service import OTPService, OTPServiceError, get_otp_service
from app.services.token_service import TokenService, get_token_service
from app.services.user_service import UserService, get_user_service
from app.services.webhook_service import WebhookService, get_webhook_service

router = APIRouter(tags=["auth"])


def _auth_service_audience() -> str:
    """Resolve the auth service audience with a safe default for lightweight tests."""
    try:
        return get_settings().app.service
    except Exception:
        return "auth-service"

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


def _extract_bearer_token(request: Request) -> str | None:
    """Compatibility wrapper for bearer extraction used by existing tests."""
    return _shared_extract_bearer_token(request)


def _first_form_value(form_data: dict[str, list[str]], key: str) -> str | None:
    """Return the first form value for a key or None when absent."""
    values = form_data.get(key, [])
    if not values:
        return None
    value = values[0].strip()
    return value or None


def _issue_token_pair(
    token_service: TokenService,
    db_session: AsyncSession,
    user_id: str,
    email: str | None = None,
    role: str | None = None,
    email_verified: bool | None = None,
    email_otp_enabled: bool | None = None,
    scopes: list[str] | None = None,
    audience=None,
    auth_time=None,
):
    """Issue token pair while supporting legacy test doubles without db_session arg."""
    issue_method = token_service.issue_token_pair
    supported_parameters = get_callable_parameter_names(issue_method)
    kwargs: dict[str, object] = {"user_id": user_id, "email": email, "scopes": scopes}
    if supported_parameters is not None and "db_session" in supported_parameters:
        kwargs["db_session"] = db_session

    add_supported_kwarg(
        kwargs,
        supported_parameters=supported_parameters,
        name="role",
        value=role,
    )
    add_supported_kwarg(
        kwargs,
        supported_parameters=supported_parameters,
        name="email_verified",
        value=email_verified,
    )
    add_supported_kwarg(
        kwargs,
        supported_parameters=supported_parameters,
        name="email_otp_enabled",
        value=email_otp_enabled,
    )
    add_supported_kwarg(
        kwargs,
        supported_parameters=supported_parameters,
        name="audience",
        value=audience,
    )
    add_supported_kwarg(
        kwargs,
        supported_parameters=supported_parameters,
        name="audiences",
        value=audience,
    )
    add_supported_kwarg(
        kwargs,
        supported_parameters=supported_parameters,
        name="auth_time",
        value=auth_time,
    )
    return issue_method(**kwargs)


def _password_login_requires_verified_email() -> bool:
    """Return whether password login is blocked until email verification completes."""
    return bool(get_settings().auth.require_verified_email_for_password_login)


@router.post(
    "/auth/login",
    response_model=TokenPairResponse | LoginOTPChallengeResponse | CookieSessionResponse,
)
async def login(
    payload: LoginRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
    brute_force_service: Annotated[BruteForceProtectionService, Depends(get_brute_force_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> TokenPairResponse | LoginOTPChallengeResponse | JSONResponse:
    """Authenticate email/password credentials and issue JWT pair."""
    csrf_error = require_csrf_for_cookie_transport(request)
    if csrf_error is not None:
        return csrf_error

    user = await user_service.get_user_by_email(db_session=db_session, email=payload.email)
    client_ip = extract_client_ip(request)
    user_agent = normalize_user_agent(request.headers.get("user-agent"))

    if user is None or user.password_hash is None:
        user_service.dummy_verify()
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            failure_reason="invalid_credentials",
            metadata={"provider": "password"},
        )
        return _error_response(
            status_code=401,
            detail="Invalid email or password.",
            code="invalid_credentials",
        )

    try:
        await brute_force_service.ensure_not_locked(str(user.id))
    except BruteForceProtectionError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            actor_id=str(user.id),
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    if not user_service.verify_password(
        password=payload.password, password_hash=user.password_hash
    ):
        try:
            failure_decision = await brute_force_service.record_failed_password_attempt(
                str(user.id),
                ip_address=client_ip,
            )
        except BruteForceProtectionError as exc:
            await audit_service.record(
                db=db_session,
                event_type="user.login.failure",
                actor_type="user",
                success=False,
                request=request,
                actor_id=str(user.id),
                failure_reason=exc.code,
                metadata={"provider": "password"},
            )
            return _error_response(
                status_code=exc.status_code,
                detail=exc.detail,
                code=exc.code,
                headers=exc.headers,
            )

        if failure_decision.locked:
            await audit_service.record(
                db=db_session,
                event_type="user.locked",
                actor_type="user",
                success=False,
                request=request,
                actor_id=str(user.id),
                target_id=str(user.id),
                target_type="user",
                failure_reason="account_locked",
                metadata={
                    "provider": "password",
                    "retry_after": failure_decision.retry_after,
                    "distributed_attack": failure_decision.distributed_attack,
                    "attempt_count": failure_decision.attempt_count,
                },
            )
            await webhook_service.emit_event(
                event_type="user.locked",
                data={
                    "user_id": str(user.id),
                    "provider": "password",
                    "retry_after": failure_decision.retry_after,
                    "distributed_attack": failure_decision.distributed_attack,
                },
            )
            await audit_service.record(
                db=db_session,
                event_type="user.login.failure",
                actor_type="user",
                success=False,
                request=request,
                actor_id=str(user.id),
                failure_reason="account_locked",
                metadata={"provider": "password"},
            )
            return _error_response(
                status_code=401,
                detail="Account temporarily locked.",
                code="account_locked",
                headers={"Retry-After": str(failure_decision.retry_after or 1)},
            )

        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            actor_id=str(user.id),
            failure_reason="invalid_credentials",
            metadata={"provider": "password"},
        )
        return _error_response(
            status_code=401,
            detail="Invalid email or password.",
            code="invalid_credentials",
        )

    if _password_login_requires_verified_email() and not bool(
        getattr(user, "email_verified", False)
    ):
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            actor_id=str(user.id),
            failure_reason="email_not_verified",
            metadata={"provider": "password"},
        )
        return _error_response(
            status_code=400,
            detail="Email is not verified.",
            code="email_not_verified",
        )

    if bool(getattr(user, "email_verified", False)) and bool(
        getattr(user, "email_otp_enabled", False)
    ):
        try:
            challenge = await otp_service.start_login_challenge(
                db_session=db_session,
                user=user,
                requested_audience=payload.audience,
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
            event_type="user.login.otp_required",
            actor_type="user",
            success=True,
            request=request,
            actor_id=challenge.user_id,
            metadata={"provider": "password"},
        )
        await audit_service.record(
            db=db_session,
            event_type="otp.sent",
            actor_type="user",
            success=True,
            request=request,
            actor_id=challenge.user_id,
            metadata={"context": "login"},
        )
        return LoginOTPChallengeResponse(
            otp_required=True,
            challenge_token=challenge.challenge_token,
            masked_email=challenge.masked_email,
        )

    try:
        suspicious_login = await brute_force_service.record_successful_login(
            str(user.id),
            ip_address=client_ip,
            user_agent=user_agent,
        )
    except BruteForceProtectionError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            actor_id=str(user.id),
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )

    issued_pair = _issue_token_pair(
        token_service=token_service,
        db_session=db_session,
        user_id=str(user.id),
        email=user.email,
        role=getattr(user, "role", "user"),
        email_verified=bool(getattr(user, "email_verified", False)),
        email_otp_enabled=bool(getattr(user, "email_otp_enabled", False)),
        scopes=[],
        audience=payload.audience,
    )
    token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
    try:
        session_id = await session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=getattr(user, "role", "user"),
            email_verified=bool(getattr(user, "email_verified", False)),
            email_otp_enabled=bool(getattr(user, "email_otp_enabled", False)),
            scopes=[],
            raw_access_token=token_pair.access_token,
            raw_refresh_token=token_pair.refresh_token,
        )
    except SessionStateError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.login.failure",
            actor_type="user",
            success=False,
            request=request,
            actor_id=str(user.id),
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.login.success",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
        metadata={"provider": "password"},
    )
    if suspicious_login.suspicious:
        await audit_service.record(
            db=db_session,
            event_type="user.login.suspicious",
            actor_type="user",
            success=True,
            request=request,
            actor_id=str(user.id),
            metadata={"provider": "password", **suspicious_login.metadata},
        )
    await audit_service.record(
        db=db_session,
        event_type="session.created",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
        target_id=str(session_id),
        target_type="session",
        metadata={"provider": "password"},
    )
    await webhook_service.emit_event(
        event_type="session.created",
        data={
            "session_id": str(session_id),
            "user_id": str(user.id),
            "provider": "password",
        },
    )
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
        metadata={"provider": "password", "token_kind": "access_refresh_pair"},
    )
    if is_cookie_transport_request(request):
        return build_cookie_session_response(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
        )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )


@router.post(
    "/auth/token",
    response_model=TokenPairResponse | OAuthAccessTokenResponse | CookieSessionResponse,
)
async def token_endpoint(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    m2m_service: Annotated[M2MService, Depends(get_m2m_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> TokenPairResponse | OAuthAccessTokenResponse | JSONResponse:
    """Handle refresh-token rotation and client-credentials token issuance."""
    content_type = request.headers.get("content-type", "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        raw_body = await request.body()
        form_data = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
        grant_type = _first_form_value(form_data, "grant_type")
        if grant_type != "client_credentials":
            await audit_service.record(
                db=db_session,
                event_type="client.auth.failure",
                actor_type="service",
                success=False,
                request=request,
                failure_reason="invalid_credentials",
            )
            return _error_response(
                status_code=400,
                detail="Unsupported grant type.",
                code="invalid_credentials",
            )

        client_id = _first_form_value(form_data, "client_id")
        client_secret = _first_form_value(form_data, "client_secret")
        scope = _first_form_value(form_data, "scope")
        audience = _first_form_value(form_data, "audience")
        if client_id is None or client_secret is None:
            await audit_service.record(
                db=db_session,
                event_type="client.auth.failure",
                actor_type="service",
                success=False,
                request=request,
                failure_reason="invalid_credentials",
                metadata={"client_id": client_id},
            )
            return _error_response(
                status_code=401,
                detail="Invalid client credentials.",
                code="invalid_credentials",
            )

        try:
            issued_token = await m2m_service.authenticate_client_credentials(
                db_session=db_session,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                audience=audience,
            )
        except M2MServiceError as exc:
            await audit_service.record(
                db=db_session,
                event_type="client.auth.failure",
                actor_type="service",
                success=False,
                request=request,
                failure_reason=exc.code,
                metadata={"client_id": client_id},
            )
            return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

        await audit_service.record(
            db=db_session,
            event_type="client.authenticated",
            actor_type="service",
            success=True,
            request=request,
            metadata={"client_id": issued_token.client_id, "scope": issued_token.scope},
        )
        return OAuthAccessTokenResponse(
            access_token=issued_token.access_token,
            token_type="Bearer",
            expires_in=issued_token.expires_in,
            scope=issued_token.scope,
        )

    refresh_token: str
    cookie_transport = is_cookie_transport_request(request)
    if cookie_transport:
        csrf_error = require_csrf_for_cookie_transport(request)
        if csrf_error is not None:
            return csrf_error
        refresh_token = extract_refresh_token_from_cookie(request) or ""
        if not refresh_token:
            return _error_response(
                status_code=401, detail="Session expired.", code="session_expired"
            )
    else:
        try:
            payload = RefreshTokenRequest.model_validate(await request.json())
        except json.JSONDecodeError:
            return _error_response(
                status_code=422,
                detail="Invalid request payload.",
                code="invalid_credentials",
            )
        except ValidationError:
            return _error_response(
                status_code=422,
                detail="Invalid request payload.",
                code="invalid_credentials",
            )
        refresh_token = payload.refresh_token

    try:

        async def _issue_pair(
            user_id: str,
            email: str | None = None,
            role: str | None = None,
            email_verified: bool | None = None,
            email_otp_enabled: bool | None = None,
            scopes: list[str] | None = None,
            audiences=None,
            auth_time=None,
        ):
            issued = _issue_token_pair(
                token_service=token_service,
                db_session=db_session,
                user_id=user_id,
                email=email,
                role=role,
                email_verified=email_verified,
                email_otp_enabled=email_otp_enabled,
                scopes=scopes,
                audience=audiences,
                auth_time=auth_time,
            )
            return await issued if inspect.isawaitable(issued) else issued

        rotated = await session_service.rotate_refresh_session(
            db_session=db_session,
            raw_refresh_token=refresh_token,
            token_issuer=_issue_pair,
        )
        token_pair = await rotated if inspect.isawaitable(rotated) else rotated
    except SessionStateError as exc:
        await audit_service.record(
            db=db_session,
            event_type="token.refreshed",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="token.refreshed",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "password"},
    )
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        metadata={"provider": "password", "token_kind": "access_refresh_pair"},
    )
    if cookie_transport:
        return build_cookie_session_response(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
        )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )


@router.post("/auth/logout", response_model=None)
async def logout(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
    signing_key_service: Annotated[SigningKeyService, Depends(get_signing_key_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    payload: LogoutRequest | None = None,
) -> Response | JSONResponse:
    """Revoke session and blocklist current access token JTI."""
    cookie_transport = is_cookie_transport_request(request)
    if cookie_transport:
        csrf_error = require_csrf_for_cookie_transport(request)
        if csrf_error is not None:
            return csrf_error
        settings = get_browser_session_settings()
        access_token = request.cookies.get(settings.access_cookie_name, "").strip()
        refresh_token = request.cookies.get(settings.refresh_cookie_name, "").strip()
    else:
        access_token = _extract_bearer_token(request)
        refresh_token = payload.refresh_token if payload is not None else ""

    if access_token is None or not access_token:
        await audit_service.record(
            db=db_session,
            event_type="user.logout",
            actor_type="user",
            success=False,
            request=request,
            failure_reason="invalid_token",
            metadata={"provider": "password"},
        )
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")
    if not refresh_token:
        await audit_service.record(
            db=db_session,
            event_type="user.logout",
            actor_type="user",
            success=False,
            request=request,
            failure_reason="invalid_token",
            metadata={"provider": "password"},
        )
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        verification_keys = await signing_key_service.get_verification_public_keys(db_session)
        claims = jwt_service.verify_token(
            access_token,
            expected_type="access",
            public_keys_by_kid=verification_keys,
            expected_audience=_auth_service_audience(),
        )
    except TokenValidationError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.logout",
            actor_type="user",
            success=False,
            request=request,
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(status_code=401, detail=exc.detail, code=exc.code)

    try:
        await session_service.revoke_session(
            db_session=db_session,
            raw_refresh_token=refresh_token,
            access_jti=str(claims["jti"]),
            access_expiration_epoch=int(claims["exp"]),
        )
    except SessionStateError as exc:
        await audit_service.record(
            db=db_session,
            event_type="user.logout",
            actor_type="user",
            success=False,
            request=request,
            actor_id=str(claims.get("sub", "")),
            failure_reason=exc.code,
            metadata={"provider": "password"},
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    await audit_service.record(
        db=db_session,
        event_type="user.logout",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(claims.get("sub", "")),
        metadata={"provider": "password"},
    )
    await webhook_service.emit_event(
        event_type="session.revoked",
        data={
            "user_id": str(claims.get("sub", "")),
            "provider": "password",
            "reason": "logout",
        },
    )
    response = Response(status_code=204)
    if cookie_transport:
        clear_auth_cookies(response, clear_csrf=True)
    return response


@router.get("/auth/csrf", response_model=CSRFTokenResponse)
async def csrf() -> CSRFTokenResponse | JSONResponse:
    """Mint or rotate the CSRF token used for browser-session double submit protection."""
    csrf_token = mint_csrf_token()
    response = JSONResponse(status_code=200, content={"csrf_token": csrf_token})
    set_csrf_cookie(response, csrf_token)
    return response


@router.get("/.well-known/jwks.json")
async def jwks(
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    signing_key_service: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> dict[str, list[dict[str, str]]]:
    """Return public JWKS for RS256 token verification."""
    return await signing_key_service.get_jwks_payload(db_session)


@router.get("/auth/validate", response_model=None)
async def validate_access_token(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    otp_service: Annotated[OTPService, Depends(get_otp_service)],
) -> Response | JSONResponse:
    """Validate that a bearer access token is still backed by an active session."""
    access_token = _extract_bearer_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        await otp_service.validate_access_token(db_session=db_session, token=access_token)
    except OTPServiceError as exc:
        return _error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            code=exc.code,
            headers=exc.headers,
        )
    return Response(status_code=204)


@router.post("/auth/introspect")
async def introspect_api_key(
    request: Request,
    payload: APIKeyIntrospectRequest,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> JSONResponse:
    """Introspect opaque API key and return SDK contract payload."""
    result = await api_key_service.introspect(db_session=db_session, raw_key=payload.api_key)
    if not result.valid:
        await audit_service.record(
            db=db_session,
            event_type="api_key.used",
            actor_type="service",
            success=False,
            request=request,
            failure_reason=result.code,
            target_type="api_key",
        )
        return JSONResponse(status_code=200, content={"valid": False, "code": result.code})
    await audit_service.record(
        db=db_session,
        event_type="api_key.used",
        actor_type="service",
        success=True,
        request=request,
        actor_id=result.user_id,
        target_id=result.key_id,
        target_type="api_key",
    )
    response_content = {
        "valid": True,
        "user_id": result.user_id,
        "scopes": result.scopes or [],
        "key_id": result.key_id,
        "expires_at": result.expires_at,
    }
    if result.service:
        response_content["service"] = result.service
    return JSONResponse(
        status_code=200,
        content=response_content,
    )
