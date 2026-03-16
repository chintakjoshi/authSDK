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

from app.core.jwt import JWTService, TokenValidationError, get_jwt_service
from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.dependencies import get_database_session
from app.schemas.api_key import APIKeyIntrospectRequest
from app.schemas.otp import LoginOTPChallengeResponse
from app.schemas.token import (
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
from app.services.user_service import UserService

router = APIRouter(tags=["auth"])


def get_user_service() -> UserService:
    """Provide the user service dependency."""
    return UserService()


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
    """Extract bearer token from Authorization header."""
    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    cleaned = token.strip()
    return cleaned or None


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
    auth_time=None,
):
    """Issue token pair while supporting legacy test doubles without db_session arg."""
    issue_method = token_service.issue_token_pair
    try:
        signature = inspect.signature(issue_method)
    except (TypeError, ValueError):
        signature = None
    if signature and "db_session" in signature.parameters:
        kwargs: dict[str, object] = {
            "db_session": db_session,
            "user_id": user_id,
            "email": email,
            "scopes": scopes,
        }
        if role is not None and "role" in signature.parameters:
            kwargs["role"] = role
        if email_verified is not None and "email_verified" in signature.parameters:
            kwargs["email_verified"] = email_verified
        if email_otp_enabled is not None and "email_otp_enabled" in signature.parameters:
            kwargs["email_otp_enabled"] = email_otp_enabled
        if auth_time is not None and "auth_time" in signature.parameters:
            kwargs["auth_time"] = auth_time
        return issue_method(**kwargs)
    kwargs: dict[str, object] = {"user_id": user_id, "email": email, "scopes": scopes}
    if signature and role is not None and "role" in signature.parameters:
        kwargs["role"] = role
    if signature and email_verified is not None and "email_verified" in signature.parameters:
        kwargs["email_verified"] = email_verified
    if signature and email_otp_enabled is not None and "email_otp_enabled" in signature.parameters:
        kwargs["email_otp_enabled"] = email_otp_enabled
    if signature and auth_time is not None and "auth_time" in signature.parameters:
        kwargs["auth_time"] = auth_time
    return issue_method(**kwargs)


@router.post("/auth/login", response_model=TokenPairResponse | LoginOTPChallengeResponse)
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
) -> TokenPairResponse | LoginOTPChallengeResponse | JSONResponse:
    """Authenticate email/password credentials and issue JWT pair."""
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

    if bool(getattr(user, "email_verified", False)) and bool(
        getattr(user, "email_otp_enabled", False)
    ):
        try:
            challenge = await otp_service.start_login_challenge(db_session=db_session, user=user)
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
    await audit_service.record(
        db=db_session,
        event_type="token.issued",
        actor_type="user",
        success=True,
        request=request,
        actor_id=str(user.id),
        metadata={"provider": "password", "token_kind": "access_refresh_pair"},
    )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )


@router.post("/auth/token", response_model=TokenPairResponse | OAuthAccessTokenResponse)
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

    try:

        async def _issue_pair(
            user_id: str,
            email: str | None = None,
            role: str | None = None,
            email_verified: bool | None = None,
            email_otp_enabled: bool | None = None,
            scopes: list[str] | None = None,
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
                auth_time=auth_time,
            )
            return await issued if inspect.isawaitable(issued) else issued

        rotated = await session_service.rotate_refresh_session(
            db_session=db_session,
            raw_refresh_token=payload.refresh_token,
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
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )


@router.post("/auth/logout", response_model=None)
async def logout(
    payload: LogoutRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
    signing_key_service: Annotated[SigningKeyService, Depends(get_signing_key_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> Response | JSONResponse:
    """Revoke session and blocklist current access token JTI."""
    access_token = _extract_bearer_token(request)
    if access_token is None:
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
            raw_refresh_token=payload.refresh_token,
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
    return Response(status_code=204)


@router.get("/.well-known/jwks.json")
async def jwks(
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    signing_key_service: Annotated[SigningKeyService, Depends(get_signing_key_service)],
) -> dict[str, list[dict[str, str]]]:
    """Return public JWKS for RS256 token verification."""
    return await signing_key_service.get_jwks_payload(db_session)


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
    return JSONResponse(
        status_code=200,
        content={
            "valid": True,
            "user_id": result.user_id,
            "scopes": result.scopes or [],
            "key_id": result.key_id,
            "expires_at": result.expires_at,
        },
    )
