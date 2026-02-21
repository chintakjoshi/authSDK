"""Authentication routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import JWTService, TokenValidationError, get_jwt_service
from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.dependencies import get_database_session
from app.schemas.api_key import APIKeyIntrospectRequest
from app.schemas.token import LogoutRequest, RefreshTokenRequest, TokenPairResponse
from app.schemas.user import LoginRequest
from app.services.api_key_service import APIKeyService, get_api_key_service
from app.services.audit_service import AuditService, get_audit_service
from app.services.token_service import TokenService, get_token_service
from app.services.user_service import UserService

router = APIRouter(tags=["auth"])


def get_user_service() -> UserService:
    """Provide the user service dependency."""
    return UserService()


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


@router.post("/auth/login", response_model=TokenPairResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> TokenPairResponse | JSONResponse:
    """Authenticate email/password credentials and issue JWT pair."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    user = await user_service.authenticate_user(
        db_session=db_session,
        email=payload.email,
        password=payload.password,
    )
    if user is None:
        audit_service.log_login_attempt(
            provider="password",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            user_identifier=payload.email,
        )
        return _error_response(
            status_code=401,
            detail="Invalid email or password.",
            code="invalid_credentials",
        )

    token_pair = token_service.issue_token_pair(user_id=str(user.id), email=user.email, scopes=[])
    try:
        await session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            scopes=[],
            raw_refresh_token=token_pair.refresh_token,
        )
    except SessionStateError as exc:
        audit_service.log_login_attempt(
            provider="password",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            user_id=str(user.id),
            user_identifier=user.email,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.log_login_attempt(
        provider="password",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=str(user.id),
        user_identifier=user.email,
    )
    audit_service.log_token_issuance(
        provider="password",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=str(user.id),
        user_identifier=user.email,
    )
    return TokenPairResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
    )


@router.post("/auth/token", response_model=TokenPairResponse)
async def refresh_token(
    payload: RefreshTokenRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> TokenPairResponse | JSONResponse:
    """Rotate refresh token and issue a new token pair."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    try:
        token_pair = await session_service.rotate_refresh_session(
            db_session=db_session,
            raw_refresh_token=payload.refresh_token,
            token_issuer=token_service.issue_token_pair,
        )
    except SessionStateError as exc:
        audit_service.log_token_refresh(
            provider="password",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            user_id=None,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.log_token_refresh(
        provider="password",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
    )
    audit_service.log_token_issuance(
        provider="password",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
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
    session_service: Annotated[SessionService, Depends(get_session_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> Response | JSONResponse:
    """Revoke session and blocklist current access token JTI."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    access_token = _extract_bearer_token(request)
    if access_token is None:
        audit_service.log_logout(
            provider="password",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            error_code="invalid_token",
        )
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = jwt_service.verify_token(access_token, expected_type="access")
    except TokenValidationError as exc:
        audit_service.log_logout(
            provider="password",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            error_code=exc.code,
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
        audit_service.log_logout(
            provider="password",
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            user_id=str(claims.get("sub", "")),
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    audit_service.log_logout(
        provider="password",
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=str(claims.get("sub", "")),
    )
    return Response(status_code=204)


@router.get("/.well-known/jwks.json")
async def jwks(
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> dict[str, list[dict[str, str]]]:
    """Return public JWKS for RS256 token verification."""
    return jwt_service.jwks()


@router.post("/auth/introspect")
async def introspect_api_key(
    request: Request,
    payload: APIKeyIntrospectRequest,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
    audit_service: Annotated[AuditService, Depends(get_audit_service)],
) -> JSONResponse:
    """Introspect opaque API key and return SDK contract payload."""
    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    client_ip = _extract_client_ip(request)
    result = await api_key_service.introspect(db_session=db_session, raw_key=payload.api_key)
    if not result.valid:
        audit_service.log_api_key_usage(
            ip_address=client_ip,
            correlation_id=correlation_id,
            success=False,
            error_code=result.code,
        )
        return JSONResponse(status_code=200, content={"valid": False, "code": result.code})
    audit_service.log_api_key_usage(
        ip_address=client_ip,
        correlation_id=correlation_id,
        success=True,
        user_id=result.user_id,
        key_id=result.key_id,
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
