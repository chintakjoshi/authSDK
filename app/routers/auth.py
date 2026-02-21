"""Authentication routes."""

from __future__ import annotations

from typing import Annotated

import structlog
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
from app.services.token_service import TokenService, get_token_service
from app.services.user_service import UserService

router = APIRouter(tags=["auth"])
logger = structlog.get_logger(__name__)


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
) -> TokenPairResponse | JSONResponse:
    """Authenticate email/password credentials and issue JWT pair."""
    correlation_id = request.headers.get("x-correlation-id", "unknown")
    client_ip = _extract_client_ip(request)
    user = await user_service.authenticate_user(
        db_session=db_session,
        email=payload.email,
        password=payload.password,
    )
    if user is None:
        logger.warning(
            "login_attempt",
            correlation_id=correlation_id,
            event_type="login_attempt",
            user_id=None,
            user_identifier=payload.email,
            provider="password",
            ip_address=client_ip,
            success=False,
        )
        return _error_response(
            status_code=401,
            detail="Invalid email or password.",
            code="invalid_credentials",
        )

    token_pair = token_service.issue_token_pair(user_id=str(user.id))
    try:
        await session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            scopes=[],
            raw_refresh_token=token_pair.refresh_token,
        )
    except SessionStateError as exc:
        logger.warning(
            "session_create_failed",
            correlation_id=correlation_id,
            event_type="session_create",
            user_id=str(user.id),
            user_identifier=user.email,
            provider="password",
            ip_address=client_ip,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    logger.info(
        "login_attempt",
        correlation_id=correlation_id,
        event_type="login_attempt",
        user_id=str(user.id),
        user_identifier=user.email,
        provider="password",
        ip_address=client_ip,
        success=True,
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
) -> TokenPairResponse | JSONResponse:
    """Rotate refresh token and issue a new token pair."""
    correlation_id = request.headers.get("x-correlation-id", "unknown")
    client_ip = _extract_client_ip(request)
    try:
        token_pair = await session_service.rotate_refresh_session(
            db_session=db_session,
            raw_refresh_token=payload.refresh_token,
            token_issuer=token_service.issue_token_pair,
        )
    except SessionStateError as exc:
        logger.warning(
            "token_refresh",
            correlation_id=correlation_id,
            event_type="token_refresh",
            user_id=None,
            provider="password",
            ip_address=client_ip,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    logger.info(
        "token_refresh",
        correlation_id=correlation_id,
        event_type="token_refresh",
        user_id=None,
        provider="password",
        ip_address=client_ip,
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
) -> Response | JSONResponse:
    """Revoke session and blocklist current access token JTI."""
    correlation_id = request.headers.get("x-correlation-id", "unknown")
    client_ip = _extract_client_ip(request)
    access_token = _extract_bearer_token(request)
    if access_token is None:
        return _error_response(status_code=401, detail="Invalid token.", code="invalid_token")

    try:
        claims = jwt_service.verify_token(access_token, expected_type="access")
    except TokenValidationError as exc:
        return _error_response(status_code=401, detail=exc.detail, code=exc.code)

    try:
        await session_service.revoke_session(
            db_session=db_session,
            raw_refresh_token=payload.refresh_token,
            access_jti=str(claims["jti"]),
            access_expiration_epoch=int(claims["exp"]),
        )
    except SessionStateError as exc:
        logger.warning(
            "logout",
            correlation_id=correlation_id,
            event_type="logout",
            user_id=str(claims.get("sub", "")),
            provider="password",
            ip_address=client_ip,
            success=False,
            error_code=exc.code,
        )
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)

    logger.info(
        "logout",
        correlation_id=correlation_id,
        event_type="logout",
        user_id=str(claims.get("sub", "")),
        provider="password",
        ip_address=client_ip,
        success=True,
    )
    return Response(status_code=204)


@router.get("/.well-known/jwks.json")
async def jwks(
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)]
) -> dict[str, list[dict[str, str]]]:
    """Return public JWKS for RS256 token verification."""
    return jwt_service.jwks()


@router.post("/auth/introspect")
async def introspect_api_key(
    payload: APIKeyIntrospectRequest,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    api_key_service: Annotated[APIKeyService, Depends(get_api_key_service)],
) -> JSONResponse:
    """Introspect opaque API key and return SDK contract payload."""
    result = await api_key_service.introspect(db_session=db_session, raw_key=payload.api_key)
    if not result.valid:
        return JSONResponse(status_code=200, content={"valid": False, "code": result.code})
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
