"""Authentication routes."""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import JWTService, get_jwt_service
from app.dependencies import get_database_session
from app.schemas.token import TokenPairResponse
from app.schemas.user import LoginRequest
from app.services.token_service import TokenService, get_token_service
from app.services.user_service import UserService

router = APIRouter(tags=["auth"])
logger = structlog.get_logger(__name__)


def get_user_service() -> UserService:
    """Provide the user service dependency."""
    return UserService()


def _extract_client_ip(request: Request) -> str:
    """Extract client IP using forwarding headers when present."""
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


@router.post("/auth/login", response_model=TokenPairResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    user_service: Annotated[UserService, Depends(get_user_service)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
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
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid email or password.", "code": "invalid_credentials"},
        )

    token_pair = token_service.issue_token_pair(user_id=str(user.id))
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


@router.get("/.well-known/jwks.json")
async def jwks(
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)]
) -> dict[str, list[dict[str, str]]]:
    """Return public JWKS for RS256 token verification."""
    return jwt_service.jwks()
