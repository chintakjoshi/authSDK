"""Authentication routes."""

from __future__ import annotations

import inspect
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import JWTService, TokenValidationError, get_jwt_service
from app.core.sessions import SessionService, SessionStateError, get_session_service
from app.core.signing_keys import SigningKeyService, get_signing_key_service
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


def _issue_token_pair(
    token_service: TokenService,
    db_session: AsyncSession,
    user_id: str,
    email: str | None = None,
    role: str | None = None,
    scopes: list[str] | None = None,
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
        return issue_method(**kwargs)
    kwargs: dict[str, object] = {"user_id": user_id, "email": email, "scopes": scopes}
    if signature and role is not None and "role" in signature.parameters:
        kwargs["role"] = role
    return issue_method(**kwargs)


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
    user = await user_service.authenticate_user(
        db_session=db_session,
        email=payload.email,
        password=payload.password,
    )
    if user is None:
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

    issued_pair = _issue_token_pair(
        token_service=token_service,
        db_session=db_session,
        user_id=str(user.id),
        email=user.email,
        role=getattr(user, "role", "user"),
        scopes=[],
    )
    token_pair = await issued_pair if inspect.isawaitable(issued_pair) else issued_pair
    try:
        session_id = await session_service.create_login_session(
            db_session=db_session,
            user_id=user.id,
            email=user.email,
            role=getattr(user, "role", "user"),
            scopes=[],
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
    try:

        async def _issue_pair(
            user_id: str,
            email: str | None = None,
            role: str | None = None,
            scopes: list[str] | None = None,
        ):
            issued = _issue_token_pair(
                token_service=token_service,
                db_session=db_session,
                user_id=user_id,
                email=email,
                role=role,
                scopes=scopes,
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
