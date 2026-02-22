"""Global exception handlers enforcing API error response contracts."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

VALID_ERROR_CODES = {
    "invalid_token",
    "token_expired",
    "invalid_api_key",
    "expired_api_key",
    "revoked_api_key",
    "invalid_credentials",
    "rate_limited",
    "saml_assertion_invalid",
    "oauth_state_mismatch",
    "session_expired",
    "already_verified",
    "invalid_verify_token",
}

_DEFAULT_ERROR_CODE_BY_STATUS: dict[int, str] = {
    400: "invalid_credentials",
    401: "invalid_token",
    403: "invalid_token",
    404: "invalid_token",
    405: "invalid_token",
    422: "invalid_credentials",
    429: "rate_limited",
    503: "session_expired",
}

logger = structlog.get_logger(__name__)


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized JSON error payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


def _resolve_error_code(status_code: int, raw_code: str | None) -> str:
    """Resolve a valid machine-readable error code."""
    if raw_code in VALID_ERROR_CODES:
        return raw_code
    return _DEFAULT_ERROR_CODE_BY_STATUS.get(status_code, "invalid_token")


def _extract_detail_and_code(detail: Any) -> tuple[str, str | None]:
    """Normalize exception detail payload into message and optional code."""
    if isinstance(detail, dict):
        raw_detail = detail.get("detail", "Request failed.")
        raw_code = detail.get("code")
        return str(raw_detail), str(raw_code) if raw_code is not None else None
    if isinstance(detail, str):
        return detail, None
    return "Request failed.", None


def _sanitize_detail(detail: str, status_code: int, environment: str) -> str:
    """Hide internal failure details outside development."""
    if environment != "development" and status_code >= 500:
        return "Internal server error."
    return detail


def _extract_client_ip(request: Request) -> str:
    """Extract request client IP with forwarding-header support."""
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


def _extract_user_identifier(request: Request) -> tuple[str | None, str | None]:
    """Extract best-effort user identifiers from request state."""
    user_state = getattr(request.state, "user", None)
    if isinstance(user_state, dict):
        user_id = user_state.get("user_id")
        user_identifier = user_state.get("email") or user_id
        return str(user_id) if user_id else None, str(user_identifier) if user_identifier else None
    return None, None


def _is_auth_request_path(path: str) -> bool:
    """Return True for auth-related request paths."""
    return (
        path.startswith("/auth") or path.startswith("/apikeys") or path == "/.well-known/jwks.json"
    )


def _log_auth_failure(
    request: Request,
    status_code: int,
    detail: str,
    code: str,
) -> None:
    """Emit required WARNING-level log for auth failure responses."""
    if status_code < 400 or status_code >= 500:
        return
    if not _is_auth_request_path(request.url.path):
        return
    if code not in VALID_ERROR_CODES:
        return

    correlation_id = getattr(
        request.state,
        "correlation_id",
        request.headers.get("x-correlation-id", "unknown"),
    )
    user_id, user_identifier = _extract_user_identifier(request)
    logger.warning(
        "auth_failure",
        correlation_id=correlation_id,
        event_type="auth_failure",
        user_id=user_id,
        user_identifier=user_identifier,
        provider="unknown",
        ip_address=_extract_client_ip(request),
        success=False,
        status_code=status_code,
        code=code,
        detail=detail,
        path=request.url.path,
        method=request.method,
    )


def register_exception_handlers(app: FastAPI, environment: str) -> None:
    """Register global exception handlers enforcing error shape contract."""

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Normalize framework HTTP exceptions to contract payload."""
        raw_detail, raw_code = _extract_detail_and_code(exc.detail)
        code = _resolve_error_code(exc.status_code, raw_code)
        detail = raw_detail
        _log_auth_failure(request=request, status_code=exc.status_code, detail=detail, code=code)
        return _error_response(status_code=exc.status_code, detail=detail, code=code)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_exception(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Map request validation errors to standardized payload."""
        detail = "Invalid request payload."
        if environment == "development":
            errors = exc.errors()
            if errors:
                detail = f"Invalid request payload: {errors[0].get('msg', 'validation error')}."
        code = "invalid_credentials"
        _log_auth_failure(request=request, status_code=422, detail=detail, code=code)
        return _error_response(status_code=422, detail=detail, code=code)

    @app.exception_handler(Exception)
    async def handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
        """Mask internal errors and enforce contract payload."""
        correlation_id = getattr(
            request.state,
            "correlation_id",
            request.headers.get("x-correlation-id", "unknown"),
        )
        logger.error(
            "unhandled_exception",
            correlation_id=correlation_id,
            path=request.url.path,
            method=request.method,
            error=str(exc),
        )
        detail = _sanitize_detail(str(exc), 500, environment)
        return _error_response(status_code=500, detail=detail, code="invalid_token")
