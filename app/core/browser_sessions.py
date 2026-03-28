"""Helpers for browser-cookie session transport and CSRF validation."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from typing import Literal

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from app.config import get_settings

SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


@dataclass(frozen=True)
class BrowserSessionRuntimeSettings:
    """Resolved browser-session settings used at request time."""

    enabled: bool
    infer_cookie_transport: bool
    transport_header_name: str
    access_cookie_name: str
    refresh_cookie_name: str
    csrf_cookie_name: str
    same_site: Literal["lax", "strict", "none"]
    secure_only: bool
    cookie_domain: str | None
    access_cookie_path: str
    refresh_cookie_path: str
    csrf_cookie_path: str
    csrf_header_name: str


def _default_settings(*, enabled: bool) -> BrowserSessionRuntimeSettings:
    """Return a safe default config for runtime use and lightweight tests."""
    return BrowserSessionRuntimeSettings(
        enabled=enabled,
        infer_cookie_transport=True,
        transport_header_name="X-Auth-Session-Transport",
        access_cookie_name="__Host-auth_access",
        refresh_cookie_name="__Host-auth_refresh",
        csrf_cookie_name="__Host-auth_csrf",
        same_site="lax",
        secure_only=False,
        cookie_domain=None,
        access_cookie_path="/",
        refresh_cookie_path="/",
        csrf_cookie_path="/",
        csrf_header_name="X-CSRF-Token",
    )


def get_browser_session_settings() -> BrowserSessionRuntimeSettings:
    """Resolve browser-session settings with lightweight-test fallbacks."""
    try:
        settings = get_settings()
    except Exception:
        return _default_settings(enabled=True)

    browser_sessions = settings.browser_sessions
    return BrowserSessionRuntimeSettings(
        enabled=browser_sessions.enabled,
        infer_cookie_transport=browser_sessions.infer_cookie_transport,
        transport_header_name=browser_sessions.transport_header_name,
        access_cookie_name=browser_sessions.access_cookie_name,
        refresh_cookie_name=browser_sessions.refresh_cookie_name,
        csrf_cookie_name=browser_sessions.csrf_cookie_name,
        same_site=browser_sessions.same_site,
        secure_only=browser_sessions.secure_only,
        cookie_domain=browser_sessions.cookie_domain,
        access_cookie_path=browser_sessions.access_cookie_path,
        refresh_cookie_path=browser_sessions.refresh_cookie_path,
        csrf_cookie_path=browser_sessions.csrf_cookie_path,
        csrf_header_name=browser_sessions.csrf_header_name,
    )


def _requested_transport(request: Request) -> Literal["token", "cookie"] | None:
    """Resolve the explicit transport selector header when present."""
    settings = get_browser_session_settings()
    if not settings.enabled:
        return None
    header_value = request.headers.get(settings.transport_header_name, "").strip().lower()
    if hmac.compare_digest(header_value, "cookie"):
        return "cookie"
    if hmac.compare_digest(header_value, "token"):
        return "token"
    return None


def _has_browser_session_signal(request: Request) -> bool:
    """Return True when the request carries browser-session cookies or CSRF intent."""
    settings = get_browser_session_settings()
    if not settings.enabled or not settings.infer_cookie_transport:
        return False
    if request.cookies.get(settings.access_cookie_name, "").strip():
        return True
    if request.cookies.get(settings.refresh_cookie_name, "").strip():
        return True
    if request.cookies.get(settings.csrf_cookie_name, "").strip():
        return True
    if request.headers.get(settings.csrf_header_name, "").strip():
        return True
    return False


def is_cookie_transport_request(request: Request) -> bool:
    """Return True when the request should use cookie transport semantics."""
    explicit_transport = _requested_transport(request)
    if explicit_transport is not None:
        return explicit_transport == "cookie"
    return _has_browser_session_signal(request)


def extract_bearer_token(request: Request) -> str | None:
    """Extract bearer token from Authorization header."""
    authorization = request.headers.get("authorization", "").strip()
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if not hmac.compare_digest(scheme.lower(), "bearer"):
        return None
    stripped = token.strip()
    return stripped or None


def extract_access_token(request: Request) -> tuple[str | None, str | None]:
    """Resolve access token from bearer header first, then from configured cookie."""
    bearer_token = extract_bearer_token(request)
    if bearer_token is not None:
        return bearer_token, "authorization"

    settings = get_browser_session_settings()
    if not settings.enabled:
        return None, None

    cookie_token = request.cookies.get(settings.access_cookie_name, "").strip()
    if cookie_token:
        return cookie_token, "cookie"
    return None, None


def extract_refresh_token_from_cookie(request: Request) -> str | None:
    """Extract refresh token from configured browser-session cookie."""
    settings = get_browser_session_settings()
    if not settings.enabled:
        return None
    refresh_token = request.cookies.get(settings.refresh_cookie_name, "").strip()
    return refresh_token or None


def is_cookie_authenticated_request(request: Request) -> bool:
    """Return True when the current request authenticates through an access cookie."""
    _, auth_transport = extract_access_token(request)
    return auth_transport == "cookie"


def csrf_error_response() -> JSONResponse:
    """Build the standardized CSRF failure response."""
    return JSONResponse(
        status_code=403,
        content={"detail": "Invalid CSRF token.", "code": "invalid_csrf_token"},
    )


def validate_csrf_token(request: Request) -> bool:
    """Validate a double-submit CSRF token using configured cookie/header names."""
    settings = get_browser_session_settings()
    cookie_token = request.cookies.get(settings.csrf_cookie_name, "").strip()
    header_token = request.headers.get(settings.csrf_header_name, "").strip()
    if not cookie_token or not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)


def require_csrf_for_cookie_transport(request: Request) -> JSONResponse | None:
    """Require a CSRF token when the request explicitly uses cookie transport."""
    if request.method.upper() in SAFE_HTTP_METHODS:
        return None
    if not is_cookie_transport_request(request):
        return None
    if validate_csrf_token(request):
        return None
    return csrf_error_response()


def require_csrf_for_cookie_authenticated_request(request: Request) -> JSONResponse | None:
    """Require a CSRF token when the request is authenticated from an access cookie."""
    if request.method.upper() in SAFE_HTTP_METHODS:
        return None
    if not is_cookie_authenticated_request(request):
        return None
    if validate_csrf_token(request):
        return None
    return csrf_error_response()


def mint_csrf_token() -> str:
    """Mint a new random CSRF token."""
    return secrets.token_urlsafe(32)


def set_access_cookie(response: Response, access_token: str) -> None:
    """Set the browser-session access cookie on a response."""
    settings = get_browser_session_settings()
    response.set_cookie(
        key=settings.access_cookie_name,
        value=access_token,
        httponly=True,
        secure=settings.secure_only,
        samesite=settings.same_site,
        domain=settings.cookie_domain,
        path=settings.access_cookie_path,
    )


def set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Set the browser-session refresh cookie on a response."""
    settings = get_browser_session_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=refresh_token,
        httponly=True,
        secure=settings.secure_only,
        samesite=settings.same_site,
        domain=settings.cookie_domain,
        path=settings.refresh_cookie_path,
    )


def set_csrf_cookie(response: Response, csrf_token: str) -> None:
    """Set the browser-session CSRF cookie on a response."""
    settings = get_browser_session_settings()
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        httponly=False,
        secure=settings.secure_only,
        samesite=settings.same_site,
        domain=settings.cookie_domain,
        path=settings.csrf_cookie_path,
    )


def clear_auth_cookies(response: Response, *, clear_csrf: bool) -> None:
    """Delete browser-session cookies from the response."""
    settings = get_browser_session_settings()
    response.delete_cookie(
        key=settings.access_cookie_name,
        domain=settings.cookie_domain,
        path=settings.access_cookie_path,
    )
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        domain=settings.cookie_domain,
        path=settings.refresh_cookie_path,
    )
    if clear_csrf:
        response.delete_cookie(
            key=settings.csrf_cookie_name,
            domain=settings.cookie_domain,
            path=settings.csrf_cookie_path,
        )


def build_cookie_session_response(
    *,
    access_token: str,
    refresh_token: str,
    status_code: int = 200,
) -> JSONResponse:
    """Build the standard cookie-mode login/refresh response."""
    response = JSONResponse(
        status_code=status_code,
        content={"authenticated": True, "session_transport": "cookie"},
    )
    set_access_cookie(response, access_token)
    set_refresh_cookie(response, refresh_token)
    return response


def build_cookie_reauth_response(*, access_token: str, status_code: int = 200) -> JSONResponse:
    """Build the standard cookie-mode re-authentication response."""
    response = JSONResponse(
        status_code=status_code,
        content={"authenticated": True, "session_transport": "cookie"},
    )
    set_access_cookie(response, access_token)
    return response
