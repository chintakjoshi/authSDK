"""Security headers middleware."""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Ensure every response carries mandatory security headers."""

    _DEFAULT_CONTENT_SECURITY_POLICY = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    _DOCS_CONTENT_SECURITY_POLICY = (
        "default-src 'none'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self'"
    )
    _COMMON_HEADERS: dict[str, str] = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    }

    @classmethod
    def _headers_for_path(cls, path: str) -> dict[str, str]:
        """Return security headers for the current request path."""
        headers = dict(cls._COMMON_HEADERS)
        headers["Content-Security-Policy"] = (
            cls._DOCS_CONTENT_SECURITY_POLICY
            if path.startswith("/docs")
            else cls._DEFAULT_CONTENT_SECURITY_POLICY
        )
        return headers

    async def dispatch(self, request: Request, call_next) -> Response:
        """Append security headers to all application responses."""
        response = await call_next(request)
        for header_name, header_value in self._headers_for_path(request.url.path).items():
            response.headers[header_name] = header_value
        return response
