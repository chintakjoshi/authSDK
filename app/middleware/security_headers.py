"""Security headers middleware."""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Ensure every response carries mandatory security headers."""

    _HEADERS: dict[str, str] = {
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    }

    async def dispatch(self, request: Request, call_next) -> Response:
        """Append security headers to all application responses."""
        response = await call_next(request)
        for header_name, header_value in self._HEADERS.items():
            response.headers[header_name] = header_value
        return response
