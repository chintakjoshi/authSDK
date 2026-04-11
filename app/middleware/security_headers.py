"""Security headers middleware."""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class SecurityHeadersMiddleware:
    """Ensure every response carries mandatory security headers."""

    _NO_STORE_EXACT_PATHS = frozenset(
        {
            "/auth/csrf",
            "/auth/login",
            "/auth/token",
            "/auth/logout",
            "/auth/reauth",
            "/auth/otp/verify/login",
            "/auth/otp/verify/action",
            "/auth/oauth/google/callback",
            "/auth/saml/callback",
        }
    )
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
        if path in cls._NO_STORE_EXACT_PATHS:
            headers["Cache-Control"] = "no-store"
            headers["Pragma"] = "no-cache"
        return headers

    def __init__(self, app: ASGIApp) -> None:
        """Initialize middleware with the downstream ASGI application."""
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Append security headers to all application responses."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_headers = self._headers_for_path(scope["path"])

        async def send_with_security_headers(message: Message) -> None:
            """Inject mandatory security headers into the response start event."""
            if message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message["headers"])
                for header_name, header_value in response_headers.items():
                    headers[header_name] = header_value
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
