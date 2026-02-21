"""SDK exception hierarchy."""

from __future__ import annotations


class SDKError(Exception):
    """Base class for all SDK-specific exceptions."""


class AuthServiceUnavailableError(SDKError):
    """Raised when the auth service is temporarily unreachable."""


class AuthServiceResponseError(SDKError):
    """Raised when auth service returns malformed or unexpected data."""

    def __init__(self, detail: str, status_code: int | None = None) -> None:
        """Initialize with optional HTTP status code context."""
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class JWTVerificationError(SDKError):
    """Raised when JWT verification fails."""

    def __init__(self, detail: str, code: str) -> None:
        """Initialize with user-facing detail and machine-readable code."""
        super().__init__(detail)
        self.detail = detail
        self.code = code
