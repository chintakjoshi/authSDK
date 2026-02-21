"""JWKS cache manager for local JWT verification."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from sdk.client import AuthClient
from sdk.types import JWKS


class JWKSCacheManager:
    """Manage JWKS refresh and TTL-based reuse."""

    def __init__(
        self,
        auth_client: AuthClient,
        ttl_seconds: int = 300,
        now: Callable[[], float] | None = None,
    ) -> None:
        """Create cache manager with configurable TTL."""
        self._auth_client = auth_client
        self._ttl_seconds = ttl_seconds
        self._cached_jwks: JWKS | None = None
        self._expires_at = 0.0
        self._now = now or time.monotonic
        self._lock = asyncio.Lock()

    async def get_jwks(self, force_refresh: bool = False) -> JWKS:
        """Return cached JWKS or fetch a fresh copy when cache is stale."""
        if not force_refresh and self._cached_jwks is not None and self._now() < self._expires_at:
            return self._cached_jwks

        async with self._lock:
            if (
                not force_refresh
                and self._cached_jwks is not None
                and self._now() < self._expires_at
            ):
                return self._cached_jwks
            self._cached_jwks = await self._auth_client.fetch_jwks()
            self._expires_at = self._now() + self._ttl_seconds
            return self._cached_jwks
