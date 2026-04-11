"""Redis-backed sliding-window rate limiting middleware."""

from __future__ import annotations

import asyncio
import json
import math
import time
from collections.abc import Callable
from typing import Protocol
from urllib.parse import parse_qs
from uuid import uuid4

import structlog
from fastapi import Request
from redis import asyncio as redis_async
from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings, reloadable_singleton
from app.core.browser_sessions import extract_access_token, extract_refresh_token_from_cookie
from app.core.client_ip import extract_client_ip
from app.core.jwt import (
    JWTService,
    TokenValidationError,
    decode_unverified_jwt_header,
    get_jwt_service,
)
from app.core.signing_keys import SigningKeyService, get_signing_key_service
from app.db.session import get_session_factory

logger = structlog.get_logger(__name__)
_WINDOW_SECONDS = 60
_VERIFICATION_KEY_CACHE_TTL_SECONDS = 30
_FAIL_CLOSED_EXACT_PATHS = {
    "/auth/login",
    "/auth/token",
}
_FAIL_CLOSED_PREFIXES = (
    "/auth/otp/",
    "/auth/password/",
    "/auth/verify-email",
    "/auth/reauth",
)


class SlidingWindowRedis(Protocol):
    """Protocol for Redis operations used by the rate limiter."""

    async def zremrangebyscore(self, key: str, min: str | int, max: int) -> int:
        """Delete members with score inside an inclusive range."""

    async def zcard(self, key: str) -> int:
        """Return sorted-set cardinality."""

    async def zrange(
        self,
        key: str,
        start: int,
        end: int,
        *,
        withscores: bool = False,
    ) -> list[tuple[str, float]] | list[str]:
        """Return a sorted-set slice ordered by score."""

    async def zadd(self, key: str, mapping: dict[str, int]) -> int:
        """Add one or more scored members to sorted set."""

    async def expire(self, key: str, ttl_seconds: int) -> bool:
        """Apply TTL to key."""


class RateLimitIdentityResolver(Protocol):
    """Resolve authenticated principals for rate-limit bucketing."""

    def requires_request_body(self, request: Request) -> bool:
        """Return True when identity resolution needs the buffered request body."""

    async def resolve_identity(self, request: Request, *, body: bytes | None = None) -> str | None:
        """Return a stable per-principal identity string when one is available."""


class VerificationKeyCache:
    """Load JWT verification keys with a short in-memory TTL for middleware use."""

    def __init__(
        self,
        *,
        signing_key_service: SigningKeyService,
        session_factory: async_sessionmaker[AsyncSession],
        fallback_public_key_pem: str,
        cache_ttl_seconds: int = _VERIFICATION_KEY_CACHE_TTL_SECONDS,
    ) -> None:
        self._signing_key_service = signing_key_service
        self._session_factory = session_factory
        self._cache_ttl_seconds = cache_ttl_seconds
        self._lock = asyncio.Lock()
        fallback_kid = JWTService.calculate_kid(fallback_public_key_pem)
        self._fallback_public_keys = {fallback_kid: fallback_public_key_pem}
        self._cached_public_keys: dict[str, str] = dict(self._fallback_public_keys)
        self._cache_expires_at = 0.0

    def fallback_public_keys(self) -> dict[str, str]:
        """Return the always-available env-backed fallback verification key set."""
        return dict(self._fallback_public_keys)

    def has_fallback_kid(self, kid: str | None) -> bool:
        """Return True when the requested key ID matches the env-backed fallback key."""
        if kid is None:
            return False
        return kid in self._fallback_public_keys

    async def get_public_keys(self, *, force_refresh: bool = False) -> dict[str, str]:
        """Return cached verification keys, reloading from the database when stale."""
        now = time.monotonic()
        if not force_refresh and now < self._cache_expires_at:
            return dict(self._cached_public_keys)

        async with self._lock:
            now = time.monotonic()
            if not force_refresh and now < self._cache_expires_at:
                return dict(self._cached_public_keys)

            public_keys = dict(self._fallback_public_keys)
            try:
                async with self._session_factory() as db_session:
                    public_keys.update(
                        await self._signing_key_service.get_verification_public_keys(db_session)
                    )
            except Exception as exc:  # pragma: no cover - exercised in integration/runtime paths.
                logger.warning(
                    "rate_limit_verification_keys_refresh_failed",
                    error=str(exc),
                )

            self._cached_public_keys = public_keys
            self._cache_expires_at = now + self._cache_ttl_seconds
            return dict(self._cached_public_keys)


class JWTPrincipalRateLimitIdentityResolver:
    """Resolve user and client identities from signed credentials when available."""

    def __init__(
        self,
        *,
        jwt_service_factory: Callable[[], JWTService],
        verification_key_cache: VerificationKeyCache,
        auth_service_audience: str,
    ) -> None:
        self._jwt_service_factory = jwt_service_factory
        self._jwt_service: JWTService | None = None
        self._verification_key_cache = verification_key_cache
        self._auth_service_audience = auth_service_audience

    def requires_request_body(self, request: Request) -> bool:
        """Refresh-token and client-credentials requests need body inspection."""
        return request.url.path == "/auth/token"

    async def resolve_identity(self, request: Request, *, body: bytes | None = None) -> str | None:
        """Resolve a stable authenticated principal for the current request."""
        if request.url.path == "/auth/token":
            token_identity = await self._resolve_token_endpoint_identity(request, body=body)
            if token_identity is not None:
                return token_identity

        access_identity = await self._resolve_access_token_identity(request)
        if access_identity is not None:
            return access_identity

        admin_api_key = request.headers.get("x-admin-api-key", "").strip()
        if admin_api_key:
            return "admin_bootstrap:" + self._hash_identifier(admin_api_key)
        return None

    async def _resolve_access_token_identity(self, request: Request) -> str | None:
        """Resolve a user identity from a verified bearer or access-cookie token."""
        access_token, _ = extract_access_token(request)
        if not access_token:
            return None

        claims = await self._verify_token(
            access_token,
            expected_type="access",
            expected_audience=self._auth_service_audience,
        )
        subject = self._extract_subject(claims)
        if subject is None:
            return None
        return f"user:{subject}"

    async def _resolve_token_endpoint_identity(
        self,
        request: Request,
        *,
        body: bytes | None,
    ) -> str | None:
        """Resolve a refresh-user or client-credentials identity on /auth/token."""
        request_body = body or b""
        client_id = self._extract_client_credentials_client_id(
            request_body=request_body,
            content_type=request.headers.get("content-type", ""),
        )
        if client_id is not None:
            return f"client:{client_id}"

        refresh_token = extract_refresh_token_from_cookie(request)
        if not refresh_token:
            refresh_token = self._extract_refresh_token_from_json_body(request_body)
        if not refresh_token:
            return None

        claims = await self._verify_token(
            refresh_token,
            expected_type="refresh",
            expected_audience=self._auth_service_audience,
        )
        subject = self._extract_subject(claims)
        if subject is None:
            return None
        return f"user:{subject}"

    async def _verify_token(
        self,
        token: str,
        *,
        expected_type: str,
        expected_audience: str,
    ) -> dict[str, object] | None:
        """Verify one JWT using cached signing keys and return claims on success."""
        jwt_service = self._get_jwt_service()
        if jwt_service is None:
            return None

        try:
            header = decode_unverified_jwt_header(token)
        except ValueError:
            return None

        kid = header.get("kid")
        resolved_kid = kid if isinstance(kid, str) and kid.strip() else None
        if self._verification_key_cache.has_fallback_kid(resolved_kid):
            verification_keys = self._verification_key_cache.fallback_public_keys()
        else:
            verification_keys = await self._verification_key_cache.get_public_keys()
            if resolved_kid is not None and resolved_kid not in verification_keys:
                verification_keys = await self._verification_key_cache.get_public_keys(
                    force_refresh=True
                )

        try:
            return jwt_service.verify_token(
                token,
                expected_type=expected_type,
                public_keys_by_kid=verification_keys,
                expected_audience=expected_audience,
            )
        except TokenValidationError:
            return None

    def _get_jwt_service(self) -> JWTService | None:
        """Return a lazily-constructed JWT service, tolerating placeholder test settings."""
        if self._jwt_service is not None:
            return self._jwt_service
        try:
            self._jwt_service = self._jwt_service_factory()
        except Exception:
            return None
        return self._jwt_service

    @staticmethod
    def _extract_subject(claims: dict[str, object] | None) -> str | None:
        """Extract a normalized JWT subject string from verified claims."""
        if claims is None:
            return None
        subject = claims.get("sub")
        if not isinstance(subject, str):
            return None
        normalized = subject.strip()
        return normalized or None

    @staticmethod
    def _extract_client_credentials_client_id(
        *,
        request_body: bytes,
        content_type: str,
    ) -> str | None:
        """Parse client_credentials client IDs from form-encoded token requests."""
        if "application/x-www-form-urlencoded" not in content_type.lower():
            return None
        try:
            form_data = parse_qs(request_body.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            return None

        grant_type_values = form_data.get("grant_type", [])
        if not grant_type_values or grant_type_values[0].strip() != "client_credentials":
            return None

        client_id_values = form_data.get("client_id", [])
        if not client_id_values:
            return None
        client_id = client_id_values[0].strip()
        return client_id or None

    @staticmethod
    def _extract_refresh_token_from_json_body(request_body: bytes) -> str | None:
        """Parse a refresh token from the JSON token endpoint request body."""
        if not request_body:
            return None
        try:
            payload = json.loads(request_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        refresh_token = payload.get("refresh_token")
        if not isinstance(refresh_token, str):
            return None
        normalized = refresh_token.strip()
        return normalized or None

    @staticmethod
    def _hash_identifier(value: str) -> str:
        """Hash a secret identifier before placing it in a shared Redis key."""
        import hashlib

        return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def _close_async_redis_client(client: Redis) -> None:
    """Close a previous async Redis client instance."""
    close = getattr(client, "aclose", None)
    if callable(close):
        await close()
        return

    close = getattr(client, "close", None)
    if callable(close):
        result = close()
        if hasattr(result, "__await__"):
            await result


@reloadable_singleton(cleanup=_close_async_redis_client)
def get_rate_limit_redis_client() -> Redis:
    """Create and cache Redis client used by rate limiter middleware."""
    settings = get_settings()
    return redis_async.from_url(
        settings.redis.url,
        decode_responses=True,
        socket_keepalive=True,
        health_check_interval=settings.redis.health_check_interval_seconds,
    )


@reloadable_singleton
def get_rate_limit_identity_resolver() -> JWTPrincipalRateLimitIdentityResolver:
    """Build the default authenticated-principal resolver for rate limiting."""
    settings = get_settings()
    fallback_public_key_pem = settings.jwt.public_key_pem.get_secret_value()
    verification_key_cache = VerificationKeyCache(
        signing_key_service=get_signing_key_service(),
        session_factory=get_session_factory(),
        fallback_public_key_pem=fallback_public_key_pem,
    )
    return JWTPrincipalRateLimitIdentityResolver(
        jwt_service_factory=get_jwt_service,
        verification_key_cache=verification_key_cache,
        auth_service_audience=settings.app.service,
    )


class RateLimitMiddleware:
    """Apply per-client sliding-window request limits as pure ASGI middleware."""

    def __init__(
        self,
        app: ASGIApp,
        redis_client: SlidingWindowRedis | None = None,
        identity_resolver: RateLimitIdentityResolver | None = None,
        default_requests_per_minute: int | None = None,
        login_requests_per_minute: int | None = None,
        token_requests_per_minute: int | None = None,
    ) -> None:
        """Initialize middleware with optional explicit limits for testability."""
        self.app = app
        settings = None
        if (
            redis_client is None
            or default_requests_per_minute is None
            or login_requests_per_minute is None
            or token_requests_per_minute is None
        ):
            settings = get_settings()

        self._redis = redis_client or get_rate_limit_redis_client()
        self._identity_resolver = identity_resolver or get_rate_limit_identity_resolver()
        if default_requests_per_minute is None:
            assert settings is not None
            self._default_limit = settings.rate_limit.default_requests_per_minute
        else:
            self._default_limit = default_requests_per_minute

        if login_requests_per_minute is None:
            assert settings is not None
            self._login_limit = settings.rate_limit.login_requests_per_minute
        else:
            self._login_limit = login_requests_per_minute

        if token_requests_per_minute is None:
            assert settings is not None
            self._token_limit = settings.rate_limit.token_requests_per_minute
        else:
            self._token_limit = token_requests_per_minute
        self._window_milliseconds = _WINDOW_SECONDS * 1000

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Reject requests exceeding the configured per-minute threshold."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body: bytes | None = None
        downstream_receive = receive
        initial_request = Request(scope, receive=receive)
        if self._identity_resolver.requires_request_body(initial_request):
            body = await self._read_request_body(receive)
            request = Request(scope, receive=self._build_replay_receive(body))
            downstream_receive = self._build_replay_receive(body)
        else:
            request = initial_request

        response = await self._evaluate_request(request, body=body)
        if response is not None:
            await response(scope, downstream_receive, send)
            return

        await self.app(scope, downstream_receive, send)

    async def _evaluate_request(
        self, request: Request, *, body: bytes | None = None
    ) -> Response | None:
        """Return an immediate response when a request must be rejected."""
        limit = self._resolve_limit(request.url.path)
        bucket_key = await self._build_bucket_key(request, body=body)
        now_ms = int(time.time() * 1000)
        window_start = now_ms - self._window_milliseconds

        try:
            await self._redis.zremrangebyscore(bucket_key, "-inf", window_start)
            current_count = await self._redis.zcard(bucket_key)
            if current_count >= limit:
                retry_after = await self._retry_after_seconds(bucket_key=bucket_key, now_ms=now_ms)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded.", "code": "rate_limited"},
                    headers={"Retry-After": str(retry_after)},
                )

            member = f"{now_ms}:{uuid4()}"
            await self._redis.zadd(bucket_key, {member: now_ms})
            await self._redis.expire(bucket_key, math.ceil(self._window_milliseconds / 1000) + 1)
        except RedisError:
            # Fail closed for sensitive auth routes, but keep non-sensitive traffic available.
            logger.warning(
                "rate_limit_backend_unavailable",
                path=request.url.path,
                method=request.method,
            )
            if self._should_fail_closed(request.url.path):
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": "Rate limit backend unavailable.",
                        "code": "rate_limit_unavailable",
                    },
                )
        return None

    async def _retry_after_seconds(self, *, bucket_key: str, now_ms: int) -> int:
        """Return the number of seconds until the oldest request leaves the window."""
        oldest_entries = await self._redis.zrange(bucket_key, 0, 0, withscores=True)
        if not oldest_entries:
            return 1

        _, oldest_score = oldest_entries[0]
        remaining_milliseconds = oldest_score + self._window_milliseconds - now_ms
        return max(1, math.ceil(remaining_milliseconds / 1000))

    def _resolve_limit(self, path: str) -> int:
        """Resolve path-specific limit override."""
        if path == "/auth/login":
            return self._login_limit
        if path == "/auth/token":
            return self._token_limit
        return self._default_limit

    async def _build_bucket_key(self, request: Request, *, body: bytes | None = None) -> str:
        """Build Redis key using the strongest available caller identity."""
        identity = await self._identity_resolver.resolve_identity(request, body=body)
        if identity is None:
            identity = f"ip:{self._extract_client_id(request)}"
        return f"rate_limit:{request.url.path}:{identity}"

    @staticmethod
    def _should_fail_closed(path: str) -> bool:
        """Return True when a Redis outage should block a sensitive auth route."""
        if path in _FAIL_CLOSED_EXACT_PATHS:
            return True
        return any(path.startswith(prefix) for prefix in _FAIL_CLOSED_PREFIXES)

    @staticmethod
    def _extract_client_id(request: Request) -> str:
        """Resolve caller identity for per-client bucketing."""
        return extract_client_ip(request) or "unknown"

    @staticmethod
    async def _read_request_body(receive: Receive) -> bytes:
        """Drain the request body from the ASGI channel so it can be replayed downstream."""
        body_chunks: list[bytes] = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] != "http.request":
                continue
            body_chunks.append(message.get("body", b""))
            more_body = message.get("more_body", False)
        return b"".join(body_chunks)

    @staticmethod
    def _build_replay_receive(body: bytes) -> Receive:
        """Create a receive callable that replays a buffered request body once."""
        emitted = False

        async def replay_receive() -> dict[str, object]:
            nonlocal emitted
            if emitted:
                return {"type": "http.request", "body": b"", "more_body": False}
            emitted = True
            return {"type": "http.request", "body": body, "more_body": False}

        return replay_receive
