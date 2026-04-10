"""Webhook endpoint registration and delivery orchestration."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID, uuid4

import httpx
import structlog
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Request
from redis import Redis
from rq import Queue
from rq_scheduler import Scheduler
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import get_settings, reloadable_singleton
from app.db.session import get_session_factory
from app.models.webhook_delivery import WebhookDelivery, WebhookDeliveryStatus
from app.models.webhook_endpoint import WebhookEndpoint
from app.services.audit_service import AuditService, get_audit_service
from app.services.pagination import CursorPage, apply_created_at_cursor, build_page, decode_cursor

logger = structlog.get_logger(__name__)

_RETRY_SCHEDULE_SECONDS = (60, 300, 1800, 7200)

ResolvedWebhookAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class WebhookSendResult:
    """Result payload from one outbound webhook attempt."""

    status_code: int | None
    body: str
    delivered: bool


@dataclass(frozen=True)
class RegisteredWebhookEndpoint:
    """Registered webhook endpoint payload."""

    id: UUID
    name: str
    url: str
    events: list[str]
    is_active: bool
    created_at: datetime


@dataclass(frozen=True)
class DeletedWebhookEndpoint:
    """Deleted webhook endpoint payload with abandoned-delivery metadata."""

    id: UUID
    abandoned_delivery_ids: list[UUID]


@dataclass(frozen=True)
class ResolvedWebhookTarget:
    """Pinned webhook target after safe hostname resolution."""

    url: str
    host_header: str
    sni_hostname: str | None


class WebhookServiceError(Exception):
    """Raised for webhook registration and retry API failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class WebhookUnsafeTargetError(Exception):
    """Raised when a webhook URL resolves to an unsafe delivery target."""


class WebhookSender(Protocol):
    """Protocol for outbound webhook delivery adapters."""

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        """Send one signed webhook payload."""


class WebhookQueueAdapter(Protocol):
    """Protocol for immediate job queueing."""

    def enqueue(self, func: str, *args: object, **kwargs: object) -> object:
        """Enqueue one job for immediate execution."""


class WebhookSchedulerAdapter(Protocol):
    """Protocol for delayed job scheduling."""

    def enqueue_at(
        self, scheduled_time: datetime, func: str, *args: object, **kwargs: object
    ) -> object:
        """Schedule one job for future execution."""


async def _resolve_host_ips(hostname: str) -> list[ResolvedWebhookAddress]:
    """Resolve hostname to IPs on a worker thread for SSRF checks."""
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, hostname, None)
    except OSError:
        return []

    resolved: list[ResolvedWebhookAddress] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            resolved.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return resolved


def _is_disallowed_ip(address: ipaddress._BaseAddress) -> bool:
    """Reject addresses that should never be used for outbound webhooks."""
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _host_header_value(url: httpx.URL) -> str:
    """Build the HTTP Host header for the original webhook authority."""
    host = url.host or ""
    host_text = f"[{host}]" if ":" in host else host
    if url.port is None:
        return host_text
    default_port = 443 if url.scheme == "https" else 80
    if url.port == default_port:
        return host_text
    return f"{host_text}:{url.port}"


async def _build_resolved_webhook_target(
    url: str,
    *,
    host_resolver: Callable[[str], Awaitable[list[ResolvedWebhookAddress]]],
    is_disallowed_ip: Callable[[ipaddress._BaseAddress], bool],
) -> ResolvedWebhookTarget | None:
    """Resolve a webhook URL to one pinned safe target address."""
    try:
        parsed_url = httpx.URL(url)
    except httpx.InvalidURL:
        return None

    if parsed_url.scheme not in {"http", "https"}:
        return None
    if parsed_url.host is None:
        return None

    original_host = parsed_url.host.strip().lower()
    if not original_host or original_host == "localhost":
        return None

    connect_host: str
    sni_hostname: str | None = None
    try:
        parsed_ip = ipaddress.ip_address(original_host)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if is_disallowed_ip(parsed_ip):
            return None
        connect_host = str(parsed_ip)
    else:
        resolved_ips = await host_resolver(original_host)
        if not resolved_ips or any(is_disallowed_ip(address) for address in resolved_ips):
            return None
        connect_host = str(resolved_ips[0])
        if parsed_url.scheme == "https":
            sni_hostname = original_host

    return ResolvedWebhookTarget(
        url=str(parsed_url.copy_with(host=connect_host)),
        host_header=_host_header_value(parsed_url),
        sni_hostname=sni_hostname,
    )


class HTTPXWebhookSender:
    """HTTP sender that signs and posts webhook payloads."""

    def __init__(self, timeout_seconds: int, response_body_max_chars: int) -> None:
        self._timeout_seconds = timeout_seconds
        self._response_body_max_chars = response_body_max_chars

    async def send(self, *, url: str, payload: dict[str, Any], secret: str) -> WebhookSendResult:
        """Send one JSON webhook request and capture truncated response details."""
        target = await self._resolve_target(url)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        signature = sign_payload(payload, secret)
        headers = {
            "Content-Type": "application/json",
            "Host": target.host_header,
            "X-Webhook-Signature": signature,
            "X-Webhook-Event": str(payload.get("event", "")),
        }
        extensions = (
            {"sni_hostname": target.sni_hostname} if target.sni_hostname is not None else None
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    target.url,
                    content=body,
                    headers=headers,
                    extensions=extensions,
                )
            truncated = response.text[: self._response_body_max_chars]
            return WebhookSendResult(
                status_code=response.status_code,
                body=truncated,
                delivered=200 <= response.status_code < 300,
            )
        except httpx.HTTPError as exc:
            return WebhookSendResult(
                status_code=None,
                body=str(exc)[: self._response_body_max_chars],
                delivered=False,
            )

    async def _resolve_target(self, url: str) -> ResolvedWebhookTarget:
        """Resolve webhook URL to one safe, pinned delivery target."""
        target = await _build_resolved_webhook_target(
            url,
            host_resolver=_resolve_host_ips,
            is_disallowed_ip=_is_disallowed_ip,
        )
        if target is None:
            raise WebhookUnsafeTargetError("Invalid webhook URL.")
        return target


def sign_payload(payload: dict[str, Any], secret: str) -> str:
    """Create the documented HMAC signature for one webhook payload."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    digest = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class WebhookService:
    """Manage webhook registration, event emission, and delivery retries."""

    _ENCRYPTION_PREFIX = "enc1:"
    _LEGACY_ENCRYPTION_PREFIXES = (bytes((118, 49, 58)).decode("ascii"),)

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        sender: WebhookSender,
        queue: WebhookQueueAdapter,
        scheduler: WebhookSchedulerAdapter,
        audit_service: AuditService,
        response_body_max_chars: int,
        secret_encryption_key: str | None,
        encryption_fallback_seed: str,
    ) -> None:
        self._session_factory = session_factory
        self._sender = sender
        self._queue = queue
        self._scheduler = scheduler
        self._audit_service = audit_service
        self._response_body_max_chars = response_body_max_chars
        self._fernet = Fernet(
            self._build_fernet_key(secret_encryption_key, encryption_fallback_seed)
        )

    async def register_endpoint(
        self,
        db_session: AsyncSession,
        *,
        name: str,
        url: str,
        secret: str,
        events: list[str] | None,
    ) -> RegisteredWebhookEndpoint:
        """Create one webhook endpoint after SSRF validation and secret encryption."""
        normalized_name = name.strip()
        normalized_url = url.strip()
        normalized_secret = secret.strip()
        if not normalized_name or not normalized_url or not normalized_secret:
            raise WebhookServiceError("Invalid webhook payload.", "invalid_credentials", 400)

        is_allowed = await self._is_safe_webhook_url(normalized_url)
        if not is_allowed:
            raise WebhookServiceError("Invalid webhook URL.", "invalid_webhook_url", 400)

        endpoint = WebhookEndpoint(
            name=normalized_name,
            url=normalized_url,
            secret=self._encrypt_secret(normalized_secret),
            events=sorted(set(events or [])),
            is_active=True,
        )
        db_session.add(endpoint)
        await db_session.flush()
        await db_session.commit()
        return RegisteredWebhookEndpoint(
            id=endpoint.id,
            name=endpoint.name,
            url=endpoint.url,
            events=list(endpoint.events),
            is_active=endpoint.is_active,
            created_at=endpoint.created_at,
        )

    async def list_endpoints(self, db_session: AsyncSession) -> list[WebhookEndpoint]:
        """List active and soft-deleted-filtered webhook endpoints."""
        statement = (
            select(WebhookEndpoint)
            .where(WebhookEndpoint.deleted_at.is_(None))
            .order_by(WebhookEndpoint.created_at.desc(), WebhookEndpoint.id.desc())
        )
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def get_endpoint(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
        for_update: bool = False,
    ) -> WebhookEndpoint:
        """Fetch one webhook endpoint or raise a stable not-found error."""
        statement = select(WebhookEndpoint).where(
            WebhookEndpoint.id == endpoint_id,
            WebhookEndpoint.deleted_at.is_(None),
        )
        if for_update:
            statement = statement.with_for_update()
        result = await db_session.execute(statement)
        endpoint = result.scalar_one_or_none()
        if endpoint is None:
            raise WebhookServiceError("Webhook endpoint not found.", "invalid_credentials", 404)
        return endpoint

    async def list_endpoints_page(
        self,
        db_session: AsyncSession,
        *,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[WebhookEndpoint]:
        """Return one cursor-paginated page of webhook endpoints."""
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = (
            select(WebhookEndpoint)
            .where(WebhookEndpoint.deleted_at.is_(None))
            .order_by(WebhookEndpoint.created_at.desc(), WebhookEndpoint.id.desc())
        )
        statement = apply_created_at_cursor(
            statement,
            model=WebhookEndpoint,
            cursor=cursor_position,
        ).limit(limit + 1)
        result = await db_session.execute(statement)
        return build_page(list(result.scalars().all()), limit=limit)

    async def update_endpoint(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
        name: str | None = None,
        url: str | None = None,
        events: list[str] | None = None,
        is_active: bool | None = None,
    ) -> WebhookEndpoint:
        """Update mutable webhook endpoint fields with SSRF revalidation."""
        endpoint = await self.get_endpoint(
            db_session=db_session,
            endpoint_id=endpoint_id,
            for_update=True,
        )

        if name is not None:
            normalized_name = name.strip()
            if not normalized_name:
                raise WebhookServiceError("Invalid webhook payload.", "invalid_credentials", 400)
            endpoint.name = normalized_name
        if url is not None:
            normalized_url = url.strip()
            if not normalized_url:
                raise WebhookServiceError("Invalid webhook payload.", "invalid_credentials", 400)
            is_allowed = await self._is_safe_webhook_url(normalized_url)
            if not is_allowed:
                raise WebhookServiceError("Invalid webhook URL.", "invalid_webhook_url", 400)
            endpoint.url = normalized_url
        if events is not None:
            endpoint.events = sorted(set(events))
        if is_active is not None:
            endpoint.is_active = is_active

        await db_session.flush()
        await db_session.commit()
        return endpoint

    async def delete_endpoint(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
    ) -> DeletedWebhookEndpoint:
        """Soft-delete a webhook endpoint and abandon pending deliveries."""
        endpoint = await self.get_endpoint(
            db_session=db_session,
            endpoint_id=endpoint_id,
            for_update=True,
        )
        endpoint.deleted_at = datetime.now(UTC)
        endpoint.is_active = False

        delivery_statement = (
            select(WebhookDelivery)
            .where(
                WebhookDelivery.endpoint_id == endpoint_id,
                WebhookDelivery.status == WebhookDeliveryStatus.PENDING.value,
            )
            .with_for_update()
        )
        deliveries = list((await db_session.execute(delivery_statement)).scalars().all())
        abandoned_delivery_ids: list[UUID] = []
        for delivery in deliveries:
            delivery.status = WebhookDeliveryStatus.ABANDONED.value
            delivery.next_retry_at = None
            abandoned_delivery_ids.append(delivery.id)

        await db_session.flush()
        await db_session.commit()
        return DeletedWebhookEndpoint(
            id=endpoint.id,
            abandoned_delivery_ids=abandoned_delivery_ids,
        )

    async def list_deliveries(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
        status: str | None = None,
    ) -> list[WebhookDelivery]:
        """List webhook deliveries for one endpoint."""
        statement = (
            select(WebhookDelivery)
            .where(WebhookDelivery.endpoint_id == endpoint_id)
            .order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id.desc())
        )
        if status is not None:
            statement = statement.where(WebhookDelivery.status == status)
        result = await db_session.execute(statement)
        return list(result.scalars().all())

    async def list_deliveries_page(
        self,
        db_session: AsyncSession,
        *,
        endpoint_id: UUID,
        status: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[WebhookDelivery]:
        """Return one cursor-paginated page of webhook deliveries."""
        limit = max(1, min(limit, 200))
        cursor_position = decode_cursor(cursor) if cursor is not None else None
        statement = (
            select(WebhookDelivery)
            .where(WebhookDelivery.endpoint_id == endpoint_id)
            .order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id.desc())
        )
        if status is not None:
            statement = statement.where(WebhookDelivery.status == status)
        statement = apply_created_at_cursor(
            statement,
            model=WebhookDelivery,
            cursor=cursor_position,
        ).limit(limit + 1)
        result = await db_session.execute(statement)
        return build_page(list(result.scalars().all()), limit=limit)

    async def retry_delivery(
        self, db_session: AsyncSession, *, delivery_id: UUID
    ) -> WebhookDelivery:
        """Reset one delivery for immediate retry and enqueue it."""
        statement = (
            select(WebhookDelivery).where(WebhookDelivery.id == delivery_id).with_for_update()
        )
        result = await db_session.execute(statement)
        delivery = result.scalar_one_or_none()
        if delivery is None:
            raise WebhookServiceError("Webhook delivery not found.", "invalid_credentials", 404)

        delivery.status = WebhookDeliveryStatus.PENDING.value
        delivery.attempt_count = 0
        delivery.next_retry_at = None
        delivery.last_attempted_at = None
        delivery.response_status = None
        delivery.response_body = None
        await db_session.flush()
        await db_session.commit()
        self._enqueue_delivery(delivery.id)
        return delivery

    async def emit_event(self, *, event_type: str, data: dict[str, Any]) -> None:
        """Create delivery rows and enqueue them after the source transaction has committed."""
        try:
            async with self._session_factory() as db_session:
                endpoints = await self._get_matching_endpoints(
                    db_session=db_session, event_type=event_type
                )
                if not endpoints:
                    return

                created_at = datetime.now(UTC)
                created_at_text = self._isoformat_z(created_at)
                delivery_ids: list[UUID] = []
                for endpoint in endpoints:
                    delivery_id = uuid4()
                    payload = {
                        "id": str(delivery_id),
                        "event": event_type,
                        "created_at": created_at_text,
                        "data": data,
                    }
                    db_session.add(
                        WebhookDelivery(
                            id=delivery_id,
                            endpoint_id=endpoint.id,
                            event_type=event_type,
                            payload=payload,
                            status=WebhookDeliveryStatus.PENDING.value,
                            attempt_count=0,
                            last_attempted_at=None,
                            next_retry_at=None,
                            response_status=None,
                            response_body=None,
                        )
                    )
                    delivery_ids.append(delivery_id)
                await db_session.commit()
        except Exception as exc:
            logger.error("webhook_emit_failed", event_type=event_type, error=str(exc))
            return

        for delivery_id in delivery_ids:
            try:
                self._enqueue_delivery(delivery_id)
            except Exception as exc:
                logger.error(
                    "webhook_enqueue_failed",
                    event_type=event_type,
                    delivery_id=str(delivery_id),
                    error=str(exc),
                )

    async def process_delivery(self, *, delivery_id: UUID) -> None:
        """Process one delivery idempotently, scheduling retry or abandonment as needed."""
        retry_at: datetime | None = None
        async with self._session_factory() as db_session:
            statement = (
                select(WebhookDelivery, WebhookEndpoint)
                .join(WebhookEndpoint, WebhookEndpoint.id == WebhookDelivery.endpoint_id)
                .where(WebhookDelivery.id == delivery_id)
                .with_for_update()
            )
            row = (await db_session.execute(statement)).one_or_none()
            if row is None:
                return
            delivery, endpoint = row

            if delivery.status in {
                WebhookDeliveryStatus.DELIVERED.value,
                WebhookDeliveryStatus.ABANDONED.value,
            }:
                return

            now = datetime.now(UTC)
            if delivery.next_retry_at is not None and delivery.next_retry_at > now:
                return

            if endpoint.deleted_at is not None or not endpoint.is_active:
                delivery.status = WebhookDeliveryStatus.ABANDONED.value
                delivery.next_retry_at = None
                await db_session.commit()
                return

            secret = self._decrypt_secret(endpoint.secret)
            try:
                send_result = await self._sender.send(
                    url=endpoint.url, payload=delivery.payload, secret=secret
                )
            except WebhookUnsafeTargetError:
                delivery.status = WebhookDeliveryStatus.ABANDONED.value
                delivery.next_retry_at = None
                await db_session.commit()
                await self._record_delivery_audit_event(
                    event_type="webhook.failed",
                    success=False,
                    failure_reason="invalid_webhook_url",
                    metadata={
                        "delivery_id": str(delivery.id),
                        "endpoint_id": str(endpoint.id),
                        "event_type": delivery.event_type,
                    },
                )
                return

            delivery.attempt_count += 1
            delivery.last_attempted_at = now
            delivery.response_status = send_result.status_code
            delivery.response_body = send_result.body[: self._response_body_max_chars]

            if send_result.delivered:
                delivery.status = WebhookDeliveryStatus.DELIVERED.value
                delivery.next_retry_at = None
                await db_session.commit()
                await self._record_delivery_audit_event(
                    event_type="webhook.delivered",
                    success=True,
                    metadata={
                        "delivery_id": str(delivery.id),
                        "endpoint_id": str(endpoint.id),
                        "event_type": delivery.event_type,
                        "response_status": send_result.status_code,
                    },
                )
                return

            if delivery.attempt_count >= 5:
                delivery.status = WebhookDeliveryStatus.ABANDONED.value
                delivery.next_retry_at = None
                await db_session.commit()
                await self._record_delivery_audit_event(
                    event_type="webhook.failed",
                    success=False,
                    failure_reason="delivery_abandoned",
                    metadata={
                        "delivery_id": str(delivery.id),
                        "endpoint_id": str(endpoint.id),
                        "event_type": delivery.event_type,
                        "attempt_count": delivery.attempt_count,
                        "response_status": send_result.status_code,
                    },
                )
                return

            retry_at = now + timedelta(seconds=_RETRY_SCHEDULE_SECONDS[delivery.attempt_count - 1])
            delivery.status = WebhookDeliveryStatus.FAILED.value
            delivery.next_retry_at = retry_at
            await db_session.commit()

        if retry_at is not None:
            try:
                self._schedule_delivery(delivery_id, retry_at)
            except Exception as exc:
                logger.error(
                    "webhook_retry_schedule_failed",
                    delivery_id=str(delivery_id),
                    retry_at=self._isoformat_z(retry_at),
                    error=str(exc),
                )

    async def _record_delivery_audit_event(
        self,
        *,
        event_type: str,
        success: bool,
        metadata: dict[str, Any],
        failure_reason: str | None = None,
    ) -> None:
        """Record worker-driven webhook audit events using a synthetic request."""
        async with self._session_factory() as db_session:
            await self._audit_service.record(
                db=db_session,
                event_type=event_type,
                actor_type="system",
                success=success,
                request=self._build_system_request(),
                failure_reason=failure_reason,
                metadata=metadata,
            )

    async def _get_matching_endpoints(
        self,
        *,
        db_session: AsyncSession,
        event_type: str,
    ) -> list[WebhookEndpoint]:
        """Return active endpoints subscribed to the provided event type."""
        statement = (
            select(WebhookEndpoint)
            .where(
                WebhookEndpoint.deleted_at.is_(None),
                WebhookEndpoint.is_active.is_(True),
            )
            .order_by(WebhookEndpoint.created_at.asc())
        )
        result = await db_session.execute(statement)
        endpoints = list(result.scalars().all())
        return [
            endpoint
            for endpoint in endpoints
            if not endpoint.events or event_type in endpoint.events
        ]

    def _enqueue_delivery(self, delivery_id: UUID) -> None:
        """Enqueue one delivery for immediate processing."""
        self._queue.enqueue("workers.webhook_worker.process_webhook_delivery", str(delivery_id))

    def _schedule_delivery(self, delivery_id: UUID, scheduled_time: datetime) -> None:
        """Schedule one delivery retry at the computed backoff time."""
        self._scheduler.enqueue_at(
            scheduled_time,
            "workers.webhook_worker.process_webhook_delivery",
            str(delivery_id),
        )

    async def _is_safe_webhook_url(self, url: str) -> bool:
        """Reject localhost and private-network webhook destinations."""
        return (
            await _build_resolved_webhook_target(
                url,
                host_resolver=self._resolve_host_ips,
                is_disallowed_ip=self._is_disallowed_ip,
            )
            is not None
        )

    @staticmethod
    async def _resolve_host_ips(
        hostname: str,
    ) -> list[ResolvedWebhookAddress]:
        """Resolve hostname to IPs on a worker thread for SSRF checks."""
        return await _resolve_host_ips(hostname)

    @staticmethod
    def _is_disallowed_ip(address: ipaddress._BaseAddress) -> bool:
        """Reject addresses that should never be used for outbound webhooks."""
        return _is_disallowed_ip(address)

    def _encrypt_secret(self, raw_secret: str) -> str:
        """Encrypt webhook secret before persistence."""
        encrypted = self._fernet.encrypt(raw_secret.encode("utf-8")).decode("utf-8")
        return f"{self._ENCRYPTION_PREFIX}{encrypted}"

    def _decrypt_secret(self, stored_secret: str) -> str:
        """Decrypt webhook secret, supporting plaintext fallback for local rows."""
        prefix = self._ENCRYPTION_PREFIX
        if not stored_secret.startswith(prefix):
            matched_legacy = next(
                (
                    item
                    for item in self._LEGACY_ENCRYPTION_PREFIXES
                    if stored_secret.startswith(item)
                ),
                None,
            )
            if matched_legacy is None:
                return stored_secret
            prefix = matched_legacy
        token = stored_secret[len(prefix) :]
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Unable to decrypt webhook secret.") from exc

    @staticmethod
    def _build_fernet_key(secret_encryption_key: str | None, fallback_seed: str) -> bytes:
        """Build a stable Fernet key from explicit or fallback seed material."""
        source = secret_encryption_key or fallback_seed
        digest = hashlib.sha256(source.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    @staticmethod
    def _isoformat_z(value: datetime) -> str:
        """Render UTC datetimes as RFC3339 strings with Z suffix."""
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _build_system_request() -> Request:
        """Create a synthetic request object for worker-emitted audit events."""
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/workers/webhook",
                "headers": [],
                "client": ("127.0.0.1", 0),
                "scheme": "http",
                "server": ("localhost", 0),
                "query_string": b"",
            }
        )


def _close_sync_redis_client(client: Redis) -> None:
    """Close a previous sync Redis client instance."""
    close = getattr(client, "close", None)
    if callable(close):
        close()
        return

    disconnect = getattr(getattr(client, "connection_pool", None), "disconnect", None)
    if callable(disconnect):
        disconnect()


@reloadable_singleton(cleanup=_close_sync_redis_client)
def get_webhook_redis_connection() -> Redis:
    """Create a sync Redis client for RQ queueing with connection health checks."""
    settings = get_settings()
    return Redis.from_url(
        settings.redis.url,
        decode_responses=False,
        socket_keepalive=True,
        health_check_interval=settings.webhook.redis_health_check_interval_seconds,
    )


@reloadable_singleton
def get_webhook_queue() -> Queue:
    """Create the RQ queue used for webhook processing."""
    settings = get_settings()
    return Queue(name=settings.webhook.queue_name, connection=get_webhook_redis_connection())


@reloadable_singleton
def get_webhook_scheduler() -> Scheduler:
    """Create the RQ scheduler used for delayed retries."""
    settings = get_settings()
    return Scheduler(
        queue_name=settings.webhook.queue_name, connection=get_webhook_redis_connection()
    )


@reloadable_singleton
def get_webhook_service() -> WebhookService:
    """Create and cache the webhook service dependency."""
    settings = get_settings()
    return WebhookService(
        session_factory=get_session_factory(),
        sender=HTTPXWebhookSender(
            timeout_seconds=settings.webhook.request_timeout_seconds,
            response_body_max_chars=settings.webhook.response_body_max_chars,
        ),
        queue=get_webhook_queue(),
        scheduler=get_webhook_scheduler(),
        audit_service=get_audit_service(),
        response_body_max_chars=settings.webhook.response_body_max_chars,
        secret_encryption_key=(
            settings.webhook.secret_encryption_key.get_secret_value()
            if settings.webhook.secret_encryption_key is not None
            else None
        ),
        encryption_fallback_seed=(
            settings.signing_keys.encryption_key.get_secret_value()
            if settings.signing_keys.encryption_key is not None
            else settings.jwt.private_key_pem.get_secret_value()
        ),
    )
