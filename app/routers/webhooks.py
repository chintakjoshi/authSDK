"""Webhook endpoint registration and delivery inspection routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_database_session
from app.routers._admin_access import require_admin_claims
from app.schemas.webhook import (
    WebhookDeliveryResponse,
    WebhookEndpointCreateRequest,
    WebhookEndpointResponse,
    WebhookRetryResponse,
)
from app.services.admin_service import AdminService, AdminServiceError, get_admin_service
from app.services.webhook_service import (
    WebhookService,
    WebhookServiceError,
    get_webhook_service,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _error_response(status_code: int, detail: str, code: str) -> JSONResponse:
    """Build standardized API error response payload."""
    return JSONResponse(status_code=status_code, content={"detail": detail, "code": code})


@router.post("", response_model=WebhookEndpointResponse)
async def register_webhook(
    request: Request,
    payload: WebhookEndpointCreateRequest,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> WebhookEndpointResponse | JSONResponse:
    """Register one webhook endpoint for future auth-event deliveries."""
    try:
        await require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
    except AdminServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    try:
        endpoint = await webhook_service.register_endpoint(
            db_session=db_session,
            name=payload.name,
            url=str(payload.url),
            secret=payload.secret,
            events=payload.events,
        )
    except WebhookServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    return WebhookEndpointResponse(
        id=endpoint.id,
        name=endpoint.name,
        url=endpoint.url,
        events=endpoint.events,
        is_active=endpoint.is_active,
        created_at=endpoint.created_at,
    )


@router.get("", response_model=list[WebhookEndpointResponse])
async def list_webhooks(
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> list[WebhookEndpointResponse] | JSONResponse:
    """List registered webhook endpoints."""
    try:
        await require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
    except AdminServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    endpoints = await webhook_service.list_endpoints(db_session=db_session)
    return [
        WebhookEndpointResponse(
            id=endpoint.id,
            name=endpoint.name,
            url=endpoint.url,
            events=list(endpoint.events),
            is_active=endpoint.is_active,
            created_at=endpoint.created_at,
        )
        for endpoint in endpoints
    ]


@router.get("/{endpoint_id}/deliveries", response_model=list[WebhookDeliveryResponse])
async def list_webhook_deliveries(
    endpoint_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
    status: Annotated[str | None, Query()] = None,
) -> list[WebhookDeliveryResponse] | JSONResponse:
    """List deliveries for one webhook endpoint."""
    try:
        await require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
    except AdminServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    deliveries = await webhook_service.list_deliveries(
        db_session=db_session,
        endpoint_id=endpoint_id,
        status=status,
    )
    return [
        WebhookDeliveryResponse(
            id=delivery.id,
            endpoint_id=delivery.endpoint_id,
            event_type=delivery.event_type,
            status=delivery.status,
            attempt_count=delivery.attempt_count,
            last_attempted_at=delivery.last_attempted_at,
            next_retry_at=delivery.next_retry_at,
            response_status=delivery.response_status,
            response_body=delivery.response_body,
            created_at=delivery.created_at,
        )
        for delivery in deliveries
    ]


@router.post("/deliveries/{delivery_id}/retry", response_model=WebhookRetryResponse)
async def retry_webhook_delivery(
    delivery_id: UUID,
    request: Request,
    db_session: Annotated[AsyncSession, Depends(get_database_session)],
    admin_service: Annotated[AdminService, Depends(get_admin_service)],
    webhook_service: Annotated[WebhookService, Depends(get_webhook_service)],
) -> WebhookRetryResponse | JSONResponse:
    """Reset and requeue one delivery for immediate retry."""
    try:
        await require_admin_claims(
            request,
            db_session=db_session,
            admin_service=admin_service,
        )
    except AdminServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    try:
        delivery = await webhook_service.retry_delivery(
            db_session=db_session,
            delivery_id=delivery_id,
        )
    except WebhookServiceError as exc:
        return _error_response(status_code=exc.status_code, detail=exc.detail, code=exc.code)
    return WebhookRetryResponse(queued=True, delivery_id=delivery.id)
