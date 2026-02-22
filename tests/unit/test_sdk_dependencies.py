"""Unit tests for SDK FastAPI role dependencies."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from sdk.dependencies import get_current_user, require_role


def _build_app(user_payload: dict[str, object]) -> FastAPI:
    """Create app with get_current_user overridden by fixed payload."""
    app = FastAPI()
    app.dependency_overrides[get_current_user] = lambda: user_payload
    admin_dependency = Depends(require_role("admin"))

    @app.get("/admin")
    async def admin_only(user=admin_dependency):  # type: ignore[no-untyped-def]
        return {"user": user}

    return app


async def test_require_role_allows_matching_role() -> None:
    """Role dependency allows requests when role matches allowed set."""
    app = _build_app(
        {"type": "user", "user_id": "u-1", "email": "a@example.com", "role": "admin", "scopes": []}
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/admin")

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "admin"


async def test_require_role_rejects_non_matching_role() -> None:
    """Role dependency rejects requests when role is outside allowed set."""
    app = _build_app(
        {"type": "user", "user_id": "u-1", "email": "a@example.com", "role": "user", "scopes": []}
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/admin")

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient role"
