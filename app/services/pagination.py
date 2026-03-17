"""Reusable cursor-pagination helpers for admin-facing list endpoints."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy import Select, or_

T = TypeVar("T")


@dataclass(frozen=True)
class CursorPosition:
    """Decoded cursor position for created_at/id keyset pagination."""

    created_at: datetime
    row_id: UUID


@dataclass(frozen=True)
class CursorPage(Generic[T]):
    """One page of cursor-paginated results."""

    items: list[T]
    next_cursor: str | None
    has_more: bool


def encode_cursor(*, created_at: datetime, row_id: UUID) -> str:
    """Encode a cursor position as URL-safe base64 JSON."""
    payload = {
        "created_at": created_at.astimezone(UTC).isoformat(),
        "id": str(row_id),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_cursor(cursor: str) -> CursorPosition:
    """Decode a base64 cursor into its created_at/id position."""
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
        created_at = datetime.fromisoformat(str(payload["created_at"]))
        row_id = UUID(str(payload["id"]))
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid cursor.") from exc
    return CursorPosition(created_at=created_at, row_id=row_id)


def apply_created_at_cursor(
    statement: Select[tuple[T]],
    *,
    model: type[T],
    cursor: CursorPosition | None,
) -> Select[tuple[T]]:
    """Apply descending created_at/id keyset filtering to a SQLAlchemy select."""
    if cursor is None:
        return statement

    created_at_column = model.created_at
    id_column = model.id
    return statement.where(
        or_(
            created_at_column < cursor.created_at,
            (created_at_column == cursor.created_at) & (id_column < cursor.row_id),
        )
    )


def build_page(items: list[T], *, limit: int) -> CursorPage[T]:
    """Build one cursor page from a limit+1 result set."""
    has_more = len(items) > limit
    page_items = items[:limit]
    next_cursor = None
    if has_more and page_items:
        last_item = page_items[-1]
        next_cursor = encode_cursor(created_at=last_item.created_at, row_id=last_item.id)
    return CursorPage(items=page_items, next_cursor=next_cursor, has_more=has_more)
