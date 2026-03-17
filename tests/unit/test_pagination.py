"""Unit tests for reusable cursor-pagination helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.services.pagination import build_page, decode_cursor, encode_cursor


@dataclass(frozen=True)
class _Row:
    """Minimal row shape for pagination tests."""

    id: object
    created_at: datetime


def test_encode_and_decode_cursor_round_trip() -> None:
    """Encoded cursors round-trip their created_at/id position."""
    created_at = datetime.now(UTC).replace(microsecond=0)
    row_id = uuid4()

    cursor = encode_cursor(created_at=created_at, row_id=row_id)
    decoded = decode_cursor(cursor)

    assert decoded.created_at == created_at
    assert decoded.row_id == row_id


def test_decode_cursor_rejects_invalid_payload() -> None:
    """Malformed cursors fail fast with a stable ValueError."""
    with pytest.raises(ValueError):
        decode_cursor("not-a-real-cursor")


def test_build_page_sets_next_cursor_when_more_items_exist() -> None:
    """Pages use the last returned item as the next cursor anchor."""
    now = datetime.now(UTC)
    rows = [
        _Row(id=uuid4(), created_at=now),
        _Row(id=uuid4(), created_at=now - timedelta(seconds=1)),
        _Row(id=uuid4(), created_at=now - timedelta(seconds=2)),
    ]

    page = build_page(rows, limit=2)

    assert len(page.items) == 2
    assert page.has_more is True
    assert page.next_cursor is not None
    decoded = decode_cursor(page.next_cursor)
    assert decoded.row_id == rows[1].id
