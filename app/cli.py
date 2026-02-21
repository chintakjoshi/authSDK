"""CLI entrypoints for auth service operational tasks."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence

from app.config import get_settings
from app.core.signing_keys import get_signing_key_service
from app.db.session import get_session_factory


async def _run_rotate_signing_key(overlap_seconds: int | None) -> int:
    """Rotate signing keys and retire overlap-expired retiring keys."""
    settings = get_settings()
    effective_overlap = (
        overlap_seconds
        if overlap_seconds is not None
        else settings.signing_keys.rotation_overlap_seconds
    )
    signing_key_service = get_signing_key_service()
    session_factory = get_session_factory()

    async with session_factory() as db_session:
        result = await signing_key_service.rotate_signing_key(
            db_session=db_session,
            rotation_overlap_seconds=effective_overlap,
        )
        await db_session.commit()

    print(
        json.dumps(
            {
                "new_kid": result.new_kid,
                "retiring_kid": result.retiring_kid,
                "rotation_overlap_seconds": effective_overlap,
            }
        )
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for supported operational commands."""
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subcommands = parser.add_subparsers(dest="command", required=True)

    rotate_parser = subcommands.add_parser("rotate-signing-key")
    rotate_parser.add_argument(
        "--overlap-seconds",
        type=int,
        default=None,
        help="Optional override for ROTATION_OVERLAP_SECONDS during this run.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI command."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "rotate-signing-key":
        return asyncio.run(_run_rotate_signing_key(overlap_seconds=args.overlap_seconds))
    parser.error("Unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
