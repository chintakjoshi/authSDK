"""Integration tests for v2 signing key rotation behavior."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import TokenValidationError, get_jwt_service
from app.core.signing_keys import get_signing_key_service
from app.models.signing_key import SigningKey, SigningKeyStatus


@pytest.mark.asyncio
async def test_signing_key_rotation_overlap_and_retirement(
    db_session: AsyncSession,
) -> None:
    """Rotation keeps old key valid during overlap and rejects it after retirement."""
    signing_key_service = get_signing_key_service()
    jwt_service = get_jwt_service()

    original_active = await signing_key_service.get_active_signing_key(db_session)
    old_token = jwt_service.issue_token(
        subject="user-1",
        token_type="access",
        expires_in_seconds=60,
        signing_private_key_pem=original_active.private_key_pem,
        signing_kid=original_active.kid,
    )

    rotation = await signing_key_service.rotate_signing_key(
        db_session=db_session,
        rotation_overlap_seconds=999999,
    )
    await db_session.commit()

    assert rotation.retiring_kid == original_active.kid
    assert rotation.new_kid != original_active.kid

    rows = list((await db_session.execute(select(SigningKey))).scalars().all())
    active_count = sum(1 for row in rows if row.status == SigningKeyStatus.ACTIVE)
    retiring_count = sum(1 for row in rows if row.status == SigningKeyStatus.RETIRING)
    assert active_count == 1
    assert retiring_count == 1

    overlap_keys = await signing_key_service.get_verification_public_keys(db_session)
    overlap_claims = jwt_service.verify_token(
        old_token,
        expected_type="access",
        public_keys_by_kid=overlap_keys,
    )
    assert overlap_claims["sub"] == "user-1"

    retired = await signing_key_service.retire_expired_keys(
        db_session=db_session,
        rotation_overlap_seconds=0,
    )
    await db_session.commit()
    assert original_active.kid in retired

    post_retirement_keys = await signing_key_service.get_verification_public_keys(db_session)
    assert original_active.kid not in post_retirement_keys
    with pytest.raises(TokenValidationError) as exc_info:
        jwt_service.verify_token(
            old_token,
            expected_type="access",
            public_keys_by_kid=post_retirement_keys,
        )
    assert exc_info.value.code == "invalid_token"
