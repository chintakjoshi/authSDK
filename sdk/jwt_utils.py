"""Shared JWT helpers for SDK verification code."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from authlib.jose import JsonWebToken

JWT_ALGORITHM = "RS256"
RS256_JWT = JsonWebToken([JWT_ALGORITHM])
REQUIRED_REGISTERED_CLAIMS = {
    "jti": {"essential": True},
    "iat": {"essential": True},
    "exp": {"essential": True},
    "sub": {"essential": True},
}


def decode_unverified_jwt_header(token: str) -> dict[str, Any]:
    """Decode the compact JWT header without verifying the signature."""
    return _decode_unverified_jwt_segment(token, index=0, segment_name="header")


def decode_unverified_jwt_claims(token: str) -> dict[str, Any]:
    """Decode the compact JWT payload without verifying the signature."""
    return _decode_unverified_jwt_segment(token, index=1, segment_name="payload")


def _decode_unverified_jwt_segment(
    token: str,
    *,
    index: int,
    segment_name: str,
) -> dict[str, Any]:
    """Parse one compact JWT segment as a JSON object."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain exactly three segments.")

    segment = parts[index]
    if not segment:
        raise ValueError(f"JWT {segment_name} segment is empty.")

    padded_segment = segment + ("=" * (-len(segment) % 4))
    try:
        decoded_bytes = base64.urlsafe_b64decode(padded_segment.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"JWT {segment_name} segment is not valid base64url.") from exc

    try:
        value = json.loads(decoded_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"JWT {segment_name} segment is not valid JSON.") from exc

    if not isinstance(value, dict):
        raise ValueError(f"JWT {segment_name} segment must decode to a JSON object.")
    return value
