"""JWT issuance, verification, and JWKS serialization."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any, Literal
from uuid import uuid4

from authlib.jose import JoseError, JsonWebToken
from authlib.jose.errors import ExpiredTokenError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from app.config import get_settings

TokenType = Literal["access", "refresh", "email_verify", "otp_challenge", "action_token", "m2m"]
JWT_ALGORITHM = "RS256"
Audience = str | list[str] | tuple[str, ...] | set[str]
RS256_JWT = JsonWebToken([JWT_ALGORITHM])
_REQUIRED_REGISTERED_CLAIMS = {
    "jti": {"essential": True},
    "iat": {"essential": True},
    "exp": {"essential": True},
    "sub": {"essential": True},
}


class TokenValidationError(Exception):
    """Raised when JWT validation fails."""

    def __init__(self, detail: str, code: str) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code


class JWTService:
    """Service for issuing and verifying RS256 JWT tokens."""

    def __init__(self, private_key_pem: str, public_key_pem: str) -> None:
        self._private_key_pem = private_key_pem
        self._public_key_pem = public_key_pem
        self._jwk = self._build_jwk(public_key_pem)

    def issue_token(
        self,
        subject: str,
        token_type: TokenType,
        expires_in_seconds: int,
        additional_claims: dict[str, Any] | None = None,
        audience: Audience | None = None,
        signing_private_key_pem: str | None = None,
        signing_kid: str | None = None,
    ) -> str:
        """Issue a signed JWT with required claims."""
        issued_at = datetime.now(UTC)
        expires_at = issued_at + timedelta(seconds=expires_in_seconds)
        payload = {
            "jti": str(uuid4()),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "sub": subject,
            "type": token_type,
        }
        normalized_audience = normalize_audiences(audience)
        if normalized_audience:
            payload["aud"] = audience_claim_value(normalized_audience)
        if additional_claims:
            for key, value in additional_claims.items():
                if key in payload:
                    continue
                payload[key] = value
        token = RS256_JWT.encode(
            {"alg": JWT_ALGORITHM, "kid": signing_kid or self._jwk["kid"]},
            payload,
            signing_private_key_pem or self._private_key_pem,
        )
        return token.decode("utf-8")

    def verify_token(
        self,
        token: str,
        expected_type: TokenType | None = None,
        public_keys_by_kid: dict[str, str] | None = None,
        expected_audience: Audience | None = None,
    ) -> dict[str, Any]:
        """Verify token signature and required claims."""
        try:
            header = decode_unverified_jwt_header(token)
        except ValueError as exc:
            raise TokenValidationError("Invalid token.", "invalid_token") from exc
        algorithm = str(header.get("alg", ""))
        if not hmac.compare_digest(algorithm, JWT_ALGORITHM):
            raise TokenValidationError("Invalid token algorithm.", "invalid_token")

        verification_key: str = self._public_key_pem
        if public_keys_by_kid is not None:
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid.strip():
                raise TokenValidationError("Invalid token.", "invalid_token")
            verification_key = public_keys_by_kid.get(kid, "")
            if not verification_key:
                raise TokenValidationError("Invalid token.", "invalid_token")

        normalized_expected_audience = normalize_audiences(expected_audience)
        try:
            claims = RS256_JWT.decode(
                token,
                verification_key,
                claims_options=_REQUIRED_REGISTERED_CLAIMS,
            )
            claims.validate()
            payload = dict(claims)
        except ExpiredTokenError as exc:
            raise TokenValidationError("Token has expired.", "token_expired") from exc
        except JoseError as exc:
            raise TokenValidationError("Invalid token.", "invalid_token") from exc

        token_type = str(payload.get("type", ""))
        if not self._is_supported_token_type(token_type):
            raise TokenValidationError("Invalid token type.", "invalid_token")
        if expected_type and not hmac.compare_digest(token_type, expected_type):
            raise TokenValidationError("Invalid token type.", "invalid_token")
        if normalized_expected_audience and not audience_matches(
            token_audience=payload.get("aud"),
            expected_audiences=normalized_expected_audience,
        ):
            raise TokenValidationError("Invalid token.", "invalid_token")
        return payload

    def jwks(
        self, public_keys_by_kid: dict[str, str] | None = None
    ) -> dict[str, list[dict[str, str]]]:
        """Return the public key in JWKS format."""
        if public_keys_by_kid is None:
            return {"keys": [self._jwk]}
        keys = [
            self.build_public_jwk(public_key_pem=public_key, kid=kid)
            for kid, public_key in sorted(public_keys_by_kid.items())
        ]
        return {"keys": keys}

    def _build_jwk(self, public_key_pem: str) -> dict[str, str]:
        """Build an RSA JWK document from a PEM encoded public key."""
        return self.build_public_jwk(public_key_pem=public_key_pem)

    @classmethod
    def build_public_jwk(cls, public_key_pem: str, kid: str | None = None) -> dict[str, str]:
        """Build RSA JWK document from a PEM encoded public key."""
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, RSAPublicKey):
            raise ValueError("JWT public key must be RSA.")

        public_numbers = key.public_numbers()
        n_value = cls._base64url_uint(public_numbers.n)
        e_value = cls._base64url_uint(public_numbers.e)
        key_id = kid or cls._calculate_kid(public_key_pem)
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": JWT_ALGORITHM,
            "kid": key_id,
            "n": n_value,
            "e": e_value,
        }

    def _is_supported_token_type(self, token_type: str) -> bool:
        """Check whether token type is one of the supported JWT classes."""
        return (
            hmac.compare_digest(token_type, "access")
            or hmac.compare_digest(token_type, "refresh")
            or hmac.compare_digest(token_type, "email_verify")
            or hmac.compare_digest(token_type, "otp_challenge")
            or hmac.compare_digest(token_type, "action_token")
            or hmac.compare_digest(token_type, "m2m")
        )

    @staticmethod
    def _base64url_uint(value: int) -> str:
        """Encode an integer to base64url without padding."""
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")

    @staticmethod
    def _calculate_kid(public_key_pem: str) -> str:
        """Derive a deterministic key ID from the public key."""
        digest = hashlib.sha256(public_key_pem.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")

    @classmethod
    def calculate_kid(cls, public_key_pem: str) -> str:
        """Public helper for deterministic key ID derivation."""
        return cls._calculate_kid(public_key_pem)


@lru_cache
def get_jwt_service() -> JWTService:
    """Build and cache the JWT service from application settings."""
    settings = get_settings()
    return JWTService(
        private_key_pem=settings.jwt.private_key_pem.get_secret_value(),
        public_key_pem=settings.jwt.public_key_pem.get_secret_value(),
    )


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


def normalize_audiences(value: object) -> list[str]:
    """Normalize JWT audience input/claims into an ordered list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        normalized = value.strip()
        return [normalized] if normalized else []
    if not isinstance(value, Iterable):
        return []

    audiences: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        audiences.append(normalized)
    return audiences


def merge_audiences(
    primary_audience: str, additional_audiences: Audience | None = None
) -> list[str]:
    """Return a de-duplicated audience list with the service audience first."""
    primary = primary_audience.strip()
    if not primary:
        raise ValueError("primary_audience must be non-empty.")
    return normalize_audiences([primary, *normalize_audiences(additional_audiences)])


def audience_claim_value(audiences: list[str]) -> str | list[str]:
    """Render a normalized audience list as a JWT aud claim value."""
    if len(audiences) == 1:
        return audiences[0]
    return list(audiences)


def audience_matches(token_audience: object, expected_audiences: Audience | None) -> bool:
    """Return True when token audiences contain every expected audience."""
    required = set(normalize_audiences(expected_audiences))
    if not required:
        return True
    available = set(normalize_audiences(token_audience))
    return required.issubset(available)
