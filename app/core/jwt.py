"""JWT issuance, verification, and JWKS serialization."""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any, Literal
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from app.config import get_settings

TokenType = Literal["access", "refresh", "email_verify"]
JWT_ALGORITHM = "RS256"


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
        if additional_claims:
            for key, value in additional_claims.items():
                if key in payload:
                    continue
                payload[key] = value
        return jwt.encode(
            payload,
            signing_private_key_pem or self._private_key_pem,
            algorithm=JWT_ALGORITHM,
            headers={"kid": signing_kid or self._jwk["kid"]},
        )

    def verify_token(
        self,
        token: str,
        expected_type: TokenType | None = None,
        public_keys_by_kid: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Verify token signature and required claims."""
        header = jwt.get_unverified_header(token)
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

        try:
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[JWT_ALGORITHM],
                options={
                    "verify_aud": False,
                    "require_jti": True,
                    "require_iat": True,
                    "require_exp": True,
                    "require_sub": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise TokenValidationError("Token has expired.", "token_expired") from exc
        except JWTError as exc:
            raise TokenValidationError("Invalid token.", "invalid_token") from exc

        token_type = str(payload.get("type", ""))
        if not self._is_supported_token_type(token_type):
            raise TokenValidationError("Invalid token type.", "invalid_token")
        if expected_type and not hmac.compare_digest(token_type, expected_type):
            raise TokenValidationError("Invalid token type.", "invalid_token")
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
        """Check whether token type is one of the supported v2 JWT classes."""
        return (
            hmac.compare_digest(token_type, "access")
            or hmac.compare_digest(token_type, "refresh")
            or hmac.compare_digest(token_type, "email_verify")
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
