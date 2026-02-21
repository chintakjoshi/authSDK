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

TokenType = Literal["access", "refresh"]
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
        return jwt.encode(
            payload,
            self._private_key_pem,
            algorithm=JWT_ALGORITHM,
            headers={"kid": self._jwk["kid"]},
        )

    def verify_token(self, token: str, expected_type: TokenType | None = None) -> dict[str, Any]:
        """Verify token signature and required claims."""
        header = jwt.get_unverified_header(token)
        algorithm = str(header.get("alg", ""))
        if not hmac.compare_digest(algorithm, JWT_ALGORITHM):
            raise TokenValidationError("Invalid token algorithm.", "invalid_token")

        try:
            payload = jwt.decode(
                token,
                self._public_key_pem,
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

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Return the public key in JWKS format."""
        return {"keys": [self._jwk]}

    def _build_jwk(self, public_key_pem: str) -> dict[str, str]:
        """Build an RSA JWK document from a PEM encoded public key."""
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, RSAPublicKey):
            raise ValueError("JWT public key must be RSA.")

        public_numbers = key.public_numbers()
        n_value = self._base64url_uint(public_numbers.n)
        e_value = self._base64url_uint(public_numbers.e)
        kid = self._calculate_kid(public_key_pem)
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": JWT_ALGORITHM,
            "kid": kid,
            "n": n_value,
            "e": e_value,
        }

    def _is_supported_token_type(self, token_type: str) -> bool:
        """Check whether the token type is a valid access or refresh value."""
        return hmac.compare_digest(token_type, "access") or hmac.compare_digest(
            token_type, "refresh"
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


@lru_cache
def get_jwt_service() -> JWTService:
    """Build and cache the JWT service from application settings."""
    settings = get_settings()
    return JWTService(
        private_key_pem=settings.jwt.private_key_pem.get_secret_value(),
        public_key_pem=settings.jwt.public_key_pem.get_secret_value(),
    )
