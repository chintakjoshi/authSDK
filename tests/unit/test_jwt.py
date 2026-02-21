"""Unit tests for JWT issuance and verification."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.jwt import JWTService, TokenValidationError


@pytest.fixture
def jwt_service() -> JWTService:
    """Build JWT service with an ephemeral RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return JWTService(private_key_pem=private_key_pem, public_key_pem=public_key_pem)


def test_issue_and_verify_access_token(jwt_service: JWTService) -> None:
    """Issued access token includes required claims and verifies successfully."""
    token = jwt_service.issue_token(subject="user-123", token_type="access", expires_in_seconds=60)
    payload = jwt_service.verify_token(token, expected_type="access")

    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"
    assert isinstance(payload["jti"], str)
    assert isinstance(payload["iat"], int)
    assert isinstance(payload["exp"], int)
    assert payload["exp"] > int(datetime.now(UTC).timestamp())


def test_verify_token_rejects_wrong_type(jwt_service: JWTService) -> None:
    """Token verification fails when expected token type does not match."""
    token = jwt_service.issue_token(subject="user-123", token_type="refresh", expires_in_seconds=60)

    with pytest.raises(TokenValidationError) as exc_info:
        jwt_service.verify_token(token, expected_type="access")

    assert exc_info.value.code == "invalid_token"


def test_verify_token_rejects_expired(jwt_service: JWTService) -> None:
    """Expired JWT fails with token_expired code."""
    token = jwt_service.issue_token(subject="user-123", token_type="access", expires_in_seconds=-1)

    with pytest.raises(TokenValidationError) as exc_info:
        jwt_service.verify_token(token, expected_type="access")

    assert exc_info.value.code == "token_expired"


def test_verify_token_rejects_tampered_token(jwt_service: JWTService) -> None:
    """Tampered token fails signature validation."""
    token = jwt_service.issue_token(subject="user-123", token_type="access", expires_in_seconds=60)
    tampered = token[:-1] + ("a" if token[-1] != "a" else "b")

    with pytest.raises(TokenValidationError) as exc_info:
        jwt_service.verify_token(tampered, expected_type="access")

    assert exc_info.value.code == "invalid_token"


def test_jwks_returns_rsa_public_key(jwt_service: JWTService) -> None:
    """JWKS endpoint payload includes one RS256 RSA signing key."""
    jwks = jwt_service.jwks()
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert key["n"]
    assert key["e"]
