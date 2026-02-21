"""Unit tests for JWT issuance and verification."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt as jose_jwt

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
    header, payload, signature = token.split(".")
    tampered_payload = ("a" if payload[0] != "a" else "b") + payload[1:]
    tampered = ".".join([header, tampered_payload, signature])

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


def _generate_keypair() -> tuple[str, str]:
    """Create a PEM-encoded RSA keypair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


def test_verify_token_supports_multi_key_verification_by_kid() -> None:
    """Verification selects matching public key by kid across multiple active keys."""
    private_1, public_1 = _generate_keypair()
    private_2, public_2 = _generate_keypair()
    jwt_service = JWTService(private_key_pem=private_1, public_key_pem=public_1)

    token_1 = jwt_service.issue_token(
        subject="user-1",
        token_type="access",
        expires_in_seconds=60,
        signing_private_key_pem=private_1,
        signing_kid="kid-1",
    )
    token_2 = jwt_service.issue_token(
        subject="user-2",
        token_type="access",
        expires_in_seconds=60,
        signing_private_key_pem=private_2,
        signing_kid="kid-2",
    )
    keys = {"kid-1": public_1, "kid-2": public_2}

    claims_1 = jwt_service.verify_token(token_1, expected_type="access", public_keys_by_kid=keys)
    claims_2 = jwt_service.verify_token(token_2, expected_type="access", public_keys_by_kid=keys)
    assert claims_1["sub"] == "user-1"
    assert claims_2["sub"] == "user-2"


def test_verify_token_rejects_missing_kid_when_keyset_provided() -> None:
    """Verification fails when token lacks kid while multi-key verification is required."""
    private_1, public_1 = _generate_keypair()
    jwt_service = JWTService(private_key_pem=private_1, public_key_pem=public_1)
    now = int(datetime.now(UTC).timestamp())
    token = jose_jwt.encode(
        {
            "jti": "jti-1",
            "iat": now,
            "exp": now + 60,
            "sub": "user-1",
            "type": "access",
        },
        private_1,
        algorithm="RS256",
    )

    with pytest.raises(TokenValidationError) as exc_info:
        jwt_service.verify_token(
            token,
            expected_type="access",
            public_keys_by_kid={"kid-1": public_1},
        )

    assert exc_info.value.code == "invalid_token"
