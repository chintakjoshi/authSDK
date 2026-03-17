"""Additional unit tests for JWT, OAuth, and SAML core helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jose import jwt as jose_jwt
from jose.exceptions import JWTError

from app.core.jwt import JWTService, TokenValidationError
from app.core.oauth import GoogleOAuthClient
from app.core.saml import SamlCore, SamlProtocolError


def _jwt_service() -> JWTService:
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
    return JWTService(private_key_pem=private_pem, public_key_pem=public_pem)


def test_jwt_service_covers_additional_claims_and_validation_edges(monkeypatch) -> None:
    """JWT helpers ignore reserved claims, reject invalid headers, and serialize multi-key JWKS."""
    jwt_service = _jwt_service()
    token = jwt_service.issue_token(
        subject="user-1",
        token_type="access",
        expires_in_seconds=60,
        additional_claims={"sub": "ignored", "custom": "ok"},
    )
    claims = jwt_service.verify_token(token, expected_type="access")
    assert claims["sub"] == "user-1"
    assert claims["custom"] == "ok"

    monkeypatch.setattr("app.core.jwt.jwt.get_unverified_header", lambda token: (_ for _ in ()).throw(JWTError("bad")))  # type: ignore[arg-type]
    with pytest.raises(TokenValidationError, match="Invalid token."):
        jwt_service.verify_token("bad-token")

    monkeypatch.setattr("app.core.jwt.jwt.get_unverified_header", lambda token: {"alg": "HS256"})  # type: ignore[arg-type]
    with pytest.raises(TokenValidationError, match="Invalid token algorithm"):
        jwt_service.verify_token("bad-token")
    monkeypatch.undo()

    invalid_type_token = jose_jwt.encode(
        {
            "jti": "jti-1",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "sub": "user-1",
            "type": "unsupported",
        },
        jwt_service._private_key_pem,
        algorithm="RS256",
        headers={"kid": jwt_service.jwks()["keys"][0]["kid"]},
    )
    with pytest.raises(TokenValidationError, match="Invalid token type"):
        jwt_service.verify_token(invalid_type_token)

    second_service = _jwt_service()
    jwks = jwt_service.jwks(
        {
            jwt_service.jwks()["keys"][0]["kid"]: jwt_service._public_key_pem,
            second_service.jwks()["keys"][0]["kid"]: second_service._public_key_pem,
        }
    )
    assert len(jwks["keys"]) == 2

    ec_key = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    with pytest.raises(ValueError, match="must be RSA"):
        JWTService.build_public_jwk(ec_key)


def test_oauth_core_generators_and_client_builder() -> None:
    """OAuth core generates random values and builds an authlib client with expected config."""
    client = GoogleOAuthClient(
        client_id="client-id",
        client_secret="client-secret",
        default_redirect_uri="https://service.local/callback",
        redirect_uri_allowlist=["https://service.local/callback"],
    )
    assert len(client.generate_state()) > 20
    assert len(client.generate_nonce()) > 20
    assert len(client.generate_code_verifier()) > 40
    built = client._build_client("https://service.local/callback")
    assert built.client_id == "client-id"
    assert built.redirect_uri == "https://service.local/callback"


def test_saml_core_metadata_and_nameid_fallback() -> None:
    """SAML core falls back to NameID email and maps metadata generation failures."""
    assert SamlCore._extract_email({}, "person@example.com") == "person@example.com"

    class _BrokenSettings:
        def get_sp_metadata(self) -> str:
            raise RuntimeError("boom")

    saml_core = SamlCore(settings_data={})
    saml_core._build_settings = lambda: _BrokenSettings()  # type: ignore[assignment]
    with pytest.raises(SamlProtocolError, match="metadata generation failed"):
        saml_core.metadata_xml()
