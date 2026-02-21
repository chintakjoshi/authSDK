"""SAML 2.0 protocol operations via python3-saml."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from fastapi import Request

from app.config import get_settings

HTTP_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


@dataclass(frozen=True)
class SamlAssertion:
    """Normalized identity extracted from a validated SAML assertion."""

    provider_user_id: str
    email: str


class SamlProtocolError(Exception):
    """Raised for SAML protocol and assertion validation failures."""

    def __init__(self, detail: str, code: str, status_code: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.code = code
        self.status_code = status_code


class SamlCore:
    """SAML protocol wrapper around python3-saml."""

    def __init__(self, settings_data: dict[str, Any]) -> None:
        self._settings_data = settings_data

    def login_url(self, request_data: dict[str, Any], relay_state: str | None) -> str:
        """Create IdP redirect URL for SAML login."""
        auth = self._build_auth(request_data=request_data)
        try:
            return auth.login(return_to=relay_state)
        except Exception as exc:
            raise SamlProtocolError(
                "SAML login initiation failed.", "saml_assertion_invalid", 400
            ) from exc

    def parse_assertion(self, request_data: dict[str, Any]) -> SamlAssertion:
        """Validate SAML response and extract identity claims."""
        auth = self._build_auth(request_data=request_data)
        try:
            auth.process_response()
        except Exception as exc:
            raise SamlProtocolError(
                "SAML assertion invalid.", "saml_assertion_invalid", 401
            ) from exc

        errors = auth.get_errors()
        if errors or not auth.is_authenticated():
            raise SamlProtocolError("SAML assertion invalid.", "saml_assertion_invalid", 401)

        provider_user_id = str(auth.get_nameid() or "").strip()
        email = self._extract_email(auth.get_attributes(), provider_user_id)
        if not provider_user_id or not email:
            raise SamlProtocolError("SAML assertion invalid.", "saml_assertion_invalid", 401)
        return SamlAssertion(provider_user_id=provider_user_id, email=email)

    def metadata_xml(self) -> str:
        """Generate SP metadata from current SAML configuration."""
        settings = self._build_settings()
        try:
            metadata = settings.get_sp_metadata()
            errors = settings.validate_metadata(metadata)
        except Exception as exc:
            raise SamlProtocolError(
                "SAML metadata generation failed.", "saml_assertion_invalid", 500
            ) from exc
        if errors:
            raise SamlProtocolError(
                "SAML metadata generation failed.", "saml_assertion_invalid", 500
            )
        return metadata

    def _build_auth(self, request_data: dict[str, Any]) -> Any:
        """Instantiate python3-saml auth object."""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
        except ImportError as exc:
            raise SamlProtocolError(
                "SAML backend unavailable.", "saml_assertion_invalid", 503
            ) from exc
        return OneLogin_Saml2_Auth(request_data, old_settings=self._settings_data)

    def _build_settings(self) -> Any:
        """Instantiate python3-saml settings object."""
        try:
            from onelogin.saml2.settings import OneLogin_Saml2_Settings
        except ImportError as exc:
            raise SamlProtocolError(
                "SAML backend unavailable.", "saml_assertion_invalid", 503
            ) from exc
        return OneLogin_Saml2_Settings(settings=self._settings_data)

    @staticmethod
    def _extract_email(attributes: dict[str, list[str]], name_id: str) -> str:
        """Extract email value from known attribute claims."""
        candidate_keys = (
            "email",
            "mail",
            "Email",
            "EmailAddress",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        )
        for key in candidate_keys:
            values = attributes.get(key, [])
            if values:
                candidate = str(values[0]).strip()
                if candidate:
                    return candidate
        if "@" in name_id:
            return name_id
        return ""


def build_saml_request_data(
    request: Request,
    get_data: dict[str, str] | None = None,
    post_data: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Convert FastAPI request to python3-saml request context format."""
    scheme = request.url.scheme
    host = request.headers.get("host", "")
    port = request.url.port
    if port is None:
        port = 443 if scheme == "https" else 80

    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "server_port": str(port),
        "script_name": request.url.path,
        "get_data": get_data or {},
        "post_data": post_data or {},
        "query_string": request.url.query,
    }


def _build_saml_settings_from_config() -> dict[str, Any]:
    """Build python3-saml settings structure from app config."""
    settings = get_settings()
    return {
        "strict": True,
        "debug": settings.app.environment == "development",
        "sp": {
            "entityId": settings.saml.sp_entity_id,
            "assertionConsumerService": {
                "url": str(settings.saml.sp_acs_url),
                "binding": HTTP_POST_BINDING,
            },
            "x509cert": settings.saml.sp_x509_cert.get_secret_value(),
            "privateKey": settings.saml.sp_private_key.get_secret_value(),
        },
        "idp": {
            "entityId": settings.saml.idp_entity_id,
            "singleSignOnService": {
                "url": str(settings.saml.idp_sso_url),
                "binding": HTTP_REDIRECT_BINDING,
            },
            "x509cert": settings.saml.idp_x509_cert.get_secret_value(),
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": True,
            "wantNameId": True,
            "wantXMLValidation": True,
            "wantAttributeStatement": True,
            "rejectUnsolicitedResponsesWithInResponseTo": False,
        },
    }


@lru_cache
def get_saml_core() -> SamlCore:
    """Create and cache SAML core dependency."""
    return SamlCore(settings_data=_build_saml_settings_from_config())
