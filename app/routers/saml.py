"""SAML router placeholders."""

from fastapi import APIRouter

router = APIRouter(prefix="/auth/saml", tags=["saml"])
