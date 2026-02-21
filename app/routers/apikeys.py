"""API key router placeholders."""

from fastapi import APIRouter

router = APIRouter(prefix="/auth/apikeys", tags=["apikeys"])
