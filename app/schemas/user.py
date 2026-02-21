"""User-facing auth request schemas."""

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Password login request payload."""

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=256)
