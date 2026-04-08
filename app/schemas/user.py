"""User-facing auth request schemas."""

from typing import Annotated

from pydantic import BaseModel, EmailStr, Field

EmailAddress = Annotated[EmailStr, Field(max_length=320)]


class LoginRequest(BaseModel):
    """Password login request payload."""

    email: EmailAddress
    password: str = Field(min_length=8, max_length=256)
    audience: str | None = Field(default=None, min_length=1, max_length=255)
