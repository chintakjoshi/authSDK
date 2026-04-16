"""User-facing auth request schemas."""

from pydantic import BaseModel, Field

from app.schemas.validation import AuthPassword, EmailAddress


class LoginRequest(BaseModel):
    """Password login request payload."""

    email: EmailAddress
    password: AuthPassword
    audience: str | None = Field(default=None, min_length=1, max_length=255)
