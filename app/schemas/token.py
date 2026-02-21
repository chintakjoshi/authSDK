"""Token response schemas."""

from typing import Literal

from pydantic import BaseModel, Field


class TokenPairResponse(BaseModel):
    """Access/refresh token response payload."""

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"


class RefreshTokenRequest(BaseModel):
    """Refresh token request payload."""

    refresh_token: str = Field(min_length=16)


class LogoutRequest(BaseModel):
    """Logout request payload."""

    refresh_token: str = Field(min_length=16)
