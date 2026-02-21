"""Token response schemas."""

from typing import Literal

from pydantic import BaseModel


class TokenPairResponse(BaseModel):
    """Access/refresh token response payload."""

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
