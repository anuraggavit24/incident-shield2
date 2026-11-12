"""Owner authentication, shared by the incident API and the payment app's reviewer endpoints."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from .config import get_settings, hash_api_key

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Owner API key (not the hash)")


def require_owner(x_api_key: str | None = Security(api_key_header)) -> None:
    expected = get_settings().owner_api_key_sha256
    if not x_api_key or not hmac.compare_digest(hash_api_key(x_api_key), expected):
        raise HTTPException(status_code=401, detail="invalid API key")
