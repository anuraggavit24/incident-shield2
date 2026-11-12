"""Who may do what.

- The OWNER key (OWNER_API_KEY_SHA256) can do everything: review, risk records, metrics, audit, reconcile.
- REVIEWER keys (REVIEWERS="asha:<sha256>,ravi:<sha256>") can work the review queue only. Each reviewer has
  their own key, so every release, decline and refund is recorded under a name.
Only hashes are configured; the keys themselves are never stored.
"""

from __future__ import annotations

import hmac
import os
import re

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from .config import get_settings, hash_api_key

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Owner or reviewer API key")
_NAME = re.compile(r"^[a-z0-9_]{2,24}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


def reviewers() -> dict[str, str]:
    """{name: sha256 hex} from the REVIEWERS variable. Malformed entries are ignored, never half-trusted."""
    out: dict[str, str] = {}
    for part in os.getenv("REVIEWERS", "").split(","):
        name, _, digest = part.strip().partition(":")
        name, digest = name.strip().lower(), digest.strip().lower()
        if _NAME.fullmatch(name) and _HASH.fullmatch(digest) and name != "owner":
            out[name] = digest
    return out


def _is_owner(key: str | None) -> bool:
    return bool(key) and hmac.compare_digest(hash_api_key(key or ""), get_settings().owner_api_key_sha256)


def require_owner(x_api_key: str | None = Security(api_key_header)) -> None:
    if not _is_owner(x_api_key):
        raise HTTPException(status_code=401, detail="invalid API key")


def require_reviewer(x_api_key: str | None = Security(api_key_header)) -> str:
    """Returns who is acting: "owner" or a reviewer's name."""
    if _is_owner(x_api_key):
        return "owner"
    if x_api_key:
        digest = hash_api_key(x_api_key)
        found = [name for name, expected in reviewers().items() if hmac.compare_digest(digest, expected)]
        if found:
            return found[0]
    raise HTTPException(status_code=401, detail="invalid API key")
