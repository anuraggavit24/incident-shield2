"""Who may do what.

- The OWNER key (OWNER_API_KEY_SHA256) can do everything: review, risk records, metrics, audit, reconcile.
- REVIEWER keys (REVIEWERS="asha:<sha256>:2026-12-31,ravi:<sha256>") can work the review queue only. Each
  reviewer has their own key, so every release, decline and refund is recorded under a name. The optional
  third part is the last day the key works (UTC); after it the key is refused.
Only hashes are configured; the keys themselves are never stored.
"""

from __future__ import annotations

import hmac
import os
import re
from datetime import date, datetime, timezone

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from .config import get_settings, hash_api_key

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Owner or reviewer API key")
_NAME = re.compile(r"^[a-z0-9_]{2,24}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


def today() -> date:
    return datetime.now(timezone.utc).date()


def reviewers() -> dict[str, str]:
    """{name: sha256 hex} for keys that work today. Malformed or expired entries are ignored, never
    half-trusted: an unreadable expiry date means the key is refused, not that it never expires."""
    out: dict[str, str] = {}
    for part in os.getenv("REVIEWERS", "").split(","):
        fields = [f.strip().lower() for f in part.strip().split(":")]
        if len(fields) not in (2, 3):
            continue
        name, digest = fields[0], fields[1]
        if not (_NAME.fullmatch(name) and _HASH.fullmatch(digest)) or name == "owner":
            continue
        if len(fields) == 3:
            try:
                if date.fromisoformat(fields[2]) < today():
                    continue
            except ValueError:
                continue
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
