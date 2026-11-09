"""Generate an owner API key and the hash to put in .env as OWNER_API_KEY_SHA256.

The key itself is shown once and never stored by the app: only its SHA-256 hash is.
Usage:  python scripts/make_owner_key.py
"""

import hashlib
import secrets

key = secrets.token_urlsafe(32)
print(f"Owner API key (keep it secret, send it as the X-API-Key header):\n  {key}\n")
print(f"Put this line in .env:\n  OWNER_API_KEY_SHA256={hashlib.sha256(key.encode()).hexdigest()}")
