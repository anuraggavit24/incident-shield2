"""Application settings with a fail-closed sandbox lock.

Every PayPal URL is derived from PAYPAL_API_BASE, which must be the sandbox host.
Anything else stops the application at startup.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

SANDBOX_HOSTS = frozenset({"api-m.sandbox.paypal.com"})


class ConfigError(RuntimeError):
    """Missing or unsafe configuration."""


def assert_sandbox(url: str) -> str:
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in SANDBOX_HOSTS or parsed.path not in ("", "/"):
        raise ConfigError(f"Refusing non-sandbox PayPal URL {url!r}")
    return f"https://{host}"


def normalize_database_url(url: str) -> str:
    """Neon gives postgresql://...; SQLAlchemy needs the psycopg (v3) driver named explicitly."""
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://") :]
    if not url.startswith("postgresql+psycopg://"):
        raise ConfigError("DATABASE_URL must be a PostgreSQL connection string")
    return url


def _require(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required setting {name}")
    return value


@dataclass(frozen=True)
class Settings:
    paypal_api_base: str
    paypal_client_id: str
    paypal_client_secret: str
    paypal_webhook_id: str
    database_url: str
    owner_api_key_sha256: str
    process_interval_s: float = 30.0
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash"
    copilot_daily_budget: int = 40
    paypal_merchant_id: str = ""
    webhook_rate_per_minute: int = 300
    verify_concurrency: int = 4


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    owner_hash = _require("OWNER_API_KEY_SHA256").lower()
    if len(owner_hash) != 64 or any(c not in "0123456789abcdef" for c in owner_hash):
        raise ConfigError("OWNER_API_KEY_SHA256 must be a 64-character hex SHA-256 digest")
    return Settings(
        paypal_api_base=assert_sandbox(os.getenv("PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")),
        paypal_client_id=_require("MERCHANT_CLIENT_ID"),
        paypal_client_secret=_require("MERCHANT_CLIENT_SECRET"),
        paypal_webhook_id=_require("PAYPAL_WEBHOOK_ID"),
        database_url=normalize_database_url(_require("DATABASE_URL")),
        owner_api_key_sha256=owner_hash,
        process_interval_s=float(os.getenv("PROCESS_INTERVAL_S", "30")),
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash").strip(),
        copilot_daily_budget=int(os.getenv("COPILOT_DAILY_BUDGET", "40")),
        paypal_merchant_id=os.getenv("PAYPAL_MERCHANT_ID", "").strip(),
        webhook_rate_per_minute=int(os.getenv("WEBHOOK_RATE_PER_MINUTE", "300")),
        verify_concurrency=int(os.getenv("VERIFY_CONCURRENCY", "4")),
    )
