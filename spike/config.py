"""Spike configuration with a fail-closed sandbox lock.

Every PayPal URL the spike can call is derived from PAYPAL_API_BASE, and that
base must be an https URL on an allowlisted sandbox host. Anything else stops
the program before a single request is made.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "spike_logs"
WEBHOOK_ID_FILE = LOG_DIR / "webhook_id.txt"

load_dotenv(ROOT / ".env")

SANDBOX_HOSTS = frozenset({"api-m.sandbox.paypal.com"})
DEFAULT_API_BASE = "https://api-m.sandbox.paypal.com"


class ConfigError(RuntimeError):
    """Raised when configuration is missing or unsafe."""


def assert_sandbox(url: str) -> str:
    """Return the URL without a trailing slash, or raise if it is not sandbox."""
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in SANDBOX_HOSTS:
        raise ConfigError(
            f"Refusing non-sandbox PayPal URL {url!r}. Allowed: https://{', https://'.join(sorted(SANDBOX_HOSTS))}"
        )
    if parsed.path not in ("", "/"):
        raise ConfigError(f"PAYPAL_API_BASE must not contain a path: {url!r}")
    return f"https://{host}"


def _require(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required setting {name}. Copy .env.example to .env and fill it in.")
    return value


@dataclass(frozen=True)
class AppCreds:
    label: str
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class Settings:
    api_base: str
    merchant: AppCreds
    sender: AppCreds | None
    reporting: AppCreds | None = None


def load_settings() -> Settings:
    api_base = assert_sandbox(os.getenv("PAYPAL_API_BASE", DEFAULT_API_BASE))
    merchant = AppCreds(
        label="merchant",
        client_id=_require("MERCHANT_CLIENT_ID"),
        client_secret=_require("MERCHANT_CLIENT_SECRET"),
    )
    sender_id = os.getenv("SENDER_CLIENT_ID", "").strip()
    sender_secret = os.getenv("SENDER_CLIENT_SECRET", "").strip()
    sender = AppCreds("sender", sender_id, sender_secret) if sender_id and sender_secret else None
    # Optional second app on the SAME merchant account, used only for Transaction Search.
    # PayPal reuses an access token (and its scopes) until it expires, so an app whose
    # token was issued before a permission was enabled can't pick it up for hours.
    rep_id = os.getenv("REPORTING_CLIENT_ID", "").strip()
    rep_secret = os.getenv("REPORTING_CLIENT_SECRET", "").strip()
    reporting = AppCreds("reporting", rep_id, rep_secret) if rep_id and rep_secret else None
    return Settings(api_base=api_base, merchant=merchant, sender=sender, reporting=reporting)


def resolve_webhook_id() -> str:
    """Webhook ID from PAYPAL_WEBHOOK_ID, else the file written by webhook-register.

    Read on every request so re-registering a webhook needs no server restart.
    """
    from_env = os.getenv("PAYPAL_WEBHOOK_ID", "").strip()
    if from_env:
        return from_env
    if WEBHOOK_ID_FILE.exists():
        return WEBHOOK_ID_FILE.read_text(encoding="utf-8").strip()
    return ""
