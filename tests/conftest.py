"""Test configuration: dummy sandbox credentials so modules that load settings at
import time can be imported, and an isolated log directory per test."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
os.environ.setdefault("MERCHANT_CLIENT_ID", "test-client-id")
os.environ.setdefault("MERCHANT_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("PAYPAL_WEBHOOK_ID", "WH-TEST")


@pytest.fixture(autouse=True)
def isolated_logs(tmp_path, monkeypatch):
    from spike import logs

    monkeypatch.setattr(logs, "LOG_DIR", tmp_path)
    monkeypatch.delenv("SPIKE_FORCE_503", raising=False)
    return tmp_path


# --- application settings for tests (must be set before app.config.get_settings is first called)
import hashlib  # noqa: E402

TEST_OWNER_KEY = "test-owner-key"
# Tests ALWAYS use TEST_DATABASE_URL (never the app's DATABASE_URL from .env), and the DB tests
# refuse any database whose name doesn't contain "test".
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "postgresql://postgres@localhost:55432/shield_test?host=/tmp"
)
os.environ.setdefault("OWNER_API_KEY_SHA256", hashlib.sha256(TEST_OWNER_KEY.encode()).hexdigest())
os.environ.setdefault("PROCESS_INTERVAL_S", "3600")  # tests drive processing explicitly
os.environ.setdefault("PAYPAL_MERCHANT_ID", "HUU66NVJRLZ2L")  # the sandbox merchant in the fixtures
