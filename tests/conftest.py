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
