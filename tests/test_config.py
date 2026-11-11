"""Startup settings that must fail closed."""

from __future__ import annotations

import pytest

from app.config import ConfigError, get_settings


def test_missing_merchant_id_stops_startup(monkeypatch) -> None:
    # Review round 2, finding 5: without it, events about other accounts couldn't be quarantined.
    get_settings.cache_clear()
    monkeypatch.delenv("PAYPAL_MERCHANT_ID", raising=False)
    try:
        with pytest.raises(ConfigError, match="PAYPAL_MERCHANT_ID"):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_blank_merchant_id_also_stops_startup(monkeypatch) -> None:
    get_settings.cache_clear()
    monkeypatch.setenv("PAYPAL_MERCHANT_ID", "   ")
    try:
        with pytest.raises(ConfigError):
            get_settings()
    finally:
        get_settings.cache_clear()
