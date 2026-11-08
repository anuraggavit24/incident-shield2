"""Tests for the parts of the spike that must never be wrong: the sandbox lock,
the signature-verification body, and secret redaction."""

from __future__ import annotations

import json

import pytest

from spike.config import ConfigError, assert_sandbox
from spike.logs import redact
from spike.signature import HEADER_MAP, build_verify_body, missing_headers


@pytest.mark.parametrize(
    "url",
    [
        "https://api-m.sandbox.paypal.com",
        "https://api-m.sandbox.paypal.com/",
        "https://API-M.SANDBOX.PAYPAL.COM",
    ],
)
def test_sandbox_lock_accepts_sandbox(url: str) -> None:
    assert assert_sandbox(url) == "https://api-m.sandbox.paypal.com"


@pytest.mark.parametrize(
    "url",
    [
        "https://api-m.paypal.com",                       # production
        "https://api.paypal.com",                         # production (legacy host)
        "http://api-m.sandbox.paypal.com",                # not https
        "https://api-m.sandbox.paypal.com.evil.example",  # lookalike host
        "https://evil.example/api-m.sandbox.paypal.com",  # host in path
        "https://api-m.sandbox.paypal.com/v1",            # base must not carry a path
        "",
    ],
)
def test_sandbox_lock_rejects_everything_else(url: str) -> None:
    with pytest.raises(ConfigError):
        assert_sandbox(url)


def _headers() -> dict[str, str]:
    return {h: f"value-for-{h}" for h in HEADER_MAP}


def test_verify_body_preserves_raw_event_bytes() -> None:
    # Key order and number formatting that json.dumps would normalise away.
    raw = b'{"z":1,"id":"WH-1","amount":{"value":"10.50"},"n":1.0}'
    body = build_verify_body(_headers(), raw, "WEBHOOK-123")
    assert body.endswith(b',"webhook_event":' + raw + b"}")
    parsed = json.loads(body)
    assert parsed["webhook_id"] == "WEBHOOK-123"
    assert parsed["transmission_sig"] == "value-for-paypal-transmission-sig"
    assert parsed["webhook_event"]["id"] == "WH-1"


def test_missing_headers_reported() -> None:
    headers = _headers()
    del headers["paypal-cert-url"]
    assert missing_headers(headers) == ["paypal-cert-url"]


def test_redaction_hides_secrets_and_card_data() -> None:
    record = {
        "Authorization": "Bearer abc",
        "payment_source": {"card": {"number": "4111", "expiry": "2030-01", "name": "Test Sender"}},
        "items": [{"access_token": "x", "ok": 1}],
    }
    out = redact(record)
    assert out["Authorization"] == "[REDACTED]"
    assert out["payment_source"]["card"]["number"] == "[REDACTED]"
    assert out["payment_source"]["card"]["expiry"] == "[REDACTED]"
    assert out["payment_source"]["card"]["name"] == "Test Sender"
    assert out["items"][0]["access_token"] == "[REDACTED]"
    assert out["items"][0]["ok"] == 1
