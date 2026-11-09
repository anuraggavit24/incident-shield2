"""Handler behaviour that carries into the product: status mapping, the streaming
body cap, and logging only verified events in full."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from spike import logs, webhook_server
from spike.run_spike import verified_hooks
from spike.signature import HEADER_MAP

EVENT = {
    "id": "WH-1",
    "event_type": "PAYMENT.CAPTURE.COMPLETED",
    "create_time": "2026-11-07T06:00:00Z",
    "resource": {"custom_id": "run-1", "amount": {"value": "1.00", "currency_code": "USD"}},
}
HEADERS = {h: f"value-{h}" for h in HEADER_MAP}


@pytest.fixture
def client() -> TestClient:
    return TestClient(webhook_server.app)


@pytest.fixture
def verify_calls(monkeypatch):
    """Replace the PayPal verification call. Set calls['status'] to control the result."""
    calls: dict = {"count": 0, "status": "SUCCESS"}

    def fake_verify(headers, raw):
        calls["count"] += 1
        return {"status": calls["status"], "elapsed_ms": 1.0}

    monkeypatch.setattr(webhook_server, "verify", fake_verify)
    return calls


def logged() -> list[dict]:
    return logs.read_jsonl("webhooks")


def post_event(client: TestClient, event=EVENT):
    return client.post("/webhooks/paypal", content=json.dumps(event).encode(), headers=HEADERS)


def test_verified_event_returns_200_and_is_logged_in_full(client, verify_calls):
    response = post_event(client)
    assert response.status_code == 200
    [record] = logged()
    assert record["outcome"] == "accepted"
    assert record["verified"] is True
    assert record["event"]["resource"]["custom_id"] == "run-1"
    assert isinstance(record["handler_ms"], float)


def test_invalid_signature_returns_400_and_logs_metadata_only(client, verify_calls):
    verify_calls["status"] = "FAILURE"
    response = post_event(client)
    assert response.status_code == 400
    [record] = logged()
    assert record["outcome"] == "rejected_invalid_signature"
    assert "event" not in record
    assert record["claimed_event_type"] == "PAYMENT.CAPTURE.COMPLETED"
    assert len(record["sha256"]) == 64


@pytest.mark.parametrize("status", ["VERIFY_CALL_ERROR", "VERIFY_HTTP_ERROR", "NO_WEBHOOK_ID", "MISSING_HEADERS"])
def test_verification_unavailable_returns_503_so_paypal_retries(client, verify_calls, status):
    verify_calls["status"] = status
    response = post_event(client)
    assert response.status_code == 503
    [record] = logged()
    assert record["outcome"] == "verification_unavailable"
    assert "event" not in record


def test_force_503_still_records_verified_event_for_retry_analysis(client, verify_calls, monkeypatch):
    monkeypatch.setenv("SPIKE_FORCE_503", "1")
    response = post_event(client)
    assert response.status_code == 503
    [record] = logged()
    assert record["outcome"] == "forced_503"
    assert record["verified"] is True


def test_declared_content_length_over_cap_is_rejected(client, verify_calls):
    body = b"{" + b" " * (webhook_server.MAX_BODY_BYTES + 10) + b"}"
    response = client.post("/webhooks/paypal", content=body, headers=HEADERS)
    assert response.status_code == 413
    assert verify_calls["count"] == 0


@pytest.mark.parametrize("body", [b"not json", b"[1, 2, 3]", b"\xff\xfe"])
def test_bad_json_returns_400_without_verification(client, verify_calls, body):
    response = client.post("/webhooks/paypal", content=body, headers=HEADERS)
    assert response.status_code == 400
    assert verify_calls["count"] == 0


def test_report_uses_only_verified_events(client, verify_calls):
    post_event(client)  # genuine
    verify_calls["status"] = "FAILURE"
    post_event(client, {**EVENT, "id": "WH-FORGED", "event_type": "FORGED.EVENT"})
    records = logged()
    assert len(records) == 2
    assert [h["event_type"] for h in verified_hooks(records)] == ["PAYMENT.CAPTURE.COMPLETED"]


def test_unverified_logging_stops_when_log_is_full(client, verify_calls, monkeypatch):
    monkeypatch.setattr(webhook_server, "MAX_UNVERIFIED_LOG_BYTES", 1)
    post_event(client)  # verified: always logged
    verify_calls["status"] = "FAILURE"
    post_event(client)  # log already over 1 byte: dropped
    assert [r["outcome"] for r in logged()] == ["accepted"]


def test_forged_strings_are_truncated_in_unverified_records(client, verify_calls):
    verify_calls["status"] = "FAILURE"
    long = "A" * 5000
    headers = {**HEADERS, "paypal-transmission-id": long}
    client.post(
        "/webhooks/paypal", content=json.dumps({**EVENT, "id": long, "event_type": long}).encode(), headers=headers
    )
    [record] = logged()
    for key in ("claimed_event_id", "claimed_event_type", "transmission_id"):
        assert len(record[key]) <= webhook_server.MAX_LOGGED_STRING + len("...[truncated]")


@pytest.mark.parametrize(
    ("event_id", "event_type"),
    [
        ({"nested": {"deep": "B" * 50_000}}, ["C" * 1000] * 5),
        (12345, None),
        ([1, 2, 3], {"a": 1}),
    ],
)
def test_non_string_claimed_fields_are_reduced_and_truncated(client, verify_calls, event_id, event_type):
    verify_calls["status"] = "FAILURE"
    client.post(
        "/webhooks/paypal", content=json.dumps({"id": event_id, "event_type": event_type}).encode(), headers=HEADERS
    )
    [record] = logged()
    limit = webhook_server.MAX_LOGGED_STRING + len("...[truncated]")
    for key in ("claimed_event_id", "claimed_event_type"):
        value = record[key]
        assert value is None or (isinstance(value, str) and len(value) <= limit)
    assert len(json.dumps(record)) < 2000


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-32"])
def test_non_utf8_json_is_rejected_as_bad_json_not_500(client, verify_calls, encoding):
    body = json.dumps(EVENT).encode(encoding)
    response = client.post("/webhooks/paypal", content=body, headers=HEADERS)
    assert response.status_code == 400
    assert verify_calls["count"] == 0
    assert logged()[0]["outcome"] == "rejected_bad_json"


def test_real_verify_survives_non_utf8_body_without_500(monkeypatch):
    """Defence in depth: even if a non-UTF-8 body reached verify(), it must not raise."""
    monkeypatch.setattr(webhook_server, "resolve_webhook_id", lambda: "WH-TEST")
    result = webhook_server.verify(HEADERS, json.dumps(EVENT).encode("utf-16"))
    assert result["status"] == "VERIFY_CALL_ERROR"


def test_ack_delay_applies_to_verified_events(client, verify_calls, monkeypatch):
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(webhook_server.asyncio, "sleep", fake_sleep)
    monkeypatch.setenv("SPIKE_ACK_DELAY_S", "30")
    post_event(client)
    assert slept == [30.0]
    assert logged()[0]["ack_delay_s"] == 30.0


@pytest.mark.parametrize(("raw", "expected"), [("", 0.0), ("abc", 0.0), ("-5", 0.0), ("500", 120.0), ("12.5", 12.5)])
def test_ack_delay_parsing_is_bounded(monkeypatch, raw, expected):
    monkeypatch.setenv("SPIKE_ACK_DELAY_S", raw)
    assert webhook_server.ack_delay_seconds() == expected
