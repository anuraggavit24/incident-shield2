"""Tests for CLI helpers: ID validation, the lag-probe abort policy, report
statistics, the cold-start idle gate, and the client-level sandbox lock."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from spike.config import AppCreds, ConfigError, Settings
from spike.paypal import PayPalClient
from spike.run_spike import (
    ProbeErrorPolicy,
    first_deliveries,
    idle_gate,
    neon_endpoint_kind,
    paypal_id,
    summarize,
)

# --- paypal_id


@pytest.mark.parametrize(
    "value", ["PP-D-12345", "5O190127TN364715T", "WH-2WR32451HC0233532-67976317FL4543714", "a" * 64]
)
def test_paypal_id_accepts_paypal_style_ids(value: str) -> None:
    assert paypal_id(value) == value


@pytest.mark.parametrize("value", ["", "../etc/passwd", "a/b", "id with space", "a" * 65, "x;rm", "PP-D-1\n"])
def test_paypal_id_rejects_anything_else(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        paypal_id(value)


# --- lag probe abort policy


def test_probe_aborts_after_consecutive_non_auth_errors() -> None:
    policy = ProbeErrorPolicy(max_errors=3, auth_grace_hours=4)
    assert policy.record_error(500, 0.1) is False
    assert policy.record_error(None, 0.2) is False  # network failure counts too
    assert policy.record_error(400, 0.3) is True


def test_probe_success_resets_the_count() -> None:
    policy = ProbeErrorPolicy(max_errors=3, auth_grace_hours=4)
    policy.record_error(500, 0.1)
    policy.record_error(500, 0.2)
    policy.record_success()
    assert policy.record_error(500, 0.3) is False


@pytest.mark.parametrize("status", [401, 403])
def test_probe_tolerates_auth_errors_during_grace_period(status: int) -> None:
    policy = ProbeErrorPolicy(max_errors=3, auth_grace_hours=4)
    for hour in range(0, 40):  # 40 polls over the first ~3.9 hours
        assert policy.record_error(status, hour / 10) is False
    assert policy.consecutive_errors == 0


def test_probe_counts_auth_errors_after_grace_period() -> None:
    policy = ProbeErrorPolicy(max_errors=3, auth_grace_hours=4)
    assert policy.record_error(403, 4.0) is False
    assert policy.record_error(403, 4.2) is False
    assert policy.record_error(403, 4.4) is True


# --- report statistics


def test_summarize_reports_median_p95_max() -> None:
    text = summarize([10.0, 20.0, 30.0, 40.0, 1000.0])
    assert "n=5" in text
    assert "median=30.0" in text
    assert "max=1000.0" in text
    assert "p95=" in text


def test_summarize_single_value() -> None:
    assert summarize([7.0]) == "n=1 median=7.0 p95=7.0 max=7.0"


def test_first_deliveries_ignores_redeliveries() -> None:
    hooks = [
        {"event_id": "WH-1", "received_at": "2026-11-07T10:00:00+00:00", "delivery_delay_s": 2.0},
        {"event_id": "WH-1", "received_at": "2026-11-07T13:00:00+00:00", "delivery_delay_s": 10800.0},
        {"event_id": "WH-2", "received_at": "2026-11-07T10:05:00+00:00", "delivery_delay_s": 3.0},
    ]
    delays = sorted(h["delivery_delay_s"] for h in first_deliveries(hooks))
    assert delays == [2.0, 3.0]


# --- cold-start helpers

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def test_idle_gate_allows_first_run() -> None:
    assert idle_gate(None, NOW, 10) is None


def test_idle_gate_refuses_recent_use() -> None:
    message = idle_gate(NOW - timedelta(minutes=3), NOW, 10)
    assert message is not None
    assert "3.0 min ago" in message


def test_idle_gate_allows_after_idle_period() -> None:
    assert idle_gate(NOW - timedelta(minutes=11), NOW, 10) is None


def test_idle_gate_zero_allows_warm_measurement() -> None:
    assert idle_gate(NOW - timedelta(seconds=5), NOW, 0) is None


@pytest.mark.parametrize(
    ("url", "kind"),
    [
        ("postgresql://u:p@ep-cool-name-123456-pooler.us-east-2.aws.neon.tech/db", "pooled"),
        ("postgresql://u:p@ep-cool-name-123456.us-east-2.aws.neon.tech/db", "direct"),
    ],
)
def test_neon_endpoint_kind(url: str, kind: str) -> None:
    assert neon_endpoint_kind(url) == kind


# --- sandbox lock inside the client itself


def test_client_refuses_production_even_if_settings_bypass_load_settings() -> None:
    creds = AppCreds("merchant", "id", "secret")
    settings = Settings(api_base="https://api-m.paypal.com", merchant=creds, sender=None)
    with pytest.raises(ConfigError):
        PayPalClient(settings, creds)


def test_client_accepts_sandbox() -> None:
    creds = AppCreds("merchant", "id", "secret")
    client = PayPalClient(Settings("https://api-m.sandbox.paypal.com", creds, None), creds)
    assert client.base == "https://api-m.sandbox.paypal.com"
    client.close()


# --- marker file read/write and the failed-attempt case

from spike.run_spike import measure_attempts, read_marker, write_marker  # noqa: E402


def test_marker_round_trip(tmp_path) -> None:
    marker = tmp_path / "markers" / "db.txt"
    assert read_marker(marker) is None
    write_marker(marker, NOW)
    assert read_marker(marker) == NOW


def test_corrupt_marker_reads_as_unknown(tmp_path) -> None:
    marker = tmp_path / "db.txt"
    marker.write_text("not a timestamp", encoding="utf-8")
    assert read_marker(marker) is None


def test_failed_attempt_is_recorded_and_still_updates_marker(tmp_path) -> None:
    marker = tmp_path / "db.txt"

    def failing_connect() -> dict:
        raise TimeoutError("connect timed out")

    results = measure_attempts(2, failing_connect, marker, now=lambda: NOW)
    assert [r["ok"] for r in results] == [False, False]
    assert results[0]["error_type"] == "TimeoutError"
    assert "timed out" in results[0]["error"]
    # The failed connect may have woken the database, so the gate must now refuse a "cold" run.
    assert read_marker(marker) == NOW
    assert idle_gate(read_marker(marker), NOW + timedelta(minutes=2), 10) is not None


def test_timeout_on_first_attempt_then_success(tmp_path) -> None:
    calls = {"n": 0}

    def flaky() -> dict:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ReadTimeout("timed out waiting for sleeping service")
        return {"http_status": 200}

    results = measure_attempts(2, flaky, tmp_path / "m.txt", now=lambda: NOW)
    assert results[0]["ok"] is False and results[0]["error_type"] == "ReadTimeout"
    assert results[1]["ok"] is True and results[1]["http_status"] == 200


def test_successful_attempts_are_timed_and_marked(tmp_path) -> None:
    marker = tmp_path / "db.txt"
    results = measure_attempts(2, lambda: {"connect_ms": 5}, marker, now=lambda: NOW)
    assert [r["attempt"] for r in results] == [1, 2]
    assert all(r["ok"] and r["connect_ms"] == 5 and r["total_ms"] >= 0 for r in results)
    assert read_marker(marker) == NOW


# --- cold-start classification and process age parsing

from spike.run_spike import NOT_COLD_AFTER_S, coldness, process_age_from, timing_hooks  # noqa: E402


@pytest.mark.parametrize(
    ("attempt", "age", "expected"),
    [
        (1, 0.4, "cold"),
        (1, NOT_COLD_AFTER_S, "cold"),
        (1, NOT_COLD_AFTER_S + 1, "NOT COLD"),
        (1, 3600.0, "NOT COLD"),
        (1, None, "UNCONFIRMED"),
        (2, 0.4, "warm"),
    ],
)
def test_coldness(attempt, age, expected) -> None:
    assert coldness(attempt, age) == expected


@pytest.mark.parametrize(
    ("body", "expected"),
    [(b'{"process_age_s": 1.5}', 1.5), (b'{"process_age_s": "x"}', None), (b"not json", None), (b"[1]", None)],
)
def test_process_age_from(body, expected) -> None:
    response = httpx.Response(200, content=body)
    assert process_age_from(response) == expected


def test_timing_stats_exclude_experiments() -> None:
    hooks = [
        {"handler_ms": 300.0, "outcome": "accepted", "ack_delay_s": 0.0},
        {"handler_ms": 30_400.0, "outcome": "accepted", "ack_delay_s": 30.0},
        {"handler_ms": 250.0, "outcome": "forced_503", "ack_delay_s": 0.0},
        {"handler_ms": 320.0, "outcome": "accepted"},
    ]
    assert [h["handler_ms"] for h in timing_hooks(hooks)] == [300.0, 320.0]
