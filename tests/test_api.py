"""HTTP layer: webhook intake status mapping, dedupe, auth, health. Real PostgreSQL."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app import db
from app.models import WebhookEvent
from app.paypal_client import PayPalError
from tests.conftest import TEST_OWNER_KEY
from tests.test_pipeline_db import (  # noqa: F401  (reuse skip + fixtures)
    EVENTS,
    ORDERS,
    migrated_db,  # noqa: F401
    pytestmark,
)

HEADERS = {
    "paypal-auth-algo": "SHA256withRSA",
    "paypal-cert-url": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-x",
    "paypal-transmission-id": "t-1",
    "paypal-transmission-sig": "sig",
    "paypal-transmission-time": "2026-11-08T07:49:33Z",
}


@pytest.fixture
def client(monkeypatch):
    from app.main import app

    with TestClient(app) as c:
        with db.get_engine().begin() as conn:
            conn.execute(
                text("TRUNCATE incident_events, rule_hits, incidents, transactions, webhook_events RESTART IDENTITY")
            )
        state = {"verify": "SUCCESS"}

        def fake_verify(headers, raw):
            if state["verify"] == "RAISE":
                raise PayPalError("verify endpoint down")
            return state["verify"]

        monkeypatch.setattr(app.state.paypal, "verify_webhook", fake_verify)
        monkeypatch.setattr(app.state.paypal, "get_order", lambda oid: ORDERS[oid])
        c.verify_state = state
        yield c


def post(client, event):
    return client.post("/webhooks/paypal", content=json.dumps(event).encode(), headers=HEADERS)


def stored_count() -> int:
    with db.session_scope() as session:
        return len(session.scalars(select(WebhookEvent)).all())


def test_verified_event_is_stored_and_processed(client) -> None:
    assert post(client, EVENTS[0]).json() == {"outcome": "accepted"}
    with db.session_scope() as session:
        event = session.scalar(select(WebhookEvent))
    assert event.event_id == EVENTS[0]["id"]
    assert event.status == "processed"  # background task ran after the response


def test_duplicate_delivery_is_acknowledged_but_stored_once(client) -> None:
    post(client, EVENTS[0])
    response = post(client, EVENTS[0])
    assert response.status_code == 200 and response.json() == {"outcome": "duplicate"}
    assert stored_count() == 1


def test_invalid_signature_is_rejected_and_not_stored(client) -> None:
    client.verify_state["verify"] = "FAILURE"
    assert post(client, EVENTS[0]).status_code == 400
    assert stored_count() == 0


def test_verification_outage_returns_503_so_paypal_retries(client) -> None:
    client.verify_state["verify"] = "RAISE"
    assert post(client, EVENTS[0]).status_code == 503
    assert stored_count() == 0


@pytest.mark.parametrize("body", [b"not json", b"[1]", b'{"no_id": true}', json.dumps({"id": 5}).encode()])
def test_malformed_bodies_are_rejected(client, body) -> None:
    assert client.post("/webhooks/paypal", content=body, headers=HEADERS).status_code == 400


def test_oversized_body_is_rejected(client) -> None:
    big = b'{"id":"x","pad":"' + b"a" * 70_000 + b'"}'
    assert client.post("/webhooks/paypal", content=big, headers=HEADERS).status_code == 413


def test_owner_endpoints_require_the_api_key(client) -> None:
    assert client.get("/incidents").status_code == 401
    assert client.get("/incidents", headers={"x-api-key": "wrong"}).status_code == 401
    assert client.get("/incidents", headers={"x-api-key": TEST_OWNER_KEY}).status_code == 200


def test_incident_detail_shows_evidence_audit_and_labels_untrusted_text(client) -> None:
    for event in EVENTS:
        post(client, event)
    auth = {"x-api-key": TEST_OWNER_KEY}
    incidents = client.get("/incidents", headers=auth).json()
    assert incidents and incidents[0]["kind"] == "risk_indicators"
    detail = client.get(f"/incidents/{incidents[0]['id']}", headers=auth).json()
    assert {h["rule_id"] for h in detail["rule_hits"]} >= {"R1_BURST_NEW_SENDERS", "R3_PROBE_PAYMENT"}
    assert "not proof of fraud" in detail["disclaimer"]
    echo = next(t for t in detail["transactions"] if t["paypal_id"] == "6JB34600M49183205")
    assert echo["untrusted_text"] == {"payer_name": "Test Sender Echo"}
    assert any(a["action"] == "opened" for a in detail["audit"])


def test_health(client) -> None:
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").status_code == 200
