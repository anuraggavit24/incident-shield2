"""End-to-end pipeline on a real PostgreSQL database, using REAL sandbox webhook payloads.

Needs PostgreSQL: TEST_DATABASE_URL (or DATABASE_URL). Skipped with a clear reason if unreachable.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url

from app import db
from app.config import normalize_database_url
from app.models import Incident, IncidentEvent, RuleHit, Transaction, WebhookEvent
from app.normalize import parse_time
from app.processing import process_pending

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
EVENTS = json.loads((FIXTURES / "sandbox_webhook_events.json").read_text(encoding="utf-8"))
ORDERS = json.loads((FIXTURES / "sandbox_orders.json").read_text(encoding="utf-8"))
URL = normalize_database_url(os.environ["DATABASE_URL"])


def _reachable() -> bool:
    try:
        with create_engine(URL).connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _is_test_database(url: str) -> bool:
    """These tests DROP the schema. Never run them against a database not named for testing."""
    return "test" in (make_url(url).database or "").lower()


if not _is_test_database(URL):
    raise RuntimeError(
        f"Refusing to run destructive DB tests: database name must contain 'test' ({make_url(URL).database!r})"
    )

# Locally, no PostgreSQL means skip. In CI, the database must exist, so a missing one fails loudly.
pytestmark = pytest.mark.skipif(
    not os.environ.get("CI") and not _reachable(), reason="PostgreSQL not reachable (set TEST_DATABASE_URL)"
)


@pytest.fixture(scope="module", autouse=True)
def migrated_db():
    engine = create_engine(URL)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "head")
    db.init_engine(URL)
    yield
    db.get_engine().dispose()


@pytest.fixture(autouse=True)
def clean_tables():
    with db.get_engine().begin() as conn:
        conn.execute(
            text(
                "TRUNCATE copilot_calls, incident_events, rule_hits, incidents, "
                "transactions, webhook_events RESTART IDENTITY"
            )
        )


def store(events) -> None:
    with db.session_scope() as session:
        for e in events:
            res = e.get("resource") or {}
            session.add(
                WebhookEvent(
                    event_id=e["id"],
                    event_type=e["event_type"],
                    resource_id=res.get("id") or res.get("transaction_id"),
                    event_created_at=parse_time(e.get("create_time")),
                    payload=e,
                    status="pending",
                )
            )


def lookup(order_id: str) -> dict:
    return ORDERS[order_id]


def test_migrations_match_models() -> None:
    from app.db import Base

    with create_engine(URL).connect() as conn:
        diffs = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diffs == [], f"models and migrations differ: {diffs}"


def test_real_sandbox_events_produce_transactions_with_identities() -> None:
    store(EVENTS)
    assert process_pending(lookup) == 12
    with db.session_scope() as session:
        txns = {t.paypal_id: t for t in session.scalars(select(Transaction))}
        statuses = {e.status for e in session.scalars(select(WebhookEvent))}
    assert len(txns) == 9
    assert statuses == {"processed", "ignored"}
    echo = txns["6JB34600M49183205"]
    assert echo.counterparty_key == "card:test sender echo:VISA:1881"
    assert echo.untrusted_text == {"payer_name": "Test Sender Echo"}
    assert txns["014977958F658263K"].identity_strength == "strong"
    assert str(txns["6F2349135S128104C"].amount_usd) == "144.37"
    assert txns["4T656028Y5133581B"].direction == "out"


def test_real_sandbox_burst_raises_indicators_but_not_the_mule_pattern() -> None:
    """In the real spike run only $50 left against ~$381 in: not a pass-through."""
    store(EVENTS)
    process_pending(lookup)
    with db.session_scope() as session:
        rules = {h.rule_id for h in session.scalars(select(RuleHit))}
        kinds = {i.kind for i in session.scalars(select(Incident))}
    assert {"R1_BURST_NEW_SENDERS", "R3_PROBE_PAYMENT", "R4_CURRENCY_MIX"} <= rules
    assert "R2_PASS_THROUGH" not in rules
    assert kinds == {"risk_indicators"}


def test_large_outflow_completes_the_mule_sequence() -> None:
    payout = copy.deepcopy(next(e for e in EVENTS if e["event_type"] == "PAYMENT.PAYOUTS-ITEM.SUCCEEDED"))
    payout["id"] = "WH-SYNTHETIC-OUT"
    payout["resource"]["transaction_id"] = "SYNTHOUT0001"
    payout["resource"]["payout_item"]["amount"]["value"] = "300.00"
    store(EVENTS + [payout])
    process_pending(lookup)
    with db.session_scope() as session:
        mule = session.scalar(select(Incident).where(Incident.kind == "money_mule_pattern"))
        assert mule is not None and mule.severity == "high"
        linked = session.scalars(select(RuleHit).where(RuleHit.incident_id == mule.id)).all()
        audit = session.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == mule.id)).all()
    assert {h.rule_id for h in linked} == {"R1_BURST_NEW_SENDERS", "R2_PASS_THROUGH", "R3_PROBE_PAYMENT"}
    assert [a.action for a in audit].count("sequence_step_linked") == 3


def test_reprocessing_is_idempotent() -> None:
    store(EVENTS)
    process_pending(lookup)
    with db.get_engine().begin() as conn:
        conn.execute(text("UPDATE webhook_events SET status = 'pending'"))
    process_pending(lookup)
    with db.session_scope() as session:
        assert len(session.scalars(select(Transaction)).all()) == 9
        keys = [h.dedupe_key for h in session.scalars(select(RuleHit))]
    assert len(keys) == len(set(keys))


def test_failed_identity_lookup_does_not_block_detection() -> None:
    def broken(_order_id: str) -> dict:
        raise TimeoutError("PayPal down")

    store(EVENTS)
    assert process_pending(broken) == 12
    with db.session_scope() as session:
        txn = session.scalar(select(Transaction).where(Transaction.paypal_id == "6JB34600M49183205"))
        rules = {h.rule_id for h in session.scalars(select(RuleHit))}
    assert txn.counterparty_key is None and "identity_lookup_failed" in txn.flags
    assert "R1_BURST_NEW_SENDERS" in rules  # unknown identity counts as new


def test_malformed_event_is_marked_failed_and_retried_later() -> None:
    bad = copy.deepcopy(EVENTS[0])
    bad["id"] = "WH-BAD"
    bad["resource"]["amount"] = {"currency_code": "USD", "value": "not-a-number"}
    store([bad])
    process_pending(lookup)
    with db.session_scope() as session:
        event = session.scalar(select(WebhookEvent).where(WebhookEvent.event_id == "WH-BAD"))
    assert event.status == "failed" and event.attempts == 1 and "bad amount" in event.last_error
