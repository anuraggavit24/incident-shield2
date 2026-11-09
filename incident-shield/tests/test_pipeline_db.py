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
        # The fixture account has no earlier history, so the pattern is reported at medium, not high.
        assert mule is not None and mule.severity == "medium"
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


def test_failed_identity_lookup_is_retried_then_detection_goes_ahead() -> None:
    def broken(_order_id: str) -> dict:
        raise TimeoutError("PayPal down")

    store(EVENTS)
    process_pending(broken)  # attempt 1: captures wait for a retry
    with db.session_scope() as session:
        assert session.scalar(select(Transaction)) is not None  # the payout (no lookup needed) went ahead
        waiting = session.scalars(select(WebhookEvent).where(WebhookEvent.status == "failed")).all()
    assert len(waiting) == 8 and all("will retry" in e.last_error for e in waiting)
    process_pending(broken)  # attempt 2: still waiting
    process_pending(broken)  # attempt 3: gives up on identity, processes anyway
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


# --------------------------------------------------------------------------- review findings (synthetic events)

BASE = "2026-11-10T10:{m:02d}:00Z"


def capture(event_id: str, minute: int, amount: str, order_id: str, currency: str = "USD") -> dict:
    return {
        "id": event_id,
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "create_time": BASE.format(m=minute),
        "resource": {
            "id": f"CAP{event_id[-6:]}",
            "amount": {"currency_code": currency, "value": amount},
            "status": "COMPLETED",
            "create_time": BASE.format(m=minute),
            "supplementary_data": {"related_ids": {"order_id": order_id}},
        },
    }


def payout(event_id: str, minute: int, amount: str, receiver: str) -> dict:
    return {
        "id": event_id,
        "event_type": "PAYMENT.PAYOUTS-ITEM.SUCCEEDED",
        "create_time": BASE.format(m=minute),
        "resource": {
            "transaction_id": f"OUT{event_id[-6:]}",
            "transaction_status": "SUCCESS",
            "time_processed": BASE.format(m=minute),
            "payout_item": {"amount": {"currency": "USD", "value": amount}, "receiver": receiver},
        },
    }


def card_lookup(names: dict[str, str]):
    return lambda order_id: {
        "payment_source": {"card": {"name": names[order_id], "last_digits": "4242", "brand": "VISA"}}
    }


def rule_ids_in_db() -> set[str]:
    with db.session_scope() as session:
        return {h.rule_id for h in session.scalars(select(RuleHit).where(RuleHit.superseded_by.is_(None)))}


def test_late_arriving_event_still_completes_the_burst() -> None:
    """Three new senders at 10:00, 10:10, 10:20, with the 10:10 webhook delivered last."""
    names = {"O1": "Payer One", "O2": "Payer Two", "O3": "Payer Three"}
    lookup = card_lookup(names)
    store([capture("WH-000001", 0, "50.00", "O1"), capture("WH-000003", 20, "50.00", "O3")])
    process_pending(lookup)
    assert "R1_BURST_NEW_SENDERS" not in rule_ids_in_db()  # only two senders so far
    store([capture("WH-000002", 10, "50.00", "O2")])  # the late one
    process_pending(lookup)
    assert "R1_BURST_NEW_SENDERS" in rule_ids_in_db()


def test_ordinary_seller_end_to_end_gets_no_mule_incident() -> None:
    """Supplier was paid an hour earlier (so it's a known recipient), then a normal day of sales."""
    names = {f"S{i}": f"Customer {i}" for i in range(4)}
    events = [
        payout("WH-SUP001", 0, "61.00", "supplier@example.com"),  # 10:00, earlier relationship
    ]
    # the sales day starts 65+ minutes later: reuse BASE with minutes 65..85 via hour rollover
    later = "2026-11-10T11:{m:02d}:00Z"
    for i, (amount, minute) in enumerate([("0.50", 5), ("40.00", 10), ("40.00", 15), ("40.00", 20)]):
        e = capture(f"WH-SALE0{i}", 0, amount, f"S{i}")
        e["create_time"] = e["resource"]["create_time"] = later.format(m=minute)
        events.append(e)
    final = payout("WH-SUP002", 0, "61.00", "supplier@example.com")
    final["create_time"] = final["resource"]["time_processed"] = later.format(m=25)
    events.append(final)
    store(events)
    process_pending(card_lookup(names))
    with db.session_scope() as session:
        kinds = {i.kind for i in session.scalars(select(Incident))}
    assert "money_mule_pattern" not in kinds
    assert "R2_PASS_THROUGH" not in rule_ids_in_db()
